//! Official `libghostty-vt` native terminal actor (`native/ghostty/shim.c`),
//! run-length span coalescer, terminal key encoder, and semantic Agent Reader /
//! Approval Card extractor.
//!
//! `RpTerminal` holds non-thread-safe Ghostty C state (`!Send`), so EVERY `RpTerminal`
//! lives exclusively on the dedicated `"rex-zero-vt"` OS thread (`VtActor`).

use super::transport::Waker;
use crate::rex::types::{
    ApprovalCard, ApprovalOption, ReaderMessage, ReaderRole, VtSpan, VtViewport,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    ffi::{c_char, c_int, c_void},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

const RP_CELL_BOLD: u32 = 1 << 0;
const RP_CELL_INVERSE: u32 = 1 << 3;
const RP_CELL_INVISIBLE: u32 = 1 << 4;
const RP_CELL_UNDERLINE: u32 = 1 << 6;
const RP_CELL_FG_DEFAULT: u32 = 1 << 7;
const RP_CELL_BG_DEFAULT: u32 = 1 << 8;
const RP_ROW_WRAPPED: u32 = 1 << 27;
const RP_ROW_CONTINUATION: u32 = 1 << 28;

const RP_INPUT_ALT_SCREEN: u8 = 2;
const MIN_VT_COLS: u16 = 10;
const MAX_VT_COLS: u16 = 400;
const MIN_VT_ROWS: u16 = 4;
const MAX_VT_ROWS: u16 = 200;
const MAX_CELL_PX: u32 = 256;
const MAX_SNAPSHOT_BUFFER: usize = 1536 * 1024;
const LIVE_SLICE_BYTES: usize = 64 * 1024;
const MAX_QUEUED_VT_BYTES: usize = 1024 * 1024;
const MAX_VT_SLOTS: usize = 8;
const LIVE_RETAIN_SLOTS: usize = 2;
const MAX_FORMAT_SCROLLBACK_BYTES: usize = 64 * 1024;

#[repr(C)]
struct RpTerminal {
    _opaque: [u8; 0],
}

#[repr(C)]
#[derive(Default)]
struct RpFrame {
    columns: u16,
    rows: u16,
    cursor_x: u16,
    cursor_y: u16,
    cursor_visible: u8,
    foreground: [u8; 3],
    background: [u8; 3],
    scroll_total: u64,
    scroll_offset: u64,
    scroll_visible: u64,
    input_flags: u8,
    cursor_style: u8,
    cell_width_px: u32,
    cell_height_px: u32,
}

#[repr(C)]
struct RpImage {
    image_id: u32,
    generation: u64,
    layer: i32,
    z: i32,
    column: i32,
    row: i32,
    offset_x: u32,
    offset_y: u32,
    width: u32,
    height: u32,
    source_x: u32,
    source_y: u32,
    source_width: u32,
    source_height: u32,
}

type ApcFn = unsafe extern "C" fn(*mut c_void, *const u8, usize);
type CellFn = unsafe extern "C" fn(
    *mut c_void,
    u16,
    u16,
    *const u32,
    usize,
    *const u8,
    *const u8,
    u32,
    u8,
    *const u8,
    usize,
);
type ImageFn = unsafe extern "C" fn(*mut c_void, *const RpImage);

extern "C" {
    fn rp_new(cols: u16, rows: u16, out: *mut *mut RpTerminal) -> c_int;
    fn rp_decode(
        bytes: *const u8,
        len: usize,
        out: *mut *mut RpTerminal,
        offset: *mut usize,
    ) -> c_int;
    fn rp_free(t: *mut RpTerminal);
    fn rp_write(
        t: *mut RpTerminal,
        bytes: *const u8,
        len: usize,
        consumed: *mut usize,
        callback: Option<ApcFn>,
        userdata: *mut c_void,
    ) -> c_int;
    fn rp_resize(t: *mut RpTerminal, cols: u16, rows: u16, cw: u32, ch: u32) -> c_int;
    fn rp_color(t: *mut RpTerminal, which: c_int, rgb: *const u8) -> c_int;
    fn rp_scroll(t: *mut RpTerminal, lines: i32, bottom: c_int);
    fn rp_frame(
        t: *mut RpTerminal,
        frame: *mut RpFrame,
        callback: CellFn,
        images: Option<ImageFn>,
        userdata: *mut c_void,
    ) -> c_int;
    fn rp_key(
        t: *mut RpTerminal,
        android_keycode: c_int,
        repeat: c_int,
        android_meta: c_int,
        utf8: *const c_char,
        utf8_len: usize,
        out: *mut u8,
        capacity: usize,
        len: *mut usize,
    ) -> c_int;
}

#[derive(Clone, Default)]
pub struct ExtractedView {
    pub vt: Option<VtViewport>,
    pub reader_messages: Vec<ReaderMessage>,
    pub raw_lines: Vec<String>,
    pub approval: Option<ApprovalCard>,
    pub live_activity: Option<String>,
}

enum StreamDecodeState {
    AwaitingSnapshot { buf: Vec<u8>, next_record: usize },
    Live,
    SnapshotFailed,
}

struct TerminalSlot {
    ptr: *mut RpTerminal,
    cols: u16,
    rows: u16,
    decode_state: StreamDecodeState,
    format_scrollback: Option<String>,
    last_used_seq: u64,
}

impl Drop for TerminalSlot {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe { rp_free(self.ptr) };
            self.ptr = std::ptr::null_mut();
        }
    }
}

impl TerminalSlot {
    fn new(cols: u16, rows: u16) -> Option<Self> {
        let cols = cols.clamp(MIN_VT_COLS, MAX_VT_COLS);
        let rows = rows.clamp(MIN_VT_ROWS, MAX_VT_ROWS);
        let mut ptr = std::ptr::null_mut();
        let rc = unsafe { rp_new(cols, rows, &mut ptr) };
        if rc != 0 || ptr.is_null() {
            return None;
        }
        Some(Self {
            ptr,
            cols,
            rows,
            decode_state: StreamDecodeState::Live,
            format_scrollback: None,
            last_used_seq: 0,
        })
    }

    fn sync_dimensions_from_native(&mut self) {
        unsafe extern "C" fn noop_cell(
            _userdata: *mut c_void,
            _x: u16,
            _y: u16,
            _graphemes: *const u32,
            _count: usize,
            _fg: *const u8,
            _bg: *const u8,
            _flags: u32,
            _width: u8,
            _uri: *const u8,
            _uri_len: usize,
        ) {
        }
        if self.ptr.is_null() {
            self.cols = 0;
            self.rows = 0;
            return;
        }
        let mut frame = RpFrame::default();
        let rc = unsafe { rp_frame(self.ptr, &mut frame, noop_cell, None, std::ptr::null_mut()) };
        if rc == 0 && frame.columns > 0 && frame.rows > 0 {
            self.cols = frame.columns;
            self.rows = frame.rows;
        } else {
            // Invalidate cache so next `resize_local` unconditionally calls `rp_resize`.
            self.cols = 0;
            self.rows = 0;
        }
    }

    /// Feeds stream bytes; returns `false` if a `GHOSTSNP` snapshot exceeded limits or failed
    /// unrecoverably (caller should request a fresh snapshot instead of treating bytes as live).
    fn feed_stream(&mut self, nonce: u64, start_fresh: bool, bytes: &[u8]) -> bool {
        if start_fresh {
            self.decode_state = StreamDecodeState::AwaitingSnapshot {
                buf: Vec::new(),
                next_record: 10,
            };
        }
        let tail_to_write: Option<Vec<u8>> = match &mut self.decode_state {
            StreamDecodeState::SnapshotFailed => {
                return false;
            }
            StreamDecodeState::AwaitingSnapshot { buf, next_record } => {
                if buf.len().saturating_add(bytes.len()) > MAX_SNAPSHOT_BUFFER {
                    // Enforce buffer cap BEFORE extending; never feed binary snapshot data to VT!
                    *buf = Vec::new();
                    self.decode_state = StreamDecodeState::SnapshotFailed;
                    return false;
                }
                buf.extend_from_slice(bytes);

                let prefix_len = buf.len().min(8);
                if &buf[..prefix_len] != &b"GHOSTSNP"[..prefix_len] {
                    // Diverged from `"GHOSTSNP"` magic: flush short/live bytes immediately!
                    let raw = std::mem::take(buf);
                    self.decode_state = StreamDecodeState::Live;
                    Some(raw)
                } else if buf.len() >= 10 {
                    // Ghostty v1 has a ten-byte envelope and length-prefixed records.
                    // Decode once FINISH (tag 6) is complete; Ghostty checks CRC and semantics.
                    if buf[8..10] != [1, 0] {
                        self.decode_state = StreamDecodeState::SnapshotFailed;
                        return false;
                    }
                    loop {
                        let Some(header) = buf.get(*next_record..*next_record + 10) else {
                            if buf.len() >= MAX_SNAPSHOT_BUFFER {
                                self.decode_state = StreamDecodeState::SnapshotFailed;
                                return false;
                            }
                            return true;
                        };
                        let tag = u16::from_le_bytes(header[..2].try_into().unwrap());
                        let size = u32::from_le_bytes(header[2..6].try_into().unwrap()) as usize;
                        let end = (*next_record + 10).saturating_add(size);
                        if end > MAX_SNAPSHOT_BUFFER {
                            self.decode_state = StreamDecodeState::SnapshotFailed;
                            return false;
                        }
                        if end > buf.len() {
                            return true;
                        }
                        *next_record = end;
                        if tag == 6 {
                            break;
                        }
                    }
                    let mut decoded = std::ptr::null_mut();
                    let mut offset = 0usize;
                    let rc =
                        unsafe { rp_decode(buf.as_ptr(), buf.len(), &mut decoded, &mut offset) };
                    if rc == 0 && !decoded.is_null() {
                        if !self.ptr.is_null() {
                            unsafe { rp_free(self.ptr) };
                        }
                        self.ptr = decoded;
                        let remainder = buf.get(offset..).unwrap_or(&[]).to_vec();
                        self.decode_state = StreamDecodeState::Live;
                        self.sync_dimensions_from_native();
                        Some(remainder)
                    } else {
                        *buf = Vec::new();
                        self.decode_state = StreamDecodeState::SnapshotFailed;
                        return false;
                    }
                } else {
                    None
                }
            }
            StreamDecodeState::Live => Some(bytes.to_vec()),
        };

        if let Some(data) = tail_to_write {
            if !data.is_empty() {
                self.write_with_apc(nonce, &data);
            }
        }
        true
    }

    fn write_raw(&mut self, bytes: &[u8]) {
        self.decode_state = StreamDecodeState::Live;
        self.write_with_apc(0, bytes);
    }

    fn write_with_apc(&mut self, nonce: u64, bytes: &[u8]) {
        if self.ptr.is_null() || bytes.is_empty() {
            return;
        }
        unsafe extern "C" fn collect_apc(userdata: *mut c_void, ptr: *const u8, len: usize) {
            if !userdata.is_null() && !ptr.is_null() && len <= 65536 {
                let vec = unsafe { &mut *(userdata as *mut Vec<Vec<u8>>) };
                let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
                vec.push(slice.to_vec());
            }
        }

        let mut pos = 0usize;
        while pos < bytes.len() {
            let mut apcs: Vec<Vec<u8>> = Vec::new();
            let mut consumed = 0usize;
            let rc = unsafe {
                rp_write(
                    self.ptr,
                    bytes[pos..].as_ptr(),
                    bytes.len() - pos,
                    &mut consumed,
                    Some(collect_apc),
                    (&mut apcs as *mut Vec<Vec<u8>>).cast::<c_void>(),
                )
            };
            if rc != 0 && consumed == 0 {
                break;
            }
            pos += consumed.max(1);
            for apc in apcs {
                self.apply_rex_apc(nonce, &apc);
            }
        }
    }

    fn apply_rex_apc(&mut self, nonce: u64, apc: &[u8]) {
        if nonce == 0 {
            return;
        }
        let Ok(text) = std::str::from_utf8(apc) else {
            return;
        };
        let Some(rest) = text.strip_prefix("rex1;") else {
            return;
        };
        let Some((nonce_str, json_str)) = rest.split_once(';') else {
            return;
        };
        if nonce_str.parse::<u64>().ok() != Some(nonce) {
            return;
        }
        let Ok(val) = serde_json::from_str::<Value>(json_str) else {
            return;
        };
        match val.get("type").and_then(Value::as_str) {
            Some("resize") => {
                let Some(raw_cols) = val.get("cols").and_then(Value::as_u64) else {
                    return;
                };
                let Some(raw_rows) = val.get("rows").and_then(Value::as_u64) else {
                    return;
                };
                if !(2..=MAX_VT_COLS as u64).contains(&raw_cols)
                    || !(1..=MAX_VT_ROWS as u64).contains(&raw_rows)
                {
                    return;
                }
                let cols = (raw_cols as u16).clamp(MIN_VT_COLS, MAX_VT_COLS);
                let rows = (raw_rows as u16).clamp(MIN_VT_ROWS, MAX_VT_ROWS);
                let cw = val
                    .get("cell_width_px")
                    .and_then(Value::as_u64)
                    .filter(|&v| v <= MAX_CELL_PX as u64)
                    .unwrap_or(0) as u32;
                let ch = val
                    .get("cell_height_px")
                    .and_then(Value::as_u64)
                    .filter(|&v| v <= MAX_CELL_PX as u64)
                    .unwrap_or(0) as u32;
                if !self.ptr.is_null() {
                    let rc = unsafe { rp_resize(self.ptr, cols, rows, cw, ch) };
                    if rc == 0 {
                        self.cols = cols;
                        self.rows = rows;
                    }
                }
            }
            Some("theme") => {
                for (which, field) in [(0, "foreground"), (1, "background"), (2, "cursor")] {
                    if let Some(hex) = val.get(field).and_then(Value::as_str) {
                        if let Some(rgb) = parse_hex_rgb(hex) {
                            unsafe {
                                let _ = rp_color(self.ptr, which, rgb.as_ptr());
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn resize_local(&mut self, cols: u16, rows: u16) {
        let cols = cols.clamp(MIN_VT_COLS, MAX_VT_COLS);
        let rows = rows.clamp(MIN_VT_ROWS, MAX_VT_ROWS);
        if self.cols != cols || self.rows != rows {
            if !self.ptr.is_null() {
                let rc = unsafe { rp_resize(self.ptr, cols, rows, 0, 0) };
                if rc == 0 {
                    self.cols = cols;
                    self.rows = rows;
                }
            }
        }
    }

    fn scroll(&mut self, delta_lines: i32, to_bottom: bool) {
        if !self.ptr.is_null() {
            unsafe {
                rp_scroll(self.ptr, delta_lines, i32::from(to_bottom));
            }
        }
    }

    fn encode_key(&mut self, key_name: &str, mods: u32) -> Option<String> {
        if self.ptr.is_null() {
            return None;
        }
        let (bare_key, merged_mods) = split_prefixed_key(key_name, mods);
        // Let fallback encoder handle Ctrl+<letter> deterministically (\x01..\x1a)
        if (merged_mods & 2) != 0 && bare_key.len() == 1 && bare_key.as_bytes()[0].is_ascii_alphabetic() {
            return Some(fallback_encode_key(bare_key, merged_mods));
        }
        let (keycode, text) = map_key_to_android(bare_key)?;
        let mut android_meta: c_int = 0;
        if (merged_mods & 1) != 0 {
            android_meta |= 0x1; // SHIFT
        }
        if (merged_mods & 2) != 0 {
            android_meta |= 0x1000; // CTRL
        }
        if (merged_mods & 4) != 0 {
            android_meta |= 0x2; // ALT
        }
        if (merged_mods & 8) != 0 {
            android_meta |= 0x10000; // SUPER
        }
        let utf8_bytes = if (merged_mods & (2 | 4 | 8)) == 0 {
            text.unwrap_or("")
        } else {
            ""
        };
        let mut out = [0u8; 64];
        let mut out_len = 0usize;
        let rc = unsafe {
            rp_key(
                self.ptr,
                keycode,
                0,
                android_meta,
                if utf8_bytes.is_empty() {
                    std::ptr::null()
                } else {
                    utf8_bytes.as_ptr().cast::<c_char>()
                },
                utf8_bytes.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        if rc == 0 && out_len > 0 && out_len <= out.len() {
            String::from_utf8(out[..out_len].to_vec()).ok()
        } else {
            None
        }
    }

    fn extract(&mut self) -> Option<ExtractedView> {
        if self.ptr.is_null() {
            return None;
        }

        #[derive(Default)]
        struct RawRow {
            cells: Vec<RawCell>,
            wrapped: bool,
            continuation: bool,
        }

        struct RawCell {
            text: String,
            fg: Option<String>,
            bg: Option<String>,
            b: bool,
            inv: bool,
            u: bool,
            is_plain_space: bool,
        }

        unsafe extern "C" fn collect_cell(
            userdata: *mut c_void,
            _x: u16,
            y: u16,
            graphemes: *const u32,
            count: usize,
            fg: *const u8,
            bg: *const u8,
            flags: u32,
            width: u8,
            _uri: *const u8,
            _uri_len: usize,
        ) {
            let rows = unsafe { &mut *(userdata as *mut Vec<RawRow>) };
            let idx = y as usize;
            if rows.len() <= idx {
                rows.resize_with(idx + 1, RawRow::default);
            }
            let row = &mut rows[idx];
            row.wrapped = (flags & RP_ROW_WRAPPED) != 0;
            row.continuation = (flags & RP_ROW_CONTINUATION) != 0;

            // Skip wide-character spacer tail cells so CJK characters stay 2 cols without extra space.
            if width == 0 {
                return;
            }

            let mut ch_str = String::new();
            if count == 0 || (flags & RP_CELL_INVISIBLE) != 0 || graphemes.is_null() {
                ch_str.push(' ');
            } else {
                let slice = unsafe { std::slice::from_raw_parts(graphemes, count) };
                for &cp in slice {
                    if cp == 0 {
                        ch_str.push(' ');
                    } else if let Some(ch) = char::from_u32(cp) {
                        ch_str.push(ch);
                    }
                }
                if ch_str.is_empty() {
                    ch_str.push(' ');
                }
            }

            let fg_hex = if (flags & RP_CELL_FG_DEFAULT) != 0 || fg.is_null() {
                None
            } else {
                let rgb = unsafe { std::slice::from_raw_parts(fg, 3) };
                Some(format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2]))
            };
            let bg_hex = if (flags & RP_CELL_BG_DEFAULT) != 0 || bg.is_null() {
                None
            } else {
                let rgb = unsafe { std::slice::from_raw_parts(bg, 3) };
                Some(format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2]))
            };
            let b = (flags & RP_CELL_BOLD) != 0;
            let inv = (flags & RP_CELL_INVERSE) != 0;
            let u = (flags & RP_CELL_UNDERLINE) != 0;
            let is_plain_space = ch_str == " " && bg_hex.is_none() && !inv && !u;

            row.cells.push(RawCell {
                text: ch_str,
                fg: fg_hex,
                bg: bg_hex,
                b,
                inv,
                u,
                is_plain_space,
            });
        }

        let mut frame = RpFrame::default();
        let mut raw_rows: Vec<RawRow> = Vec::new();
        let rc = unsafe {
            rp_frame(
                self.ptr,
                &mut frame,
                collect_cell,
                None,
                (&mut raw_rows as *mut Vec<RawRow>).cast::<c_void>(),
            )
        };
        if rc != 0 {
            return None;
        }
        if frame.columns > 0 && frame.rows > 0 {
            self.cols = frame.columns;
            self.rows = frame.rows;
        }

        let mut lines: Vec<Vec<VtSpan>> = Vec::with_capacity(frame.rows as usize);
        let mut unwrapped_lines: Vec<String> = Vec::new();
        let mut current_logical = String::new();

        for y in 0..(frame.rows as usize) {
            let Some(row) = raw_rows.get(y) else {
                lines.push(Vec::new());
                if !current_logical.is_empty() {
                    unwrapped_lines.push(std::mem::take(&mut current_logical));
                }
                continue;
            };

            // Trim trailing plain spaces so wide desktop panes stay super compact over JSON.
            let mut end = row.cells.len();
            while end > 0 && row.cells[end - 1].is_plain_space {
                end -= 1;
            }

            let mut spans: Vec<VtSpan> = Vec::new();
            let mut row_plain = String::new();
            for cell in &row.cells[..end] {
                row_plain.push_str(&cell.text);
                let span_text = sanitize_vt_span_text(&cell.text);
                if span_text.is_empty() && !cell.text.is_empty() {
                    continue;
                }
                let next = VtSpan {
                    t: span_text,
                    fg: cell.fg.clone(),
                    bg: cell.bg.clone(),
                    b: cell.b,
                    inv: cell.inv,
                    u: cell.u,
                };
                if let Some(last) = spans.last_mut() {
                    if last.same_style(&next) {
                        last.t.push_str(&next.t);
                        continue;
                    }
                }
                spans.push(next);
            }
            lines.push(spans);

            if row.continuation && !current_logical.is_empty() {
                current_logical.push_str(row_plain.trim_end());
            } else {
                if !current_logical.is_empty() {
                    unwrapped_lines.push(std::mem::take(&mut current_logical));
                }
                current_logical.push_str(row_plain.trim_end());
            }
            if !row.wrapped && !current_logical.is_empty() {
                unwrapped_lines.push(std::mem::take(&mut current_logical));
            }
        }
        if !current_logical.is_empty() {
            unwrapped_lines.push(current_logical);
        }

        // Compute scroll offset from bottom: Ghostty reports scrollbar.offset from top (0 = top),
        // and total - visible = bottom! Let's convert scrollOffset to lines above bottom.
        let max_top = frame.scroll_total.saturating_sub(frame.scroll_visible);
        let lines_from_bottom = max_top.saturating_sub(frame.scroll_offset);

        let vt = VtViewport {
            cols: frame.columns,
            rows: frame.rows,
            cursor_x: frame.cursor_x,
            cursor_y: frame.cursor_y,
            cursor_visible: frame.cursor_visible != 0,
            scroll_offset: lines_from_bottom,
            scroll_total: frame.scroll_total,
            alt_screen: (frame.input_flags & RP_INPUT_ALT_SCREEN) != 0,
            lines,
        };

        let source_lines = merge_scrollback_and_live(
            self.format_scrollback.as_deref(),
            &unwrapped_lines,
        );

        let raw_start = source_lines.len().saturating_sub(220);
        let raw_lines: Vec<String> = source_lines[raw_start..]
            .iter()
            .map(|l| sanitize_vt_span_text(l))
            .collect();

        let (reader_messages, approval, live_activity) = parse_semantic_terminal(&source_lines);

        Some(ExtractedView {
            vt: Some(vt),
            reader_messages,
            raw_lines,
            approval,
            live_activity,
        })
    }
}

fn merge_scrollback_and_live(scrollback: Option<&str>, live_unwrapped: &[String]) -> Vec<String> {
    let mut hist: Vec<String> = scrollback
        .map(|s| s.lines().map(|l| l.trim_end().to_string()).collect())
        .unwrap_or_default();
    while hist.last().is_some_and(|l| l.trim().is_empty()) {
        hist.pop();
    }

    let mut live: Vec<String> = live_unwrapped
        .iter()
        .map(|l| l.trim_end().to_string())
        .collect();
    while live.last().is_some_and(|l| l.trim().is_empty()) {
        live.pop();
    }
    while live.first().is_some_and(|l| l.trim().is_empty()) {
        live.remove(0);
    }

    if hist.is_empty() {
        return live;
    }
    if live.is_empty() {
        return hist;
    }

    // 1. Exact suffix-prefix overlap between historical scrollback and live viewport
    let max_k = hist.len().min(live.len()).min(48);
    for k in (1..=max_k).rev() {
        let h_slice = &hist[hist.len() - k..];
        let l_slice = &live[..k];
        if h_slice == l_slice && h_slice.iter().any(|l| !l.trim().is_empty()) {
            hist.extend_from_slice(&live[k..]);
            return hist;
        }
    }

    // 2. Check if live viewport already sits inside the recent tail of `hist`
    let tail_start = hist.len().saturating_sub(90);
    let tail = &hist[tail_start..];
    if live.len() <= tail.len()
        && tail
            .windows(live.len())
            .any(|win| win == live.as_slice())
    {
        return hist;
    }

    // 3. Otherwise append live viewport lines so real-time streaming output is visible immediately!
    hist.extend(live);
    hist
}

struct VtQueueBudget {
    queued_bytes: Mutex<usize>,
    cv: Condvar,
}

struct CountedBytes {
    bytes: Vec<u8>,
    budget: Arc<VtQueueBudget>,
}

impl Drop for CountedBytes {
    fn drop(&mut self) {
        let len = self.bytes.len();
        if len > 0 {
            let mut used = self.budget.queued_bytes.lock().unwrap();
            *used = used.saturating_sub(len);
            self.budget.cv.notify_all();
        }
    }
}

enum VtCmd {
    BeginStream {
        key: String,
        stream_gen: u64,
        cols: u16,
        rows: u16,
        snapshot_failed: Arc<AtomicBool>,
        waker: Waker,
    },
    FeedStream {
        key: String,
        stream_gen: u64,
        cols: u16,
        rows: u16,
        nonce: u64,
        start_fresh: bool,
        payload: CountedBytes,
    },
    WriteRaw {
        key: String,
        cols: u16,
        rows: u16,
        bytes: Vec<u8>,
        reply: Option<mpsc::Sender<()>>,
    },
    SetFormatText {
        key: String,
        text: String,
    },
    ResizeLocal {
        key: String,
        cols: u16,
        rows: u16,
    },
    Scroll {
        key: String,
        delta_lines: i32,
        to_bottom: bool,
    },
    EncodeKey {
        key: String,
        key_name: String,
        mods: u32,
        reply: mpsc::Sender<String>,
    },
    Extract {
        key: String,
        cols: u16,
        rows: u16,
        reply: mpsc::Sender<ExtractedView>,
    },
    Remove {
        key: String,
    },
    RetainOnly {
        keep_key: Option<String>,
    },
}

fn clamp_scrollback_tail(mut text: String) -> String {
    if text.len() <= MAX_FORMAT_SCROLLBACK_BYTES {
        return text;
    }
    let mut start = text.len() - MAX_FORMAT_SCROLLBACK_BYTES;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    text.drain(..start);
    text
}

fn evict_lru_slots(
    slots: &mut HashMap<String, TerminalSlot>,
    active_streams: &mut HashMap<String, (u64, Arc<AtomicBool>, Waker)>,
    protected_key: Option<&str>,
    max_slots: usize,
) {
    while slots.len() > max_slots {
        let candidate = slots
            .iter()
            .filter(|(k, _)| protected_key != Some(k.as_str()) && !active_streams.contains_key(*k))
            .min_by_key(|(_, s)| s.last_used_seq)
            .map(|(k, _)| k.clone())
            .or_else(|| {
                slots
                    .iter()
                    .filter(|(k, _)| protected_key != Some(k.as_str()))
                    .min_by_key(|(_, s)| s.last_used_seq)
                    .map(|(k, _)| k.clone())
            });
        let Some(victim) = candidate else {
            break;
        };
        active_streams.remove(&victim);
        slots.remove(&victim);
    }
}

fn ensure_slot<'a>(
    slots: &'a mut HashMap<String, TerminalSlot>,
    active_streams: &mut HashMap<String, (u64, Arc<AtomicBool>, Waker)>,
    key: &str,
    cols: u16,
    rows: u16,
    seq: &mut u64,
) -> Option<&'a mut TerminalSlot> {
    if !slots.contains_key(key) {
        evict_lru_slots(slots, active_streams, Some(key), MAX_VT_SLOTS.saturating_sub(1));
        let slot = TerminalSlot::new(cols, rows)?;
        slots.insert(key.to_string(), slot);
    }
    *seq = seq.wrapping_add(1);
    let slot = slots.get_mut(key)?;
    slot.last_used_seq = *seq;
    Some(slot)
}

#[derive(Clone)]
pub struct VtActor {
    tx: mpsc::Sender<VtCmd>,
    budget: Arc<VtQueueBudget>,
}

impl VtActor {
    pub fn spawn() -> Self {
        let (tx, rx) = mpsc::channel::<VtCmd>();
        let budget = Arc::new(VtQueueBudget {
            queued_bytes: Mutex::new(0),
            cv: Condvar::new(),
        });
        thread::Builder::new()
            .name("rex-zero-vt".into())
            .stack_size(2 * 1024 * 1024)
            .spawn(move || {
                let mut slots: HashMap<String, TerminalSlot> = HashMap::new();
                let mut active_streams: HashMap<String, (u64, Arc<AtomicBool>, Waker)> =
                    HashMap::new();
                let mut live_keep: Option<Option<String>> = None;
                let mut access_seq: u64 = 0;
                while let Ok(cmd) = rx.recv() {
                    match cmd {
                        VtCmd::BeginStream {
                            key,
                            stream_gen,
                            cols,
                            rows,
                            snapshot_failed,
                            waker,
                        } => {
                            active_streams
                                .insert(key.clone(), (stream_gen, snapshot_failed, waker));
                            let _ = ensure_slot(
                                &mut slots,
                                &mut active_streams,
                                &key,
                                cols,
                                rows,
                                &mut access_seq,
                            );
                        }
                        VtCmd::FeedStream {
                            key,
                            stream_gen,
                            cols,
                            rows,
                            nonce,
                            start_fresh,
                            payload,
                        } => {
                            let Some((cur_gen, snap_fail, waker)) = active_streams.get(&key) else {
                                // Closed/removed pane or unregistered stream: reject retired frames!
                                continue;
                            };
                            if *cur_gen != stream_gen {
                                // Retired generation: never inject stale bytes into replacement stream!
                                continue;
                            }
                            let snap_fail = snap_fail.clone();
                            let waker = waker.clone();
                            if let Some(slot) = ensure_slot(
                                &mut slots,
                                &mut active_streams,
                                &key,
                                cols,
                                rows,
                                &mut access_seq,
                            ) {
                                if !slot.feed_stream(nonce, start_fresh, &payload.bytes) {
                                    snap_fail.store(true, Ordering::Release);
                                    waker.wake();
                                }
                            }
                        }
                        VtCmd::WriteRaw {
                            key,
                            cols,
                            rows,
                            bytes,
                            reply,
                        } => {
                            if let Some(slot) = ensure_slot(
                                &mut slots,
                                &mut active_streams,
                                &key,
                                cols,
                                rows,
                                &mut access_seq,
                            ) {
                                slot.write_raw(&bytes);
                            }
                            if let Some(tx) = reply {
                                let _ = tx.send(());
                            }
                        }
                        VtCmd::SetFormatText { key, text } => {
                            let allow_create = match &live_keep {
                                None => true,
                                Some(Some(active)) => active == &key,
                                Some(None) => false,
                            };
                            if allow_create {
                                if let Some(slot) = ensure_slot(
                                    &mut slots,
                                    &mut active_streams,
                                    &key,
                                    50,
                                    14,
                                    &mut access_seq,
                                ) {
                                    slot.format_scrollback = Some(clamp_scrollback_tail(text));
                                }
                            } else if let Some(slot) = slots.get_mut(&key) {
                                slot.format_scrollback = Some(clamp_scrollback_tail(text));
                            }
                        }
                        VtCmd::ResizeLocal { key, cols, rows } => {
                            if let Some(slot) = slots.get_mut(&key) {
                                access_seq = access_seq.wrapping_add(1);
                                slot.last_used_seq = access_seq;
                                slot.resize_local(cols, rows);
                            }
                        }
                        VtCmd::Scroll {
                            key,
                            delta_lines,
                            to_bottom,
                        } => {
                            if let Some(slot) = slots.get_mut(&key) {
                                access_seq = access_seq.wrapping_add(1);
                                slot.last_used_seq = access_seq;
                                slot.scroll(delta_lines, to_bottom);
                            }
                        }
                        VtCmd::EncodeKey {
                            key,
                            key_name,
                            mods,
                            reply,
                        } => {
                            let encoded = slots
                                .get_mut(&key)
                                .and_then(|s| s.encode_key(&key_name, mods))
                                .unwrap_or_else(|| fallback_encode_key(&key_name, mods));
                            let _ = reply.send(encoded);
                        }
                        VtCmd::Extract {
                            key,
                            cols,
                            rows,
                            reply,
                        } => {
                            let allow_create = match &live_keep {
                                None => true,
                                Some(Some(active)) => active == &key,
                                Some(None) => false,
                            };
                            let out = if allow_create {
                                ensure_slot(
                                    &mut slots,
                                    &mut active_streams,
                                    &key,
                                    cols,
                                    rows,
                                    &mut access_seq,
                                )
                                .and_then(TerminalSlot::extract)
                            } else {
                                slots.get_mut(&key).and_then(TerminalSlot::extract)
                            }
                            .unwrap_or_else(|| ExtractedView {
                                vt: Some(VtViewport::empty(cols, rows)),
                                ..ExtractedView::default()
                            });
                            let _ = reply.send(out);
                        }
                        VtCmd::Remove { key } => {
                            active_streams.remove(&key);
                            slots.remove(&key);
                        }
                        VtCmd::RetainOnly { keep_key } => {
                            active_streams.retain(|k, _| keep_key.as_deref() == Some(k.as_str()));
                            let max_keep = match &keep_key {
                                Some(k) if slots.contains_key(k.as_str()) => LIVE_RETAIN_SLOTS,
                                Some(_) => LIVE_RETAIN_SLOTS.saturating_sub(1),
                                None => 1,
                            };
                            evict_lru_slots(
                                &mut slots,
                                &mut active_streams,
                                keep_key.as_deref(),
                                max_keep,
                            );
                            live_keep = Some(keep_key);
                        }
                    }
                }
            })
            .expect("spawn rex-zero-vt");
        Self { tx, budget }
    }

    pub fn begin_stream(
        &self,
        key: &str,
        stream_gen: u64,
        cols: u16,
        rows: u16,
        snapshot_failed: Arc<AtomicBool>,
        waker: Waker,
    ) {
        let _ = self.tx.send(VtCmd::BeginStream {
            key: key.to_string(),
            stream_gen,
            cols,
            rows,
            snapshot_failed,
            waker,
        });
    }

    #[allow(clippy::too_many_arguments)]
    pub fn feed_stream(
        &self,
        key: &str,
        stream_gen: u64,
        cols: u16,
        rows: u16,
        nonce: u64,
        start_fresh: bool,
        bytes: Vec<u8>,
        stop: &AtomicBool,
    ) -> bool {
        if bytes.is_empty() {
            return true;
        }
        // Slice oversized frames into `<= 64 KiB` pieces in exact stream order so total queued
        // bytes across all streams stay strictly `<= 2 MiB` even during multi-MiB snapshots!
        if bytes.len() <= LIVE_SLICE_BYTES {
            return self.enqueue_counted_chunk(
                key,
                stream_gen,
                cols,
                rows,
                nonce,
                start_fresh,
                bytes,
                stop,
            );
        }

        let mut first = start_fresh;
        for slice in bytes.chunks(LIVE_SLICE_BYTES) {
            if !self.enqueue_counted_chunk(
                key,
                stream_gen,
                cols,
                rows,
                nonce,
                first,
                slice.to_vec(),
                stop,
            ) {
                return false;
            }
            first = false;
        }
        true
    }

    #[allow(clippy::too_many_arguments)]
    fn enqueue_counted_chunk(
        &self,
        key: &str,
        stream_gen: u64,
        cols: u16,
        rows: u16,
        nonce: u64,
        start_fresh: bool,
        bytes: Vec<u8>,
        stop: &AtomicBool,
    ) -> bool {
        let len = bytes.len();
        {
            let mut used = self.budget.queued_bytes.lock().unwrap();
            while *used > 0 && used.saturating_add(len) > MAX_QUEUED_VT_BYTES {
                if stop.load(Ordering::Acquire) {
                    return false;
                }
                let (next_used, _) = self
                    .budget
                    .cv
                    .wait_timeout(used, Duration::from_millis(40))
                    .unwrap();
                used = next_used;
            }
            if stop.load(Ordering::Acquire) {
                return false;
            }
            *used = used.saturating_add(len);
        }
        let payload = CountedBytes {
            bytes,
            budget: self.budget.clone(),
        };
        self.tx
            .send(VtCmd::FeedStream {
                key: key.to_string(),
                stream_gen,
                cols,
                rows,
                nonce,
                start_fresh,
                payload,
            })
            .is_ok()
    }

    pub fn write_raw_sync(&self, key: &str, cols: u16, rows: u16, bytes: Vec<u8>) {
        let (rtx, rrx) = mpsc::channel();
        if self
            .tx
            .send(VtCmd::WriteRaw {
                key: key.to_string(),
                cols,
                rows,
                bytes,
                reply: Some(rtx),
            })
            .is_ok()
        {
            let _ = rrx.recv();
        }
    }

    pub fn set_format_text(&self, key: &str, text: String) {
        let _ = self.tx.send(VtCmd::SetFormatText {
            key: key.to_string(),
            text,
        });
    }

    pub fn resize_local(&self, key: &str, cols: u16, rows: u16) {
        let _ = self.tx.send(VtCmd::ResizeLocal {
            key: key.to_string(),
            cols,
            rows,
        });
    }

    pub fn scroll(&self, key: &str, delta_lines: i32, to_bottom: bool) {
        let _ = self.tx.send(VtCmd::Scroll {
            key: key.to_string(),
            delta_lines,
            to_bottom,
        });
    }

    pub fn encode_key(&self, key: &str, key_name: &str, mods: u32) -> String {
        let (rtx, rrx) = mpsc::channel();
        if self
            .tx
            .send(VtCmd::EncodeKey {
                key: key.to_string(),
                key_name: key_name.to_string(),
                mods,
                reply: rtx,
            })
            .is_ok()
        {
            if let Ok(seq) = rrx.recv() {
                return seq;
            }
        }
        fallback_encode_key(key_name, mods)
    }

    pub fn extract(&self, key: &str, cols: u16, rows: u16) -> ExtractedView {
        let (rtx, rrx) = mpsc::channel();
        if self
            .tx
            .send(VtCmd::Extract {
                key: key.to_string(),
                cols,
                rows,
                reply: rtx,
            })
            .is_ok()
        {
            if let Ok(view) = rrx.recv() {
                return view;
            }
        }
        ExtractedView {
            vt: Some(VtViewport::empty(cols, rows)),
            ..ExtractedView::default()
        }
    }

    pub fn remove(&self, key: &str) {
        let _ = self.tx.send(VtCmd::Remove {
            key: key.to_string(),
        });
    }

    pub fn retain_only(&self, keep_key: Option<&str>) {
        let _ = self.tx.send(VtCmd::RetainOnly {
            keep_key: keep_key.map(ToString::to_string),
        });
    }
}

fn parse_hex_rgb(hex: &str) -> Option<[u8; 3]> {
    let clean = hex.trim().strip_prefix('#').unwrap_or(hex.trim());
    let bytes = clean.as_bytes();
    if bytes.len() != 6 || !bytes.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let hex_byte = |hi: u8, lo: u8| -> Option<u8> {
        let h = (hi as char).to_digit(16)? as u8;
        let l = (lo as char).to_digit(16)? as u8;
        Some((h << 4) | l)
    };
    Some([
        hex_byte(bytes[0], bytes[1])?,
        hex_byte(bytes[2], bytes[3])?,
        hex_byte(bytes[4], bytes[5])?,
    ])
}

fn split_prefixed_key(raw: &str, initial_mods: u32) -> (&str, u32) {
    let mut s = raw;
    let mut mods = initial_mods;
    loop {
        if let Some(rest) = s.strip_prefix("Control+").or_else(|| s.strip_prefix("Ctrl+")) {
            if !rest.is_empty() {
                mods |= 2;
                s = rest;
                continue;
            }
        }
        if let Some(rest) = s.strip_prefix("Alt+") {
            if !rest.is_empty() {
                mods |= 4;
                s = rest;
                continue;
            }
        }
        if let Some(rest) = s.strip_prefix("Shift+") {
            if !rest.is_empty() {
                mods |= 1;
                s = rest;
                continue;
            }
        }
        break;
    }
    (s, mods)
}

fn map_key_to_android(key_name: &str) -> Option<(c_int, Option<&str>)> {
    if key_name.len() == 1 {
        let b = key_name.as_bytes()[0];
        if b.is_ascii_alphabetic() {
            let code = 29 + (b.to_ascii_lowercase() - b'a') as c_int;
            return Some((code, Some(key_name)));
        }
        if b.is_ascii_digit() {
            let code = 7 + (b - b'0') as c_int;
            return Some((code, Some(key_name)));
        }
        return match b {
            b' ' => Some((62, Some(" "))),
            b',' | b'<' => Some((55, Some(key_name))),
            b'.' | b'>' => Some((56, Some(key_name))),
            b'`' | b'~' => Some((68, Some(key_name))),
            b'-' | b'_' => Some((69, Some(key_name))),
            b'=' | b'+' => Some((70, Some(key_name))),
            b'[' | b'{' => Some((71, Some(key_name))),
            b']' | b'}' => Some((72, Some(key_name))),
            b'\\' | b'|' => Some((73, Some(key_name))),
            b';' | b':' => Some((74, Some(key_name))),
            b'\'' | b'"' => Some((75, Some(key_name))),
            b'/' | b'?' => Some((76, Some(key_name))),
            b'!' => Some((8, Some("!"))),
            b'@' => Some((9, Some("@"))),
            b'#' => Some((10, Some("#"))),
            b'$' => Some((11, Some("$"))),
            b'%' => Some((12, Some("%"))),
            b'^' => Some((13, Some("^"))),
            b'&' => Some((14, Some("&"))),
            b'*' => Some((15, Some("*"))),
            b'(' => Some((16, Some("("))),
            b')' => Some((7, Some(")"))),
            _ => None,
        };
    }
    match key_name {
        "Enter" | "Return" => Some((66, None)),
        "Backspace" => Some((67, None)),
        "Delete" => Some((112, None)),
        "Tab" => Some((61, None)),
        "Space" => Some((62, Some(" "))),
        "Escape" | "Esc" => Some((111, None)),
        "ArrowUp" | "Up" => Some((19, None)),
        "ArrowDown" | "Down" => Some((20, None)),
        "ArrowLeft" | "Left" => Some((21, None)),
        "ArrowRight" | "Right" => Some((22, None)),
        "PageUp" => Some((92, None)),
        "PageDown" => Some((93, None)),
        "Home" => Some((122, None)),
        "End" => Some((123, None)),
        "Insert" => Some((124, None)),
        _ => None,
    }
}

pub fn fallback_encode_key(key_name: &str, mods: u32) -> String {
    let (bare_name, merged_mods) = split_prefixed_key(key_name, mods);
    let shift = (merged_mods & 1) != 0;
    let ctrl = (merged_mods & 2) != 0;
    let alt = (merged_mods & 4) != 0;

    if ctrl && bare_name.len() == 1 {
        let ch = bare_name.as_bytes()[0].to_ascii_lowercase();
        if ch.is_ascii_lowercase() {
            let ctrl_byte = (ch - b'a') + 1;
            let mut out = String::new();
            if alt {
                out.push('\x1b');
            }
            out.push(ctrl_byte as char);
            return out;
        }
    }

    let base = match bare_name {
        "Enter" | "Return" => "\r",
        "Backspace" => "\x7f",
        "Delete" => "\x1b[3~",
        "Tab" if shift => "\x1b[Z",
        "Tab" => "\t",
        "Space" => " ",
        "Escape" | "Esc" => "\x1b",
        "ArrowUp" | "Up" => "\x1b[A",
        "ArrowDown" | "Down" => "\x1b[B",
        "ArrowRight" | "Right" => "\x1b[C",
        "ArrowLeft" | "Left" => "\x1b[D",
        "PageUp" => "\x1b[5~",
        "PageDown" => "\x1b[6~",
        "Home" => "\x1b[H",
        "End" => "\x1b[F",
        other => other,
    };

    if alt && !base.starts_with('\x1b') {
        format!("\x1b{base}")
    } else {
        base.to_string()
    }
}

/// Strips zero-width / variation-selector codepoints and maps PUA / Nerd Font / Braille /
/// unbaked terminal symbols to guaranteed baked glyphs so `□` tofu never appears in `终端` mode.
pub fn sanitize_vt_span_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let cp = ch as u32;
        if matches!(
            cp,
            0x200B..=0x200F | 0x2028..=0x202F | 0xFE00..=0xFE0F | 0xFEFF
        ) {
            continue;
        }
        if matches!(cp, 0xE000..=0xF8FF | 0xF0000..=0x10FFFF) {
            out.push(' ');
            continue;
        }
        if (0x2800..=0x28FF).contains(&cp) || (0x1F000..=0x1FAFF).contains(&cp) {
            out.push('·');
            continue;
        }
        if (0x2580..=0x259F).contains(&cp) {
            out.push('─');
            continue;
        }
        let mapped = match ch {
            '⏺' | '◉' | '⬤' => '●',
            '✻' | '✶' | '✢' | '✳' | '✴' | '✺' | '✽' | '⚡' => '*',
            '⎿' | '╰' => '└',
            '╭' => '┌',
            '╮' => '┐',
            '╯' => '┘',
            '┃' | '║' | '╎' | '╏' | '┆' | '┊' => '│',
            '━' | '═' | '╌' | '╍' | '┄' | '┈' => '─',
            '⇄' | '⇆' => '↔',
            '⏭' | '⏩' => '»',
            '⏮' | '⏪' => '«',
            '❯' | '▸' | '▶' | '⏵' | '⏯' => '›',
            '✔' | '✅' => '✓',
            '✖' | '❌' => '✗',
            '⬡' | '⬢' | '❖' | '◈' => '◆',
            '⏳' | '⌛' | '⏱' | '⏲' => '·',
            _ if matches!(cp, 0x2300..=0x23FF | 0x2600..=0x27BF | 0x2B00..=0x2BFF)
                && !matches!(ch, '⏎' | '⌫' | '⇥' | '␣' | '✓' | '✗' | '⚠' | '★' | '☆' | '♪') =>
            {
                '·'
            }
            _ => ch,
        };
        out.push(mapped);
    }
    out
}

/// Cleans TUI/terminal display strings for compact UI cards, titles, and Reader blocks:
/// maps exotic Unicode bullets/boxes to baked glyphs and strips PUA / Nerd Font / astral emoji
/// so `□` tofu blocks never appear on screen.
pub fn sanitize_ui_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let cp = ch as u32;
        if matches!(
            cp,
            0x200B..=0x200F
                | 0x2028..=0x202F
                | 0x2800..=0x28FF
                | 0xFE00..=0xFE0F
                | 0xFEFF
                | 0xE000..=0xF8FF
                | 0xF0000..=0x10FFFF
                | 0x1F000..=0x1FAFF
        ) {
            continue;
        }
        if (0x2580..=0x259F).contains(&cp) {
            out.push('-');
            continue;
        }
        let mapped = match ch {
            '⏺' | '◉' | '⬤' => '●',
            '✻' | '✶' | '✢' | '✳' | '✴' | '✺' | '✽' => '*',
            '⎿' | '╰' | '└' | '│' | '┃' | '║' | '╎' | '╏' | '┆' | '┊' => '|',
            '╭' | '┌' | '╮' | '┐' | '╯' | '┘' | '├' | '┤' | '┬' | '┴' | '┼' => '+',
            '━' | '═' | '╌' | '╍' | '┄' | '┈' | '─' => '-',
            '⇄' | '⇆' => '↔',
            '⏭' | '⏩' => '»',
            '⏮' | '⏪' => '«',
            '❯' => '›',
            '⏯' | '⏵' | '▸' => '▶',
            '⚡' => '*',
            '⏳' | '⌛' | '⏱' | '⏲' => '·',
            '✔' | '✅' => '✓',
            '✖' | '❌' => '✗',
            '\t' => ' ',
            _ => ch,
        };
        out.push(mapped);
    }
    out
}

/// Strips heavy TUI box borders, AGY/Claude/Codex telemetry footers, and extracts clean
/// `ReaderMessage` blocks + optional `ApprovalCard` + live activity banner.
pub fn parse_semantic_terminal(
    lines: &[String],
) -> (Vec<ReaderMessage>, Option<ApprovalCard>, Option<String>) {
    let mut cleaned: Vec<String> = Vec::new();
    let mut live_activity: Option<String> = None;

    let total_raw = lines.len();
    let footer_zone_start = total_raw.saturating_sub(10);

    for (idx, raw) in lines.iter().enumerate() {
        let in_footer_zone = idx >= footer_zone_start;
        let trimmed = strip_tui_chrome(raw);
        if trimmed.is_empty() {
            if cleaned.last().is_some_and(|prev| !prev.is_empty()) {
                cleaned.push(String::new());
            }
            continue;
        }
        if is_spinner_or_status_line(&trimmed) {
            let clean_act = sanitize_ui_text(&trimmed)
                .trim_start_matches(['*', '●', '·', ' '])
                .trim()
                .to_string();
            if !clean_act.is_empty() && !is_tui_noise_line(&clean_act, true) {
                live_activity = Some(clean_act);
            }
            continue;
        }
        let clean_line = sanitize_ui_text(&trimmed);
        let clean_trimmed = clean_line.trim();
        if matches!(clean_trimmed, "❯" | "›" | ">")
            && trimmed
                .chars()
                .any(|c| (0x1F000..=0x1FAFF).contains(&(c as u32)))
        {
            cleaned.push("› [emoji]".to_string());
            continue;
        }
        if clean_trimmed.is_empty() || is_tui_noise_line(clean_trimmed, in_footer_zone) {
            continue;
        }
        cleaned.push(clean_line.trim_end().to_string());
    }

    while cleaned.last().is_some_and(|s| s.trim().is_empty()) {
        cleaned.pop();
    }

    let approval = detect_approval(&cleaned);
    let mut messages: Vec<ReaderMessage> = Vec::new();
    let mut cur_role = ReaderRole::Assistant;
    let mut cur_title: Option<String> = None;
    let mut cur_body: Vec<String> = Vec::new();

    let flush = |messages: &mut Vec<ReaderMessage>,
                 role: ReaderRole,
                 title: Option<String>,
                 body: &mut Vec<String>| {
        while body.last().is_some_and(|s| s.trim().is_empty()) {
            body.pop();
        }
        if body.is_empty() && title.is_none() {
            return;
        }
        if role != ReaderRole::Tool && body.is_empty() {
            return;
        }
        let id = format!("m{}", messages.len() + 1);
        messages.push(ReaderMessage {
            id,
            role,
            title,
            body: body.join("\n"),
        });
        body.clear();
    };

    let mut in_thought_preview = false;
    for line in &cleaned {
        if line.trim().is_empty() {
            in_thought_preview = false;
            if !cur_body.is_empty() {
                cur_body.push(String::new());
            }
            continue;
        }

        if let Some(prompt_text) = strip_user_prompt(line) {
            in_thought_preview = false;
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::User;
            cur_body.push(prompt_text);
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::Assistant;
            continue;
        }

        if let Some(thought_text) = strip_thought_line(line) {
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::Tool;
            cur_title = Some("思考".into());
            if !thought_text.is_empty() {
                cur_body.push(thought_text);
            }
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::Assistant;
            in_thought_preview = true;
            continue;
        }

        if in_thought_preview && line.starts_with("  ") {
            let t = line.trim_start();
            if !t.starts_with('|')
                && !t.starts_with('●')
                && !t.starts_with('•')
                && !t.starts_with('*')
                && !t.starts_with("[1]")
                && !t.starts_with("1.")
            {
                continue;
            }
            in_thought_preview = false;
        } else {
            in_thought_preview = false;
        }

        if let Some((tool_title, rest)) = strip_tool_header(line) {
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::Tool;
            cur_title = Some(tool_title);
            if !rest.is_empty() {
                cur_body.push(rest);
            }
            continue;
        }

        if cur_role == ReaderRole::Tool
            && !line.starts_with("  ")
            && !line.starts_with('|')
        {
            flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);
            cur_role = ReaderRole::Assistant;
        }
        cur_body.push(line.clone());
    }
    flush(&mut messages, cur_role, cur_title.take(), &mut cur_body);

    // Keep the newest ~28 messages so compact UI scrolling stays lightning fast.
    if messages.len() > 28 {
        let drop_count = messages.len() - 28;
        messages.drain(0..drop_count);
    }

    (messages, approval, live_activity)
}

fn strip_tui_chrome(raw: &str) -> String {
    let had_indent = raw.starts_with("  ");
    let mut s = raw.trim();
    // Ignore pure horizontal rule lines (box drawing or ASCII separators).
    if !s.is_empty()
        && s.chars().all(|c| {
            matches!(
                c,
                '─' | '━'
                    | '═'
                    | '╭'
                    | '╮'
                    | '╰'
                    | '╯'
                    | '┌'
                    | '┐'
                    | '└'
                    | '┘'
                    | '├'
                    | '┤'
                    | '┬'
                    | '┴'
                    | '┼'
                    | '-'
                    | '='
                    | '╌'
                    | '╍'
            )
        })
    {
        return String::new();
    }
    let mut stripped_box = false;
    if let Some(inner) = s.strip_prefix('│').or_else(|| s.strip_prefix('┃')) {
        s = inner.trim_start();
        stripped_box = true;
    }
    if let Some(inner) = s.strip_suffix('│').or_else(|| s.strip_suffix('┃')) {
        s = inner.trim_end();
        stripped_box = true;
    }
    if s.is_empty() {
        String::new()
    } else if had_indent && !stripped_box {
        format!("  {s}")
    } else {
        s.to_string()
    }
}

fn is_tui_noise_line(line: &str, in_footer_zone: bool) -> bool {
    let s = line.trim();
    if s.is_empty() {
        return true;
    }
    // Empty prompt markers (`>`, `❯`, `›`, `$`, `%`).
    if matches!(s, ">" | "❯" | "›" | "$" | "%" | "●" | "*") {
        return true;
    }
    let lower = s.to_ascii_lowercase();
    let has_sep = s.contains('|') || s.contains('│');
    // Unambiguous desktop TUI Swarm banners & multi-token telemetry/quota statusbars anywhere in scrollback:
    if ((s.contains("Swarm(") || s.contains("Swarm ("))
        && (s.contains("alt+s board")
            || s.contains("coordinator:")
            || s.contains(" active")
            || s.contains("posts ·")))
        || (s.contains("5h ") && s.contains('%') && s.contains("7d "))
        || (lower.contains("tok/s") && (s.contains('%') || lower.contains("ttft")))
        || ((s.contains("k/1.0M") || s.contains("k/200k")) && s.contains('%'))
        || (s.starts_with('(') && s.contains("k)") && s.contains('%') && has_sep)
        || (s.starts_with('↑') && s.contains('↓') && s.contains('%') && s.contains('/'))
    {
        return true;
    }
    if !in_footer_zone {
        return false;
    }
    // Bottom-of-screen TUI mode/shortcut footers (anchored to footer chrome patterns):
    let stripped_prompt = lower.trim_start_matches(['>', '❯', '›', '⏵', '▶', '-', ' ']);
    if stripped_prompt.starts_with("auto mode: edits & safe commands")
        || stripped_prompt.starts_with("bypass permissions on")
        || (stripped_prompt.starts_with("bypass permissions")
            && stripped_prompt.contains("shift+tab"))
        || stripped_prompt.contains("jump to latest message")
        || stripped_prompt == "? for shortcuts"
        || stripped_prompt.ends_with("· ? for shortcuts")
        || stripped_prompt.starts_with("ctrl+g to edit")
        || stripped_prompt.ends_with("/artifact to review")
        || (stripped_prompt.ends_with("context left") && stripped_prompt.contains('%'))
        || stripped_prompt.starts_with("+ tip:")
        || (s.contains("sub (Antigravity)") && s.contains('%'))
    {
        return true;
    }
    false
}

fn is_spinner_or_status_line(line: &str) -> bool {
    const SPINNERS: &[char] = &[
        '⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏', '⢿', '⣻', '⣽', '⣾', '⣷', '⣯', '⣟', '⡿',
        '✻', '✶', '✢',
    ];
    if let Some(first) = line.chars().next() {
        if SPINNERS.contains(&first) || (0x2800..=0x28FF).contains(&(first as u32)) {
            let rest = line[first.len_utf8()..].trim_start();
            if rest.starts_with("Thought") || rest.starts_with("Thinking") {
                return false;
            }
            return true;
        }
    }
    false
}

fn strip_thought_line(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("Thought for ") || trimmed.starts_with("Thinking...") {
        return Some(trimmed.to_string());
    }
    for prefix in ["* ", "● ", "· ", "▶ ", "▸ ", "› "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let r = rest.trim();
            if r.starts_with("Thought for ")
                || r.starts_with("Thinking")
                || r.starts_with("思考")
            {
                return Some(r.to_string());
            }
        }
    }
    None
}

fn strip_user_prompt(line: &str) -> Option<String> {
    for prefix in ["❯ ", "› ", "> "] {
        if let Some(rest) = line.strip_prefix(prefix) {
            let trimmed = rest.trim();
            if !trimmed.is_empty()
                && !trimmed.starts_with("1.")
                && !trimmed.starts_with("[1]")
                && !is_tui_noise_line(trimmed, false)
            {
                return Some(trimmed.to_string());
            }
        }
    }
    // Shell prompt detection (`user@host dir % cmd` or `$ cmd`).
    for marker in [" % ", " $ ", "$ "] {
        if let Some((lhs, rhs)) = line.split_once(marker) {
            if lhs.len() <= 48
                && !rhs.trim().is_empty()
                && (lhs.contains('@') || lhs.contains('~') || lhs.is_empty())
            {
                return Some(rhs.trim().to_string());
            }
        }
    }
    None
}

fn strip_tool_header(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim_start();
    for prefix in ["● ", "• ", "⚙ ", "* ", "▶ ", "▸ "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let r = rest
                .trim()
                .trim_end_matches("(ctrl+o to expand)")
                .trim();
            let looks_like_call = {
                if let Some(open) = r.find('(') {
                    let head = &r[..open];
                    !head.is_empty()
                        && head != "Swarm"
                        && head.len() <= 32
                        && head
                            .chars()
                            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | ':' | '.'))
                } else {
                    false
                }
            };
            if looks_like_call
                || r.starts_with("Ran ")
                || r.starts_with("Read ")
                || r.starts_with("Edit ")
                || r.starts_with("Write ")
                || r.starts_with("Bash ")
            {
                return Some((r.to_string(), String::new()));
            }
        }
    }
    None
}

fn detect_approval(lines: &[String]) -> Option<ApprovalCard> {
    let tail_start = lines.len().saturating_sub(12);
    let tail = &lines[tail_start..];
    let mut options: Vec<ApprovalOption> = Vec::new();
    let mut prompt_idx: Option<usize> = None;

    for (idx, line) in tail.iter().enumerate() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("auto-approved") || lower.contains("bypass permissions") {
            continue;
        }
        let is_question = line.contains('?') || line.contains('？');
        if prompt_idx.is_none()
            && ((lower.contains("allow ") && is_question)
                || (lower.contains("approve") && is_question)
                || lower.contains("do you want to")
                || lower.contains("(y/n)")
                || lower.contains("[y/n]")
                || lower.contains("waiting for approval")
                || line.contains("⚠ Permission:"))
        {
            prompt_idx = Some(idx);
        }

        let clean = line
            .trim_start_matches(['>', '❯', '›', '•', '*', '●'])
            .trim();
        for n in 1..=4u8 {
            let p1 = format!("{n}. ");
            let p2 = format!("[{n}] ");
            let p3 = format!("{n}) ");
            if let Some(label_rest) = clean
                .strip_prefix(&p1)
                .or_else(|| clean.strip_prefix(&p2))
                .or_else(|| clean.strip_prefix(&p3))
            {
                let key = n.to_string();
                if !options.iter().any(|o| o.key == key) {
                    options.push(ApprovalOption {
                        key: key.clone(),
                        label: format!("[{n}] {}", label_rest.trim()),
                        send: key,
                    });
                }
            }
        }
    }

    let idx = prompt_idx?;
    let title = tail[idx].clone();
    let detail = tail
        .get(idx + 1)
        .filter(|l| !l.starts_with('1') && !l.starts_with("[1]"))
        .cloned()
        .unwrap_or_default();

    if options.is_empty() {
        options.push(ApprovalOption {
            key: "y".into(),
            label: "[y] 允许 (Yes)".into(),
            send: "y\r".into(),
        });
        options.push(ApprovalOption {
            key: "n".into(),
            label: "[n] 拒绝 (No)".into(),
            send: "n\r".into(),
        });
    }

    Some(ApprovalCard {
        title,
        detail,
        options,
    })
}

pub fn synthesize_blocked_approval(title: Option<&str>, msg: Option<&str>) -> ApprovalCard {
    ApprovalCard {
        title: title
            .filter(|s| !s.is_empty())
            .unwrap_or("需要确认操作权限")
            .to_string(),
        detail: msg.unwrap_or("远端会话正在等待人工批准").to_string(),
        options: vec![
            ApprovalOption {
                key: "1".into(),
                label: "[1] 允许本次".into(),
                send: "1".into(),
            },
            ApprovalOption {
                key: "2".into(),
                label: "[2] 拒绝".into(),
                send: "2".into(),
            },
            ApprovalOption {
                key: "y".into(),
                label: "[y] 确认回车".into(),
                send: "y\r".into(),
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_libghostty_vt_renders_ansi_cjk_and_coalesces_spans() {
        let actor = VtActor::spawn();
        actor.write_raw_sync(
            "test|s0|b0",
            40,
            8,
            b"\x1b[1;36mzero@cp0\x1b[0m:\x1b[33m~\x1b[0m$ echo \xe4\xbd\xa0\xe5\xa5\xbd\r\n\xe4\xbd\xa0\xe5\xa5\xbd Rex Zero\r\n".to_vec(),
        );
        let view = actor.extract("test|s0|b0", 40, 8);
        let vt = view.vt.expect("vt viewport");
        assert_eq!((vt.cols, vt.rows), (40, 8));
        assert!(!vt.lines[0].is_empty());
        assert_eq!(vt.lines[0][0].t, "zero@cp0");
        assert!(vt.lines[0][0].b);
        assert!(vt.lines[0][0].fg.is_some());
        let line1_text: String = vt.lines[1].iter().map(|s| s.t.as_str()).collect();
        assert_eq!(line1_text, "你好 Rex Zero");
    }

    #[test]
    fn rex_apc_resize_with_matching_nonce_resizes_and_bounds_dimensions() {
        let actor = VtActor::spawn();
        let stop = AtomicBool::new(false);
        let snap_fail = Arc::new(AtomicBool::new(false));
        let (_pipe, waker) = super::super::transport::WakePipe::new().unwrap();
        actor.begin_stream("apc|s0|b0", 1, 40, 10, snap_fail, waker);
        actor.feed_stream(
            "apc|s0|b0",
            1,
            40,
            10,
            777,
            false,
            b"\x1b_rex1;777;{\"type\":\"resize\",\"cols\":50,\"rows\":14}\x1b\\hello".to_vec(),
            &stop,
        );
        // Oversized / wrapped resize (`65537` -> wraps to 1 under naive `as u16`) must be rejected!
        actor.feed_stream(
            "apc|s0|b0",
            1,
            40,
            10,
            777,
            false,
            b"\x1b_rex1;777;{\"type\":\"resize\",\"cols\":65537,\"rows\":9999}\x1b\\".to_vec(),
            &stop,
        );
        let view = actor.extract("apc|s0|b0", 40, 10);
        let vt = view.vt.unwrap();
        assert_eq!((vt.cols, vt.rows), (50, 14));
    }

    #[test]
    fn utf8_multibyte_hex_color_never_panics_and_short_prompt_renders_immediately() {
        // 6-byte UTF-8 ("你好") previously panicked slicing `[0..2]` across a 3-byte codepoint!
        assert_eq!(parse_hex_rgb("你好"), None);
        assert_eq!(parse_hex_rgb("#你好"), None);
        assert_eq!(parse_hex_rgb("#1a2B3c"), Some([0x1a, 0x2b, 0x3c]));

        // Fresh stream with short 2-byte prompt `"$ "` must flush immediately without waiting for 8 bytes!
        let actor = VtActor::spawn();
        let stop = AtomicBool::new(false);
        let snap_fail = Arc::new(AtomicBool::new(false));
        let (pipe, waker) = super::super::transport::WakePipe::new().unwrap();
        actor.begin_stream("short|s0|b0", 1, 40, 8, snap_fail.clone(), waker.clone());
        actor.feed_stream("short|s0|b0", 1, 40, 8, 101, true, b"$ ".to_vec(), &stop);
        let view = actor.extract("short|s0|b0", 40, 8);
        let line0: String = view.vt.unwrap().lines[0]
            .iter()
            .map(|s| s.t.as_str())
            .collect();
        assert_eq!(line0, "$");

        // Retired generation or removed pane frames must be ignored and never recreate slots or corrupt live state!
        actor.begin_stream("short|s0|b0", 2, 40, 8, snap_fail.clone(), waker.clone());
        actor.feed_stream(
            "short|s0|b0",
            1, // stale gen 1!
            40,
            8,
            101,
            false,
            b"STALE".to_vec(),
            &stop,
        );
        let view2 = actor.extract("short|s0|b0", 40, 8);
        let line0_after: String = view2.vt.unwrap().lines[0]
            .iter()
            .map(|s| s.t.as_str())
            .collect();
        assert_eq!(line0_after, "$");

        // Oversized `GHOSTSNP` snapshot is rejected before extending and sets `snapshot_failed` without feeding binary to VT!
        let mut oversized = b"GHOSTSNP".to_vec();
        oversized.resize(MAX_SNAPSHOT_BUFFER + 64, b'X');
        actor.feed_stream("short|s0|b0", 2, 40, 8, 101, true, oversized, &stop);
        assert!(super::super::transport::wait_fd_readable(
            pipe.read_fd(),
            -1,
            1000
        ));
        let view3 = actor.extract("short|s0|b0", 40, 8);
        assert!(snap_fail.load(Ordering::Acquire));
        let line0_clean: String = view3.vt.unwrap().lines[0]
            .iter()
            .map(|s| s.t.as_str())
            .collect();
        assert!(!line0_clean.contains("GHOSTSNP"));
    }

    #[test]
    fn valid_snapshot_split_after_magic() {
        use base64::Engine;
        // Ghostty v1 complete-v1.hex, encoded so the test needs no build cache.
        let snap = base64::engine::general_purpose::STANDARD.decode(concat!(
            "R0hPU1RTTlABAAEAuAMAAONfi8wCAAMAIAMAAFgCAAAAAAIAAAABAAABAAIAZQAAAAEBAQAAAAAACAAEIgBkEAAAAAQiAGQA",
            "AAAABCIAZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD/////////////////////AB0fIcxmZrW9aPDGdIGivrKUu4q+",
            "t8XIxmZmZtVOU7nKSufFR3qm2sOX2HDAserq6gAAAAAAXwAAhwAArwAA1wAA/wBfAABfXwBfhwBfrwBf1wBf/wCHAACHXwCH",
            "hwCHrwCH1wCH/wCvAACvXwCvhwCvrwCv1wCv/wDXAADXXwDXhwDXrwDX1wDX/wD/AAD/XwD/hwD/rwD/1wD//18AAF8AX18A",
            "h18Ar18A118A/19fAF9fX19fh19fr19f119f/1+HAF+HX1+Hh1+Hr1+H11+H/1+vAF+vX1+vh1+vr1+v11+v/1/XAF/XX1/X",
            "h1/Xr1/X11/X/1//AF//X1//h1//r1//11///4cAAIcAX4cAh4cAr4cA14cA/4dfAIdfX4dfh4dfr4df14df/4eHAIeHX4eH",
            "h4eHr4eH14eH/4evAIevX4evh4evr4ev14ev/4fXAIfXX4fXh4fXr4fX14fX/4f/AIf/X4f/h4f/r4f/14f//68AAK8AX68A",
            "h68Ar68A168A/69fAK9fX69fh69fr69f169f/6+HAK+HX6+Hh6+Hr6+H16+H/6+vAK+vX6+vh6+vr6+v16+v/6/XAK/XX6/X",
            "h6/Xr6/X16/X/6//AK//X6//h6//r6//16///9cAANcAX9cAh9cAr9cA19cA/9dfANdfX9dfh9dfr9df19df/9eHANeHX9eH",
            "h9eHr9eH19eH/9evANevX9evh9evr9ev19ev/9fXANfXX9fXh9fXr9fX19fX/9f/ANf/X9f/h9f/r9f/19f///8AAP8AX/8A",
            "h/8Ar/8A1/8A//9fAP9fX/9fh/9fr/9f1/9f//+HAP+HX/+Hh/+Hr/+H1/+H//+vAP+vX/+vh/+vr/+v1/+v///XAP/XX//X",
            "h//Xr//X1//X////AP//X///h///r///1////wgICBISEhwcHCYmJjAwMDo6OkRERE5OTlhYWGJiYmxsbHZ2doCAgIqKipSU",
            "lJ6enqioqLKysry8vMbGxtDQ0Nra2uTk5O7u7oAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQIDFAAAAGZpbGU6",
            "Ly8vdG1wL3NuYXBzaG90EQAAAGNvbXBsZXRlIHNuYXBzaG90AgA2AAAAZzEOxgAAAQAEAAAAAAAAAAAAAAABAAAAAAAAAAAA",
            "AAAAAAAAAAAAAAAAAAgAAAAAAAAAAAAAAAAAAAMAJAAAAKJPJtECAAMAAAAAABAAwAAABAAAAAgAAAABAEMAAQBEAAEARQAA",
            "AAACADYAAADOH58IAQABAAAAAAAAAAAAAQACAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAAAAAAAAAAAAAAAAAwAmAAAA",
            "YhyrewIAAwAAAAAAgADAAAACAAAACAAAAwIAcm4DAgBhdAIBAGUAAAAABwAAAAAAJ4Bj0QUAAAAAAOQg7woEAAYAAAAgMu3h",
            "AAACAAAAAwAfAAAASu0vwgIAAgAAAAAAEADAAAAEAAAACAAAAAEAQgAAAAAAAAADAB8AAAAjamsZAgACAAAAAAAQAMAAAAQA",
            "AAAIAAAAAQBBAAAAAAAAAAQABgAAALh6urEBAAAAAAAGAAAAAAA+61M+"
        )).unwrap();
        let mut slot = TerminalSlot::new(40, 8).unwrap();
        assert!(slot.feed_stream(1, true, &snap[..8]));
        assert!(matches!(
            slot.decode_state,
            StreamDecodeState::AwaitingSnapshot { .. }
        ));
        assert!(slot.feed_stream(1, false, &snap[8..]));
        assert!(matches!(slot.decode_state, StreamDecodeState::Live));
        for (i, chunk) in snap.chunks(1).enumerate() {
            assert!(slot.feed_stream(2, i == 0, chunk));
        }
        assert!(matches!(slot.decode_state, StreamDecodeState::Live));
    }

    #[test]
    fn semantic_reader_detects_approval_card_and_messages() {
        let lines = vec![
            "❯ cargo zigbuild --release".to_string(),
            "⏺ Bash(cargo zigbuild --release)".to_string(),
            "Allow command cargo zigbuild --release?".to_string(),
            "  target aarch64-unknown-linux-gnu.2.36".to_string(),
            "  [1] Allow once".to_string(),
            "  [2] Deny".to_string(),
        ];
        let (msgs, approval, _) = parse_semantic_terminal(&lines);
        assert!(msgs.iter().any(|m| m.role == ReaderRole::User));
        let card = approval.expect("approval card");
        assert_eq!(card.options.len(), 2);
        assert_eq!(card.options[0].send, "1");
        assert_eq!(card.options[1].send, "2");
    }

    #[test]
    fn semantic_reader_strips_agy_telemetry_and_pua_tofu_without_false_approval() {
        assert_eq!(sanitize_vt_span_text("A\u{f110}B"), "A B");
        let lines = vec![
            "❯ \u{f110} 修复客户端列表和字体清晰度".to_string(),
            "⠋ Thought for 4s".to_string(),
            "⏺ Read(app/scenes/inbox.tsx)".to_string(),
            "  ⎿  read 200 lines".to_string(),
            "The label should read \"context left\" in normal prose.".to_string(),
            "Press Shift+Tab to bypass permissions in this menu.".to_string(),
            "已完成双行卡片与一比特锐利字库改造。".to_string(),
            "❯ 👍".to_string(),
            "收到！".to_string(),
            "────────────────────────────────────────".to_string(),
            "\u{f007} S6:alice \u{f135} 4 Hydrogen (High) │ \u{f0e7} 94 tok/s ttft 3.2s │ \u{f1c0} 96% (52.8k) │ demo".to_string(),
            "\u{f2db} ──────── 6% 61.5k/1.0M │ \u{f240} 5h 96%(1h57m) 7d 97%(6d11h)".to_string(),
            "> Auto mode: edits & safe commands auto-approved · shift+tab to cycle".to_string(),
            "⏵⏵ bypass permissions on (shift+tab to cycle)".to_string(),
        ];
        let (msgs, approval, _) = parse_semantic_terminal(&lines);
        assert!(approval.is_none(), "auto-approved footer must NOT synthesize ApprovalCard");
        assert_eq!(msgs.len(), 6);
        assert_eq!(msgs[0].role, ReaderRole::User);
        assert_eq!(msgs[0].body, "修复客户端列表和字体清晰度");
        assert_eq!(msgs[1].role, ReaderRole::Tool);
        assert_eq!(msgs[1].title.as_deref(), Some("思考"));
        assert_eq!(msgs[2].role, ReaderRole::Tool);
        assert_eq!(msgs[2].title.as_deref(), Some("Read(app/scenes/inbox.tsx)"));
        assert_eq!(msgs[3].role, ReaderRole::Assistant);
        assert!(msgs[3].body.contains("context left"));
        assert!(msgs[3].body.contains("Press Shift+Tab to bypass permissions in this menu."));
        assert!(msgs[3].body.contains("已完成双行卡片与一比特锐利字库改造。"));
        assert_eq!(msgs[4].role, ReaderRole::User);
        assert_eq!(msgs[4].body, "[emoji]");
        assert_eq!(msgs[5].role, ReaderRole::Assistant);
        assert_eq!(msgs[5].body, "收到！");
    }

    #[test]
    fn strips_swarm_footer_indented_thoughts_braille_tofu_and_encodes_prefixed_ctrl_keys() {
        assert_eq!(fallback_encode_key("Control+c", 0), "\x03");
        assert_eq!(fallback_encode_key("Ctrl+d", 0), "\x04");
        assert_eq!(fallback_encode_key("Shift+Tab", 0), "\x1b[Z");
        assert_eq!(sanitize_vt_span_text("⢿  Running ▸ ok"), "·  Running › ok");

        let lines = vec![
            "▸ Thought for 1m 56s, 6.3k tokens".to_string(),
            "  The current design conflates remote control actions with settings...".to_string(),
            "".to_string(),
            "● Bash(cargo test) (ctrl+o to expand)".to_string(),
            "All tests passed!".to_string(),
            "⢿  Running command...".to_string(),
            "────────────────────────────────────────".to_string(),
            ">".to_string(),
            "────────────────────────────────────────".to_string(),
            "  ● Swarm(Rex Zero v0.2 — Memory & Test Fixes)  coordinator: @astr… · 49 posts · alt+s board".to_string(),
        ];
        let (msgs, _, live_act) = parse_semantic_terminal(&lines);
        assert_eq!(live_act.as_deref(), Some("Running command..."));
        assert!(!msgs.iter().any(|m| m.body.contains("Swarm(") || m.title.as_deref().unwrap_or("").contains("Swarm")));
        assert!(!msgs.iter().any(|m| m.body.contains("conflates remote control")));
        assert!(msgs.iter().any(|m| m.role == ReaderRole::Tool && m.title.as_deref() == Some("Bash(cargo test)")));
        assert!(msgs.iter().any(|m| m.role == ReaderRole::Assistant && m.body.contains("All tests passed!")));
    }
}
