//! Font atlas registry + text measurement + inline-run layout.
//!
//! Parses font-atlas blobs (spec.ts "FONT ATLAS binary format", constants in
//! spec::font_atlas) into a MAX_FONT_SLOTS registry. cmap lookups binary
//! search (entries are sorted ascending by codepoint); a miss resolves to
//! gid 0 (the tofu box) and bumps the per-core miss counter.
//!
//! v1 line model (documented limitation): NO automatic word wrap — a run
//! breaks only on explicit '\n'. Measurement is the max line width (sum of
//! advances + tracking per glyph) by lines x line height.

use ab_glyph::{Font as AbFont, PxScale, ScaleFont};
use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::spec;

/// Maximum number of dynamic on-demand fallback glyph cells per compact font
/// atlas (`line_height <= 22 && cell_h <= 20`), further capped by
/// [`DYN_SLOT_BUDGET_BYTES`] and the shared [`DYN_TOTAL_BUDGET_BYTES`].
pub const DYN_CAP: usize = 384;
/// Per-slot dynamic fallback RAM ceiling (bitmap cells + LRU metadata).
pub const DYN_SLOT_BUDGET_BYTES: usize = 72 * 1024;
/// Shared `Fonts`-wide dynamic fallback RAM ceiling across all loaded slots.
pub const DYN_TOTAL_BUDGET_BYTES: usize = 360 * 1024;
const DYN_HASH_BUCKETS: usize = 512;
const DYN_EMPTY: u16 = u16::MAX;

static FALLBACK_FONT: AtomicPtr<ab_glyph::FontRef<'static>> =
    AtomicPtr::new(core::ptr::null_mut());

/// Select the Simplified Chinese (`SC`) face index inside an OpenType Collection (`.ttc`),
/// or `0` for standalone `.ttf`/`.otf` and non-SC collections.
fn select_preferred_face_index(bytes: &[u8]) -> u32 {
    if bytes.len() < 16 || &bytes[..4] != b"ttcf" {
        return 0;
    }
    let num_fonts = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]).min(32);
    for idx in 0..num_fonts {
        let off_pos = 12 + (idx as usize) * 4;
        let Some(sfnt_off) = rd_be_u32(bytes, off_pos).map(|v| v as usize) else {
            break;
        };
        if sfnt_has_sc_postscript_name(bytes, sfnt_off)
            && ab_glyph::FontRef::try_from_slice_and_index(bytes, idx).is_ok()
        {
            return idx;
        }
    }
    0
}

#[inline]
fn rd_be_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

#[inline]
fn rd_be_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

/// Inspect SFNT `name` table records for non-Mono Simplified Chinese (`CJKsc` / ` SC`,
/// excluding `Mono`) so `NotoSansCJK-*.ttc` picks `NotoSansCJKsc` (face 2).
fn sfnt_has_sc_postscript_name(bytes: &[u8], sfnt_off: usize) -> bool {
    let Some(num_tables) = rd_be_u16(bytes, sfnt_off + 4).map(|v| v as usize) else {
        return false;
    };
    let mut name_table: Option<(usize, usize)> = None;
    for i in 0..num_tables.min(64) {
        let rec = sfnt_off + 12 + i * 16;
        let Some(tag) = bytes.get(rec..rec + 4) else {
            return false;
        };
        if tag == b"name" {
            let Some(toff) = rd_be_u32(bytes, rec + 8).map(|v| v as usize) else {
                return false;
            };
            let Some(tlen) = rd_be_u32(bytes, rec + 12).map(|v| v as usize) else {
                return false;
            };
            name_table = Some((toff, tlen));
            break;
        }
    }
    let Some((noff, nlen)) = name_table else {
        return false;
    };
    let Some(nb) = bytes.get(noff..noff.saturating_add(nlen.min(8192))) else {
        return false;
    };
    let Some(count) = rd_be_u16(nb, 2).map(|v| v as usize) else {
        return false;
    };
    let Some(str_off) = rd_be_u16(nb, 4).map(|v| v as usize) else {
        return false;
    };
    for i in 0..count.min(64) {
        let r = 6 + i * 12;
        let Some(nid) = rd_be_u16(nb, r + 6) else {
            break;
        };
        if nid != 6 && nid != 1 && nid != 4 {
            continue;
        }
        let Some(slen) = rd_be_u16(nb, r + 8).map(|v| v as usize) else {
            continue;
        };
        let Some(roff) = rd_be_u16(nb, r + 10).map(|v| v as usize) else {
            continue;
        };
        let Some(raw) = nb.get(str_off.saturating_add(roff)..str_off.saturating_add(roff).saturating_add(slen)) else {
            continue;
        };
        // Strip UTF-16BE zero high bytes to ASCII for simple substring match.
        let mut ascii = [0u8; 96];
        let mut alen = 0usize;
        for &b in raw {
            if b != 0 && alen < ascii.len() {
                ascii[alen] = b.to_ascii_lowercase();
                alen += 1;
            }
        }
        let s = &ascii[..alen];
        let is_mono = s.windows(4).any(|w| w == b"mono");
        let is_sc = s.windows(5).any(|w| w == b"cjksc") || s.ends_with(b" sc");
        if is_sc && !is_mono {
            return true;
        }
    }
    false
}

/// Validate whether `bytes` is a parseable TrueType/OpenType font face (or TTC)
/// without installing or retaining it.
pub fn validate_fallback_ttf(bytes: &[u8]) -> bool {
    let idx = select_preferred_face_index(bytes);
    ab_glyph::FontRef::try_from_slice_and_index(bytes, idx).is_ok()
}

/// Register a static TrueType/OpenType font buffer (e.g. a leaked read-only
/// `memmap2::Mmap` of an OS-managed font or an owned immutable snapshot) as the
/// process-wide on-demand CJK fallback font. Validates `bytes` before
/// installation and returns `true` ONLY when this call wins installation.
pub fn set_fallback_ttf(bytes: &'static [u8]) -> bool {
    if !FALLBACK_FONT.load(Ordering::Acquire).is_null() {
        return false;
    }
    let idx = select_preferred_face_index(bytes);
    let Ok(font) = ab_glyph::FontRef::try_from_slice_and_index(bytes, idx) else {
        return false;
    };
    let ptr = Box::into_raw(Box::new(font));
    if FALLBACK_FONT
        .compare_exchange(
            core::ptr::null_mut(),
            ptr,
            Ordering::AcqRel,
            Ordering::Acquire,
        )
        .is_err()
    {
        // Another thread installed first; reclaim our boxed FontRef.
        unsafe {
            drop(Box::from_raw(ptr));
        }
        return false;
    }
    true
}

/// True once a valid fallback TTF has been registered via [`set_fallback_ttf`].
#[inline]
pub fn has_fallback_ttf() -> bool {
    !FALLBACK_FONT.load(Ordering::Acquire).is_null()
}

#[inline]
fn global_fallback_font() -> Option<&'static ab_glyph::FontRef<'static>> {
    let ptr = FALLBACK_FONT.load(Ordering::Acquire);
    if ptr.is_null() {
        None
    } else {
        // SAFETY: `FALLBACK_FONT` is set once via `Box::into_raw` and never
        // freed for the lifetime of the process.
        Some(unsafe { &*ptr })
    }
}

#[inline]
fn floor_i32(x: f32) -> i32 {
    let i = x as i32;
    if (i as f32) > x {
        i - 1
    } else {
        i
    }
}

#[inline]
fn hash_cp(cp: u32) -> usize {
    cp.wrapping_mul(0x9E37_79B1) as usize
}

/// Output root that owns a dynamic glyph pin epoch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DrawRoot {
    Primary,
    Auxiliary,
}

#[derive(Clone, Copy, Debug)]
struct DynSlot {
    codepoint: u32,
    advance: u8,
    xoff: u8,
    last_tick: u64,
    pinned_primary: u64,
    pinned_aux: u64,
}

fn dyn_hash_buckets(cap: usize) -> usize {
    if cap == 0 {
        return 0;
    }
    ((cap * 4) / 3 + 1)
        .next_power_of_two()
        .max(16)
        .min(DYN_HASH_BUCKETS)
}

pub(crate) fn dyn_allocation_bytes(cap: usize, per_glyph: usize) -> usize {
    if cap == 0 {
        return 0;
    }
    let per_entry = per_glyph.saturating_add(core::mem::size_of::<DynSlot>());
    let table_bytes = dyn_hash_buckets(cap).saturating_mul(core::mem::size_of::<u16>());
    cap.saturating_mul(per_entry).saturating_add(table_bytes)
}

pub(crate) fn compute_dyn_cap(baked_count: u16, per_glyph: usize, budget_bytes: usize) -> usize {
    let per_entry = per_glyph.saturating_add(core::mem::size_of::<DynSlot>());
    if per_entry == 0 || budget_bytes == 0 {
        return 0;
    }
    let max_by_gid = (u16::MAX as usize).saturating_sub(baked_count as usize);
    let mut cap = (budget_bytes / per_entry).min(DYN_CAP).min(max_by_gid);
    while cap > 0 && dyn_allocation_bytes(cap, per_glyph) > budget_bytes {
        cap -= 1;
    }
    cap
}

struct DynLruCache {
    entries: Vec<DynSlot>,
    table: Vec<u16>,
    tick: u64,
    primary_epoch: u64,
    aux_epoch: u64,
}

impl DynLruCache {
    fn new(cap: usize) -> Self {
        let buckets = dyn_hash_buckets(cap);
        debug_assert!(cap > 0 && cap < buckets && buckets.is_power_of_two());
        let entries = vec![
            DynSlot {
                codepoint: u32::MAX,
                advance: 0,
                xoff: 0,
                last_tick: 0,
                pinned_primary: 0,
                pinned_aux: 0,
            };
            cap
        ];
        let table = vec![DYN_EMPTY; buckets];
        Self {
            entries,
            table,
            tick: 0,
            primary_epoch: 1,
            aux_epoch: 0,
        }
    }

    #[inline]
    fn cap(&self) -> usize {
        self.entries.len()
    }

    /// Actual allocated heap bytes for the LRU slot and hash-bucket vectors.
    #[inline]
    fn metadata_bytes(&self) -> usize {
        self.entries
            .capacity()
            .saturating_mul(core::mem::size_of::<DynSlot>())
            .saturating_add(
                self.table
                    .capacity()
                    .saturating_mul(core::mem::size_of::<u16>()),
            )
    }

    /// Shrink capacity and release excess metadata heap allocations.
    fn clear_and_shrink(&mut self, new_cap: usize) {
        let new_buckets = dyn_hash_buckets(new_cap);
        debug_assert!(
            new_cap > 0 && new_cap <= self.entries.len() && new_buckets <= self.table.len()
        );
        self.entries.truncate(new_cap);
        self.entries.shrink_to_fit();
        for e in &mut self.entries {
            *e = DynSlot {
                codepoint: u32::MAX,
                advance: 0,
                xoff: 0,
                last_tick: 0,
                pinned_primary: 0,
                pinned_aux: 0,
            };
        }
        self.table.truncate(new_buckets);
        self.table.shrink_to_fit();
        self.table.fill(DYN_EMPTY);
        self.tick = 0;
        self.primary_epoch = 1;
        self.aux_epoch = 0;
    }

    fn begin_batch_for(&mut self, root: DrawRoot) -> u64 {
        match root {
            DrawRoot::Primary => {
                self.primary_epoch = self.primary_epoch.wrapping_add(1);
                if self.primary_epoch == 0 {
                    self.primary_epoch = 1;
                    for e in &mut self.entries {
                        e.pinned_primary = 0;
                    }
                }
                self.primary_epoch
            }
            DrawRoot::Auxiliary => {
                self.aux_epoch = self.aux_epoch.wrapping_add(1);
                if self.aux_epoch == 0 {
                    self.aux_epoch = 1;
                    for e in &mut self.entries {
                        e.pinned_aux = 0;
                    }
                }
                self.aux_epoch
            }
        }
    }

    #[cfg(test)]
    fn begin_batch(&mut self) -> u64 {
        self.begin_batch_for(DrawRoot::Primary)
    }

    #[inline]
    fn current_epoch_for(&self, root: DrawRoot) -> u64 {
        match root {
            DrawRoot::Primary => self.primary_epoch,
            DrawRoot::Auxiliary => self.aux_epoch,
        }
    }

    /// Read-only cache lookup (zero mutation; safe under `&self`).
    fn peek(&self, cp: u32) -> Option<(u16, u8, u8)> {
        let mask = self.table.len() - 1;
        let mut pos = hash_cp(cp) & mask;
        loop {
            let slot = self.table[pos];
            if slot == DYN_EMPTY {
                return None;
            }
            let entry = &self.entries[slot as usize];
            if entry.codepoint == cp {
                return Some((slot, entry.advance, entry.xoff));
            }
            pos = (pos + 1) & mask;
        }
    }

    fn get_and_pin_for(&mut self, cp: u32, root: DrawRoot, batch_epoch: u64) -> Option<(u16, u8, u8)> {
        let mask = self.table.len() - 1;
        let mut pos = hash_cp(cp) & mask;
        loop {
            let slot = self.table[pos];
            if slot == DYN_EMPTY {
                return None;
            }
            let entry = &mut self.entries[slot as usize];
            if entry.codepoint == cp {
                self.tick = self.tick.wrapping_add(1);
                entry.last_tick = self.tick;
                if batch_epoch != 0 {
                    match root {
                        DrawRoot::Primary => entry.pinned_primary = batch_epoch,
                        DrawRoot::Auxiliary => entry.pinned_aux = batch_epoch,
                    }
                }
                return Some((slot, entry.advance, entry.xoff));
            }
            pos = (pos + 1) & mask;
        }
    }

    #[cfg(test)]
    fn get_and_pin(&mut self, cp: u32, batch_epoch: u64) -> Option<(u16, u8, u8)> {
        self.get_and_pin_for(cp, DrawRoot::Primary, batch_epoch)
    }

    fn remove_hash(&mut self, cp: u32) {
        let mask = self.table.len() - 1;
        let mut pos = hash_cp(cp) & mask;
        loop {
            let slot = self.table[pos];
            if slot == DYN_EMPTY {
                return;
            }
            if self.entries[slot as usize].codepoint == cp {
                break;
            }
            pos = (pos + 1) & mask;
        }
        let mut hole = pos;
        let mut cur = (pos + 1) & mask;
        loop {
            let slot = self.table[cur];
            if slot == DYN_EMPTY {
                self.table[hole] = DYN_EMPTY;
                return;
            }
            let ideal = hash_cp(self.entries[slot as usize].codepoint) & mask;
            let dist_cur = cur.wrapping_sub(ideal) & mask;
            let dist_hole = hole.wrapping_sub(ideal) & mask;
            if dist_hole < dist_cur {
                self.table[hole] = slot;
                hole = cur;
            }
            cur = (cur + 1) & mask;
        }
    }

    fn insert_hash(&mut self, cp: u32, slot_idx: u16) {
        let mask = self.table.len() - 1;
        let mut pos = hash_cp(cp) & mask;
        while self.table[pos] != DYN_EMPTY {
            pos = (pos + 1) & mask;
        }
        self.table[pos] = slot_idx;
    }

    #[inline]
    fn is_pinned_for(&self, entry: &DynSlot, root: DrawRoot, batch_epoch: u64) -> bool {
        let primary_pinned = match root {
            DrawRoot::Primary => batch_epoch != 0 && entry.pinned_primary == batch_epoch,
            DrawRoot::Auxiliary => {
                self.primary_epoch != 0 && entry.pinned_primary == self.primary_epoch
            }
        };
        let aux_pinned = match root {
            DrawRoot::Primary => self.aux_epoch != 0 && entry.pinned_aux == self.aux_epoch,
            DrawRoot::Auxiliary => batch_epoch != 0 && entry.pinned_aux == batch_epoch,
        };
        primary_pinned || aux_pinned
    }

    /// Allocate a free or unpinned LRU slot. Returns `None` if every slot is
    /// currently pinned by the active primary or auxiliary output root so
    /// glyphs referenced by either retained draw list are never overwritten.
    fn alloc_slot_for(
        &mut self,
        cp: u32,
        advance: u8,
        xoff: u8,
        root: DrawRoot,
        batch_epoch: u64,
    ) -> Option<u16> {
        let idx = self
            .entries
            .iter()
            .position(|e| e.codepoint == u32::MAX)
            .or_else(|| {
                self.entries
                    .iter()
                    .enumerate()
                    .filter(|(_, e)| !self.is_pinned_for(e, root, batch_epoch))
                    .min_by_key(|(_, e)| e.last_tick)
                    .map(|(i, _)| i)
            })?;
        let old_cp = self.entries[idx].codepoint;
        if old_cp != u32::MAX {
            self.remove_hash(old_cp);
        }
        self.tick = self.tick.wrapping_add(1);
        let (pinned_primary, pinned_aux) = match root {
            DrawRoot::Primary => (batch_epoch, 0),
            DrawRoot::Auxiliary => (0, batch_epoch),
        };
        self.entries[idx] = DynSlot {
            codepoint: cp,
            advance,
            xoff,
            last_tick: self.tick,
            pinned_primary,
            pinned_aux,
        };
        self.insert_hash(cp, idx as u16);
        Some(idx as u16)
    }

    #[cfg(test)]
    fn alloc_slot(&mut self, cp: u32, advance: u8, xoff: u8, batch_epoch: u64) -> Option<u16> {
        self.alloc_slot_for(cp, advance, xoff, DrawRoot::Primary, batch_epoch)
    }
}

#[inline]
fn rd_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}

#[inline]
fn rd_u32(b: &[u8], off: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(off)?,
        *b.get(off + 1)?,
        *b.get(off + 2)?,
        *b.get(off + 3)?,
    ]))
}

/// One cmap entry (sorted ascending by codepoint in the blob).
#[derive(Clone, Copy, Debug)]
pub struct CmapEntry {
    pub codepoint: u32,
    pub gid: u16,
    /// Logical px advance; independent of atlas raster density.
    pub advance: u8,
    /// Left-side-bearing shift (cmap byte +7): logical px the outline was shifted
    /// RIGHT at bake so negative-LSB ink stays inside the cell. The cell is
    /// placed at penX - xoff when drawing.
    pub xoff: u8,
}

/// One parsed font atlas (a (family-weight, px) bake bound to a slot).
pub struct Atlas {
    /// Logical cell dimensions. Coverage dimensions are these times
    /// `raster_density`.
    pub cell_w: u32,
    pub cell_h: u32,
    pub(crate) texture_cell_w: u32,
    /// Logical px from cell top to the baseline.
    pub baseline: u32,
    /// Default logical line advance in px.
    pub line_height: u32,
    /// Raster samples per logical pixel (v2 atlases resolve to 1).
    pub raster_density: u8,
    pub slot: u8,
    pub flags: u8,
    /// Number of baked glyphs (`0..baked_count`) parsed from the atlas blob.
    pub baked_count: u16,
    /// Total addressable glyphs (`baked_count + dynamic_cap` or `baked_count + stream_cap`).
    pub glyph_count: u16,
    pub(crate) cmap: Vec<CmapEntry>,
    pub(crate) stream: Option<crate::font_stream::Stream>,
    /// On-demand LRU cache for unbaked codepoints (`gid` in `baked_count..baked_count + dyn_cap`).
    dyn_cache: Option<DynLruCache>,
    /// Monotonic counter bumped on every write/overwrite to a dynamic tail cell.
    dyn_revision: u64,
    /// Per-atlas fallback font override used by unit tests so parallel tests
    /// never race on global `FALLBACK_FONT`.
    #[cfg(test)]
    fallback_override: Option<ab_glyph::FontRef<'static>>,
    /// Coverage cells: glyphCount x (cellH*density) x (cellW*density)
    /// alpha bytes, left-to-right.
    pub(crate) bitmap: Vec<u8>,
}

impl Atlas {
    /// Parse a font-atlas blob (copies the bytes it keeps). `None` on bad
    /// magic/version/slot or truncation.
    pub fn parse(bytes: &[u8]) -> Option<Atlas> {
        Self::parse_inner(bytes, None, DYN_SLOT_BUDGET_BYTES)
    }

    pub(crate) fn parse_with_budget(bytes: &[u8], max_dyn_bytes: usize) -> Option<Atlas> {
        Self::parse_inner(bytes, None, max_dyn_bytes)
    }

    #[cfg(test)]
    pub(crate) fn parse_with_fallback(
        bytes: &[u8],
        font: ab_glyph::FontRef<'static>,
    ) -> Option<Atlas> {
        Self::parse_inner(bytes, Some(font), DYN_SLOT_BUDGET_BYTES)
    }

    #[cfg(test)]
    pub(crate) fn parse_with_fallback_budget(
        bytes: &[u8],
        font: ab_glyph::FontRef<'static>,
        max_dyn_bytes: usize,
    ) -> Option<Atlas> {
        Self::parse_inner(bytes, Some(font), max_dyn_bytes)
    }

    fn parse_inner(
        bytes: &[u8],
        fallback_override: Option<ab_glyph::FontRef<'static>>,
        max_dyn_bytes: usize,
    ) -> Option<Atlas> {
        use spec::font_atlas as fa;
        if rd_u32(bytes, 0)? != fa::MAGIC {
            return None;
        }
        let version = rd_u16(bytes, 4)?;
        // Atlas v2 used bytes 14..15 as reserved and had one coverage sample
        // per logical pixel. Keep loading it so old packs remain usable.
        let raster_density = if version == 2 {
            1
        } else if version == fa::VERSION {
            let density = *bytes.get(14)?;
            if density == 0 {
                return None;
            }
            density
        } else {
            return None;
        };
        let baked_count = rd_u16(bytes, 6)?;
        let cell_w = *bytes.get(8)? as u32;
        let cell_h = *bytes.get(9)? as u32;
        let baseline = *bytes.get(10)? as u32;
        let line_height = *bytes.get(11)? as u32;
        let slot = *bytes.get(12)?;
        let flags = *bytes.get(13)?;
        if slot as usize >= spec::MAX_FONT_SLOTS
            || baked_count == 0
            || cell_w == 0
            || cell_h == 0
        {
            return None;
        }
        let cmap_off = fa::HEADER_SIZE;
        let bitmap_off = (baked_count as usize)
            .checked_mul(fa::CMAP_ENTRY_SIZE)?
            .checked_add(cmap_off)?;
        let coverage_w = (cell_w as usize).checked_mul(raster_density as usize)?;
        let coverage_h = (cell_h as usize).checked_mul(raster_density as usize)?;
        let per_glyph = coverage_h.checked_mul(coverage_w)?;
        let bitmap_len = (baked_count as usize).checked_mul(per_glyph)?;
        let bitmap_end = bitmap_off.checked_add(bitmap_len)?;
        if bytes.len() < bitmap_end {
            return None;
        }
        let mut cmap = Vec::with_capacity(baked_count as usize);
        for i in 0..baked_count as usize {
            let o = cmap_off + i * fa::CMAP_ENTRY_SIZE;
            let gid = rd_u16(bytes, o + 4)?;
            if gid >= baked_count {
                return None;
            }
            cmap.push(CmapEntry {
                codepoint: rd_u32(bytes, o)?,
                gid,
                advance: *bytes.get(o + 6)?,
                xoff: *bytes.get(o + 7)?,
            });
        }
        let has_fallback = fallback_override.is_some() || global_fallback_font().is_some();
        let dyn_cap = if has_fallback && line_height <= 22 && cell_h <= 22 {
            compute_dyn_cap(baked_count, per_glyph, max_dyn_bytes.min(DYN_SLOT_BUDGET_BYTES))
        } else {
            0
        };
        let glyph_count = baked_count + dyn_cap as u16;
        let total_bitmap_len = (glyph_count as usize).checked_mul(per_glyph)?;
        let mut bitmap = Vec::with_capacity(total_bitmap_len);
        bitmap.extend_from_slice(&bytes[bitmap_off..bitmap_end]);
        if dyn_cap > 0 {
            bitmap.resize(total_bitmap_len, 0);
        }
        let dyn_cache = if dyn_cap > 0 {
            Some(DynLruCache::new(dyn_cap))
        } else {
            None
        };
        #[cfg(not(test))]
        let _ = fallback_override;
        Some(Atlas {
            cell_w,
            cell_h,
            baseline,
            line_height,
            raster_density,
            slot,
            flags,
            baked_count,
            glyph_count,
            cmap,
            stream: None,
            dyn_cache,
            dyn_revision: 0,
            #[cfg(test)]
            fallback_override,
            texture_cell_w: cell_w,
            bitmap,
        })
    }

    #[inline]
    fn active_fallback_font(&self) -> Option<ab_glyph::FontRef<'static>> {
        #[cfg(test)]
        if let Some(ref f) = self.fallback_override {
            return Some(f.clone());
        }
        global_fallback_font().cloned()
    }

    #[inline]
    fn per_glyph_bytes(&self) -> usize {
        self.coverage_width() as usize * self.coverage_height() as usize
    }

    /// Number of reserved dynamic fallback cells on this atlas (`0` when disabled or streaming).
    #[inline]
    pub fn dyn_cap(&self) -> usize {
        self.dyn_cache.as_ref().map_or(0, DynLruCache::cap)
    }

    /// True when this atlas has an active dynamic fallback cache.
    #[inline]
    pub fn has_dynamic_cache(&self) -> bool {
        self.stream.is_none() && self.dyn_cache.is_some()
    }

    /// Dynamic bitmap + LRU cache metadata heap RAM currently allocated by this
    /// atlas (measured on actual `Vec::capacity()`, excluding baked cells and
    /// font-stream allocations).
    #[inline]
    pub fn dynamic_ram_bytes(&self) -> usize {
        if self.stream.is_some() {
            return 0;
        }
        let baked_bytes = (self.baked_count as usize).saturating_mul(self.per_glyph_bytes());
        let bitmap_dyn_bytes = self.bitmap.capacity().saturating_sub(baked_bytes);
        let meta_bytes = self
            .dyn_cache
            .as_ref()
            .map_or(0, DynLruCache::metadata_bytes);
        bitmap_dyn_bytes.saturating_add(meta_bytes)
    }

    /// Monotonic counter incremented every time a dynamic cell in `bitmap` is
    /// written or overwritten.
    #[inline]
    pub fn dynamic_revision(&self) -> u64 {
        self.dyn_revision
    }

    /// Combine a slot's structural `base_revision` with `dynamic_revision()` so
    /// page caches and layout caches invalidate whenever dynamic pixels change,
    /// while remaining equal to `base_revision` when no dynamic write occurred.
    #[inline]
    pub fn content_revision(&self, base_revision: u64) -> u64 {
        base_revision.wrapping_add(self.dyn_revision.wrapping_shl(32))
    }

    /// Drop dynamic cache metadata (used when attaching a font stream).
    pub(crate) fn drop_dynamic_cache(&mut self) {
        self.dyn_cache = None;
    }

    /// Re-initialize an empty dynamic cache after detaching a font stream,
    /// bounded by `max_dyn_bytes` and [`DYN_SLOT_BUDGET_BYTES`].
    pub(crate) fn restore_dynamic_cache(&mut self, max_dyn_bytes: usize) {
        debug_assert!(self.stream.is_none());
        let per_glyph = self.per_glyph_bytes();
        let dyn_cap = if self.active_fallback_font().is_some()
            && self.line_height <= 22
            && self.cell_h <= 22
        {
            compute_dyn_cap(
                self.baked_count,
                per_glyph,
                max_dyn_bytes.min(DYN_SLOT_BUDGET_BYTES),
            )
        } else {
            0
        };
        self.glyph_count = self.baked_count + dyn_cap as u16;
        let total_len = self.glyph_count as usize * per_glyph;
        self.bitmap.resize(total_len, 0);
        self.bitmap.shrink_to_fit();
        self.dyn_cache = if dyn_cap > 0 {
            Some(DynLruCache::new(dyn_cap))
        } else {
            None
        };
    }

    /// Shrink this atlas's dynamic allocation and release excess `Vec`
    /// capacities so actual allocated dynamic RAM fits `max_dyn_bytes`.
    pub(crate) fn trim_dynamic_budget(&mut self, max_dyn_bytes: usize) {
        if self.stream.is_some() {
            return;
        }
        let per_glyph = self.per_glyph_bytes();
        let current_cap = self.dyn_cap();
        let new_cap = compute_dyn_cap(
            self.baked_count,
            per_glyph,
            max_dyn_bytes.min(DYN_SLOT_BUDGET_BYTES),
        );
        if new_cap >= current_cap {
            if self.dynamic_ram_bytes() > max_dyn_bytes {
                self.bitmap.shrink_to_fit();
                if let Some(cache) = self.dyn_cache.as_mut() {
                    cache.entries.shrink_to_fit();
                    cache.table.shrink_to_fit();
                }
            }
            return;
        }
        if new_cap == 0 {
            self.dyn_cache = None;
            self.glyph_count = self.baked_count;
            self.bitmap.truncate(self.baked_count as usize * per_glyph);
            self.bitmap.shrink_to_fit();
        } else {
            if let Some(cache) = self.dyn_cache.as_mut() {
                cache.clear_and_shrink(new_cap);
            }
            self.glyph_count = self.baked_count + new_cap as u16;
            self.bitmap.truncate(self.glyph_count as usize * per_glyph);
            self.bitmap.shrink_to_fit();
        }
    }

    /// Borrow the full coverage bitmap slice (`glyph_count * coverage_h * coverage_w`).
    #[inline]
    pub fn bitmap_slice(&self) -> &[u8] {
        &self.bitmap
    }

    /// Allocated capacity of the underlying coverage buffer (for diagnostics/tests).
    #[inline]
    pub fn bitmap_capacity(&self) -> usize {
        self.bitmap.capacity()
    }

    /// Advance the primary batch pinning epoch so previously pinned dynamic cells
    /// (unless still pinned by the auxiliary output root) become eligible for
    /// LRU eviction in a new draw pass.
    pub fn begin_batch(&mut self) -> u64 {
        self.begin_batch_for(DrawRoot::Primary)
    }

    /// Advance the batch pinning epoch for a specific output root (`Primary` or
    /// `Auxiliary`), preserving pins owned by the other output root.
    pub fn begin_batch_for(&mut self, root: DrawRoot) -> u64 {
        self.dyn_cache
            .as_mut()
            .map_or(0, |c| c.begin_batch_for(root))
    }

    #[inline]
    fn current_batch_epoch_for(&self, root: DrawRoot) -> u64 {
        self.dyn_cache
            .as_ref()
            .map_or(0, |c| c.current_epoch_for(root))
    }

    /// Compute `ab_glyph::PxScale` matching build-time `bake-font.ts` (`px / unitsPerEm`):
    /// `ab_glyph` scales by `px_scale / font.height_unscaled()`, so multiplying target `em_px`
    /// by `(height_unscaled / units_per_em)` makes runtime CJK glyph height and advance match
    /// baked glyphs 1:1 regardless of font `hhea` ascent/descent metrics!
    #[inline]
    fn fallback_scale(&self, font: &ab_glyph::FontRef<'_>) -> PxScale {
        let density_f = self.raster_density as f32;
        let em_px = (floor_i32((self.line_height as f32) * 0.825 + 0.5).max(1)) as f32;
        let upm = font.units_per_em().unwrap_or(1000.0).max(1.0);
        let h_unscaled = font.height_unscaled().max(1.0);
        PxScale::from(em_px * (h_unscaled / upm) * density_f)
    }

    #[inline]
    fn fallback_advance(&self, font: &ab_glyph::FontRef<'_>, glyph_id: ab_glyph::GlyphId) -> u8 {
        let density_f = self.raster_density as f32;
        let scaled = font.as_scaled(self.fallback_scale(font));
        let adv_f = scaled.h_advance(glyph_id) / density_f;
        floor_i32(adv_f + 0.5).clamp(0, 255) as u8
    }

    /// Read-only logical advance for an unbaked fallback codepoint (`&self`,
    /// zero bitmap or cache mutation).
    fn measure_fallback_advance(&self, cp: u32) -> Option<u8> {
        if self.stream.is_some() {
            return None;
        }
        let cache = self.dyn_cache.as_ref()?;
        if let Some((_, advance, _)) = cache.peek(cp) {
            return Some(advance);
        }
        let font = self.active_fallback_font()?;
        let ch = char::from_u32(cp)?;
        let glyph_id = font.glyph_id(ch);
        if glyph_id.0 == 0 {
            return None;
        }
        Some(self.fallback_advance(&font, glyph_id))
    }

    /// Read-only dynamic glyph lookup/measurement (`&self`, zero bitmap or
    /// cache mutation). If resident in `dyn_cache`, returns the live `gid`;
    /// otherwise returns `(0, advance, xoff)` computed directly from the
    /// fallback font so positions match prepared rasterization identically.
    fn peek_or_measure_dynamic(&self, cp: u32) -> Option<(u16, f32, f32)> {
        if self.stream.is_some() {
            return None;
        }
        let cache = self.dyn_cache.as_ref()?;
        if let Some((slot_idx, advance, xoff)) = cache.peek(cp) {
            return Some((self.baked_count + slot_idx, advance as f32, xoff as f32));
        }
        let font = self.active_fallback_font()?;
        let ch = char::from_u32(cp)?;
        let glyph_id = font.glyph_id(ch);
        if glyph_id.0 == 0 {
            return None;
        }
        let density = self.raster_density as i32;
        let density_f = self.raster_density as f32;
        let scale = self.fallback_scale(&font);
        let advance = self.fallback_advance(&font, glyph_id);
        let baseline_y = (self.baseline as f32) * density_f;
        let xoff_logical = font
            .outline_glyph(glyph_id.with_scale_and_position(scale, ab_glyph::point(0.0, baseline_y)))
            .map_or(0, |og| {
                let min_x = floor_i32(og.px_bounds().min.x);
                if min_x < 0 {
                    ((-min_x + density - 1) / density).min(255) as u8
                } else {
                    0
                }
            });
        Some((0, advance as f32, xoff_logical as f32))
    }

    /// Resolve and rasterize an unbaked codepoint (`cp >= 128`) into a dynamic
    /// tail cell, pinning the cell for `batch_epoch` on the primary output root
    /// so it cannot be evicted before the current draw batch consumes it.
    ///
    /// Returns:
    /// - `Some((gid, advance, xoff))` with `gid >= baked_count` when cached or rasterized;
    /// - `Some((0, advance, 0.0))` when `cp` IS supported by the fallback font
    ///   (preserving its exact measured logical `advance`) but every dynamic cell
    ///   is currently pinned;
    /// - `None` if streaming is active, no dynamic cache/fallback font is
    ///   available, or the fallback font lacks `cp`.
    pub fn prepare_dynamic_glyph(&mut self, cp: u32, batch_epoch: u64) -> Option<(u16, f32, f32)> {
        self.prepare_dynamic_glyph_for(cp, DrawRoot::Primary, batch_epoch)
    }

    /// Output-root-aware variant of [`prepare_dynamic_glyph`](Self::prepare_dynamic_glyph).
    pub fn prepare_dynamic_glyph_for(
        &mut self,
        cp: u32,
        root: DrawRoot,
        batch_epoch: u64,
    ) -> Option<(u16, f32, f32)> {
        if self.stream.is_some() {
            return None;
        }
        if let Some((slot_idx, advance, xoff)) =
            self.dyn_cache.as_mut()?.get_and_pin_for(cp, root, batch_epoch)
        {
            return Some((self.baked_count + slot_idx, advance as f32, xoff as f32));
        }

        let font = self.active_fallback_font()?;
        let ch = char::from_u32(cp)?;
        let glyph_id = font.glyph_id(ch);
        if glyph_id.0 == 0 {
            return None;
        }

        let density = self.raster_density as i32;
        let density_f = self.raster_density as f32;
        let scale = self.fallback_scale(&font);
        let advance = self.fallback_advance(&font, glyph_id);

        let baseline_y = (self.baseline as f32) * density_f;
        let outlined = font.outline_glyph(
            glyph_id.with_scale_and_position(scale, ab_glyph::point(0.0, baseline_y)),
        );

        let cov_w = self.coverage_width() as usize;
        let cov_h = self.coverage_height() as usize;
        let per_glyph = cov_w * cov_h;

        let (min_x, min_y, xoff_logical, shift_x) = if let Some(ref og) = outlined {
            let bounds = og.px_bounds();
            let min_x = floor_i32(bounds.min.x);
            let min_y = floor_i32(bounds.min.y);
            let xoff_logical = if min_x < 0 {
                ((-min_x + density - 1) / density).min(255) as u8
            } else {
                0
            };
            let shift_x = xoff_logical as i32 * density;
            (min_x, min_y, xoff_logical, shift_x)
        } else {
            (0, 0, 0, 0)
        };

        let Some(slot_idx) = self
            .dyn_cache
            .as_mut()?
            .alloc_slot_for(cp, advance, xoff_logical, root, batch_epoch)
        else {
            // Every dynamic cell is pinned: degrade cleanly to tofu (gid 0)
            // while preserving the supported character's measured advance so
            // line widths and alignment match `measure_run` 1:1.
            return Some((0, advance as f32, 0.0));
        };
        let gid = self.baked_count + slot_idx;
        let start = gid as usize * per_glyph;

        let cell = &mut self.bitmap[start..start + per_glyph];
        cell.fill(0);
        if let Some(og) = outlined {
            // Keep every glyph anchored on `baseline_y` and clip overflow
            // cleanly rather than applying per-glyph vertical shifts.
            og.draw(|gx, gy, cov| {
                let px = min_x + shift_x + gx as i32;
                let py = min_y + gy as i32;
                if px >= 0 && px < cov_w as i32 && py >= 0 && py < cov_h as i32 {
                    let a = floor_i32(cov.clamp(0.0, 1.0) * 255.0 + 0.5).clamp(0, 255) as u8;
                    let idx = (py as usize) * cov_w + (px as usize);
                    if a > cell[idx] {
                        cell[idx] = a;
                    }
                }
            });
        }
        self.dyn_revision = self.dyn_revision.wrapping_add(1);

        Some((gid, advance as f32, xoff_logical as f32))
    }

    pub(crate) fn prepare_dynamic_glyph_current_batch(
        &mut self,
        cp: u32,
        root: DrawRoot,
    ) -> Option<(u16, f32, f32)> {
        let epoch = self.current_batch_epoch_for(root);
        self.prepare_dynamic_glyph_for(cp, root, epoch)
    }

    /// GPU cells omit transparent right-hand archive padding. Source coverage
    /// retains its fixed row stride; this width includes every resident ink pixel.
    pub fn texture_coverage_width(&self) -> u32 {
        self.texture_cell_w * self.raster_density as u32
    }

    /// Binary-search the cmap. `None` = unmapped codepoint (caller decides
    /// whether that bumps the miss counter).
    pub fn lookup(&self, codepoint: u32) -> Option<(u16, u8)> {
        self.lookup_entry(codepoint).map(|e| (e.gid, e.advance))
    }

    /// Full cmap entry for a codepoint (gid + advance + xoff).
    pub fn lookup_entry(&self, codepoint: u32) -> Option<&CmapEntry> {
        self.cmap
            .binary_search_by(|e| e.codepoint.cmp(&codepoint))
            .ok()
            .map(|i| &self.cmap[i])
    }

    #[inline]
    pub fn bytes_per_row(&self) -> usize {
        self.coverage_width() as usize
    }

    #[inline]
    pub fn coverage_width(&self) -> u32 {
        self.cell_w * self.raster_density as u32
    }

    #[inline]
    pub fn coverage_height(&self) -> u32 {
        self.cell_h * self.raster_density as u32
    }

    /// The density-scaled coverage bytes of one glyph (top row first).
    pub fn glyph_rows(&self, gid: u16) -> &[u8] {
        let per_glyph = self.coverage_height() as usize * self.bytes_per_row();
        let start = gid as usize * per_glyph;
        &self.bitmap_slice()[start..start + per_glyph]
    }

    /// Average one logical pixel's density×density coverage samples. This is
    /// the reference reduction for logical-resolution software/CPU fallback
    /// renderers; density 1 returns the original byte exactly.
    pub fn logical_coverage(&self, gid: u16, x: u32, y: u32) -> u8 {
        if gid >= self.glyph_count || x >= self.cell_w || y >= self.cell_h {
            return 0;
        }
        let density = self.raster_density as usize;
        let rows = self.glyph_rows(gid);
        let bpr = self.bytes_per_row();
        let x0 = x as usize * density;
        let y0 = y as usize * density;
        let mut sum = 0u32;
        for sample_y in 0..density {
            let row = (y0 + sample_y) * bpr;
            for sample_x in 0..density {
                sum += rows[row + x0 + sample_x] as u32;
            }
        }
        let samples = (density * density) as u32;
        ((sum + samples / 2) / samples) as u8
    }
}

/// A placed glyph from inline-run layout: cell top-left relative to the box
/// origin.
#[derive(Clone, Copy, Debug)]
pub struct GlyphPos {
    pub gid: u16,
    pub codepoint: u32,
    pub x: f32,
    pub y: f32,
}

/// A host-installed native text measurer: `(text, slot, tracking,
/// line_h_override) -> (max line width, total height)` in logical px, with the
/// same `'\n'`-only line-break contract as [`Fonts::measure_run`]
/// (`line_h_override` NAN = the measurer's default for the slot). Installed by
/// native-text backends (docs/BACKENDS.md) through `Ui::set_text_measure`
/// before the guest mounts; fixed-function hosts never install one.
pub type MeasureFn = alloc::boxed::Box<dyn Fn(&str, u8, f32, f32) -> (f32, f32)>;

/// A host-installed native line wrapper: `(text, slot, max_w) -> soft-break
/// columns` (ascending, in UTF-16 code units — the guest slices JS strings
/// with them). Installed by native-text backends through `Ui::set_text_wrap`
/// next to the measurer, so break positions and measured advances always
/// come from the same provider; without one, `wrap_text` computes greedy
/// breaks over whatever provider `measure_run` resolves to.
pub type WrapFn = alloc::boxed::Box<dyn Fn(&str, u8, f32) -> alloc::vec::Vec<u32>>;

/// The per-core atlas registry.
pub struct Fonts {
    slots: [Option<Atlas>; spec::MAX_FONT_SLOTS],
    /// cmap-miss counter (Cell: measurement is `&self` per the pinned `Ui`
    /// signature but a miss must still count).
    pub misses: Cell<u32>,
    /// Native measurer; when present, tracking-0 runs measure through it
    /// (and draw.rs emits TEXT_RUN instead of GLYPH_RUN for them). Tracked
    /// runs keep the baked path on BOTH sides so a node's measured metrics
    /// always match its painted glyphs.
    native: Option<MeasureFn>,
    /// Native line wrapper (OP wrapText); absent = greedy over `measure_run`.
    wrap_native: Option<WrapFn>,
}

impl Default for Fonts {
    fn default() -> Self {
        Self::new()
    }
}

impl Fonts {
    /// Total dynamic fallback RAM (bitmap cells + LRU metadata) reserved across
    /// all currently loaded slots.
    pub fn dynamic_ram_bytes(&self) -> usize {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .map(Atlas::dynamic_ram_bytes)
            .sum()
    }

    pub(crate) fn dynamic_ram_bytes_except(&self, skip_slot: usize) -> usize {
        self.slots
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != skip_slot)
            .filter_map(|(_, s)| s.as_ref())
            .map(Atlas::dynamic_ram_bytes)
            .sum()
    }

    pub(crate) fn remaining_dynamic_budget_for(&self, slot: usize) -> usize {
        DYN_TOTAL_BUDGET_BYTES
            .saturating_sub(self.dynamic_ram_bytes_except(slot))
            .min(DYN_SLOT_BUDGET_BYTES)
    }

    pub(crate) fn total_dynamic_revision(&self) -> u64 {
        self.slots
            .iter()
            .filter_map(|s| s.as_ref())
            .fold(0u64, |acc, a| acc.wrapping_add(a.dynamic_revision()))
    }

    /// Advance the primary batch pinning epoch on every loaded atlas.
    pub fn begin_draw_batch(&mut self) {
        self.begin_draw_batch_for(DrawRoot::Primary);
    }

    /// Advance the batch pinning epoch for `root` on every loaded atlas while
    /// keeping the other output root's active pins intact.
    pub fn begin_draw_batch_for(&mut self, root: DrawRoot) {
        for atlas in self.slots.iter_mut().flatten() {
            atlas.begin_batch_for(root);
        }
    }

    pub(crate) fn merge_atlases(&mut self, staged: &mut Fonts) {
        let mut merged = [false; spec::MAX_FONT_SLOTS];
        for (slot, (destination, source)) in
            self.slots.iter_mut().zip(staged.slots.iter_mut()).enumerate()
        {
            if source.is_some() {
                *destination = source.take();
                merged[slot] = true;
            }
        }
        // Enforce the shared `DYN_TOTAL_BUDGET_BYTES` cap on actual allocated
        // `Vec` capacities across the merged atlas table.
        let mut total = self.dynamic_ram_bytes();
        if total > DYN_TOTAL_BUDGET_BYTES {
            for slot in (0..spec::MAX_FONT_SLOTS).rev() {
                if total <= DYN_TOTAL_BUDGET_BYTES {
                    break;
                }
                if !merged[slot] {
                    continue;
                }
                if let Some(atlas) = self.slots[slot].as_mut() {
                    let current = atlas.dynamic_ram_bytes();
                    if current == 0 {
                        continue;
                    }
                    let excess = total - DYN_TOTAL_BUDGET_BYTES;
                    let allowed = current.saturating_sub(excess);
                    atlas.trim_dynamic_budget(allowed);
                    total = self.dynamic_ram_bytes();
                }
            }
        }
    }

    pub fn new() -> Fonts {
        Fonts {
            slots: Default::default(),
            misses: Cell::new(0),
            native: None,
            wrap_native: None,
        }
    }

    /// Install (or clear) the native measurer. Callers relayout afterwards —
    /// every text leaf's metrics change provider.
    pub fn set_native_measure(&mut self, f: Option<MeasureFn>) {
        self.native = f;
    }

    /// Install (or clear) the native line wrapper (OP wrapText).
    pub fn set_native_wrap(&mut self, f: Option<WrapFn>) {
        self.wrap_native = f;
    }

    /// True when a native measurer is installed.
    #[inline]
    pub fn native_active(&self) -> bool {
        self.native.is_some()
    }

    /// Parse + register an atlas at the slot in its header, respecting the
    /// shared [`DYN_TOTAL_BUDGET_BYTES`] dynamic fallback RAM budget.
    pub fn load(&mut self, bytes: &[u8]) -> bool {
        let Some(&slot_byte) = bytes.get(12) else {
            return false;
        };
        let slot = slot_byte as usize;
        if slot >= spec::MAX_FONT_SLOTS {
            return false;
        }
        let budget = self.remaining_dynamic_budget_for(slot);
        match Atlas::parse_with_budget(bytes, budget) {
            Some(a) => {
                self.slots[slot] = Some(a);
                true
            }
            None => false,
        }
    }

    #[cfg(test)]
    pub(crate) fn load_with_fallback(
        &mut self,
        bytes: &[u8],
        font: ab_glyph::FontRef<'static>,
    ) -> bool {
        let Some(&slot_byte) = bytes.get(12) else {
            return false;
        };
        let slot = slot_byte as usize;
        if slot >= spec::MAX_FONT_SLOTS {
            return false;
        }
        let budget = self.remaining_dynamic_budget_for(slot);
        match Atlas::parse_with_fallback_budget(bytes, font, budget) {
            Some(a) => {
                self.slots[slot] = Some(a);
                true
            }
            None => false,
        }
    }

    #[inline]
    pub fn atlas(&self, slot: u8) -> Option<&Atlas> {
        self.slots.get(slot as usize)?.as_ref()
    }

    pub(crate) fn atlas_mut(&mut self, slot: u8) -> Option<&mut Atlas> {
        self.slots.get_mut(slot as usize)?.as_mut()
    }

    /// Prepare and pin all dynamic fallback glyphs needed for `text` in `slot`
    /// under a fresh batch epoch (`&mut self`; zero aliasing with `bitmap_slice`).
    /// Returns `true` if every fallback-supported glyph fit in the batch.
    pub fn prepare_run(&mut self, text: &str, slot: u8) -> bool {
        let Some(atlas) = self.atlas_mut(slot) else {
            return false;
        };
        if !atlas.has_dynamic_cache() {
            return true;
        }
        let epoch = atlas.begin_batch();
        let mut all_fit = true;
        for ch in text.chars() {
            let cp = ch as u32;
            if cp >= 128 && atlas.lookup_entry(cp).is_none() {
                if let Some((0, _, _)) = atlas.prepare_dynamic_glyph(cp, epoch) {
                    all_fit = false;
                }
            }
        }
        all_fit
    }

    /// If `cp` is not baked in `slot`, prepare/pin it in `root`'s current draw
    /// batch and return its resolved `gid` (`Some(0)` + miss bump on miss or
    /// batch capacity exhaustion). Returns `None` if `cp` is already baked.
    pub(crate) fn prepare_dynamic_glyph_if_unbaked(
        &mut self,
        slot: u8,
        cp: u32,
        root: DrawRoot,
    ) -> Option<u16> {
        let atlas = self.atlas_mut(slot)?;
        if atlas.lookup_entry(cp).is_some() {
            return None;
        }
        if let Some((gid, _, _)) = atlas.prepare_dynamic_glyph_current_batch(cp, root) {
            if gid == 0 {
                self.misses.set(self.misses.get().wrapping_add(1));
            }
            return Some(gid);
        }
        self.misses.set(self.misses.get().wrapping_add(1));
        Some(0)
    }

    /// Read-only logical advance for a codepoint (`&self`; never mutates bitmap
    /// or LRU state).
    fn glyph_advance(&self, atlas: &Atlas, cp: u32) -> f32 {
        if let Some(e) = atlas.lookup_entry(cp) {
            return e.advance as f32;
        }
        if cp >= 128 {
            if let Some(adv) = atlas.measure_fallback_advance(cp) {
                return adv as f32;
            }
        }
        self.misses.set(self.misses.get().wrapping_add(1));
        atlas
            .stream
            .as_ref()
            .map_or(atlas.cell_w as f32, |s| s.advance as f32)
    }

    /// Read-only `(gid, advance, xoff, used_dynamic)` for a codepoint (`&self`;
    /// never mutates bitmap or LRU state). Uncached fallback glyphs return
    /// `gid = 0` with accurate logical `advance` and `xoff` (and `used_dynamic = true`).
    fn glyph_readonly(&self, atlas: &Atlas, cp: u32) -> (u16, f32, f32, bool) {
        if let Some(e) = atlas.lookup_entry(cp) {
            return (e.gid, e.advance as f32, e.xoff as f32, false);
        }
        if cp >= 128 {
            if let Some((gid, adv, xoff)) = atlas.peek_or_measure_dynamic(cp) {
                return (gid, adv, xoff, true);
            }
        }
        self.misses.set(self.misses.get().wrapping_add(1));
        (
            0,
            atlas
                .stream
                .as_ref()
                .map_or(atlas.cell_w as f32, |s| s.advance as f32),
            0.0,
            false,
        )
    }

    /// Measure a run: (max line width, line count x line height). Empty text
    /// or an unregistered slot measures (0, 0). With a native measurer
    /// installed, tracking-0 runs route to it — the auto-gate the JS-facing
    /// `measureText` op uses. Layout does NOT call this: it picks a provider
    /// per node and records it (`measure_run_provider`; layout.rs build()).
    pub fn measure_run(
        &self,
        text: &str,
        slot: u8,
        tracking: f32,
        line_h_override: f32,
    ) -> (f32, f32) {
        self.measure_run_provider(
            self.native.is_some() && tracking == 0.0,
            text,
            slot,
            tracking,
            line_h_override,
        )
    }

    /// Measure with an EXPLICIT provider choice. `native: true` requires an
    /// installed measurer (falls back to the atlas without one); layout
    /// records the choice on the node so paint always uses the provider
    /// that sized the box (docs/BACKENDS.md).
    pub fn measure_run_provider(
        &self,
        native: bool,
        text: &str,
        slot: u8,
        tracking: f32,
        line_h_override: f32,
    ) -> (f32, f32) {
        if text.is_empty() {
            return (0.0, 0.0);
        }
        if native {
            if let Some(f) = &self.native {
                return f(text, slot, tracking, line_h_override);
            }
        }
        let Some(atlas) = self.atlas(slot) else {
            return (0.0, 0.0);
        };
        let lh = if line_h_override.is_nan() {
            atlas.line_height as f32
        } else {
            line_h_override
        };
        let mut max_w = 0.0f32;
        let mut line_w = 0.0f32;
        let mut lines = 1u32;
        for ch in text.chars() {
            if ch == '\n' {
                max_w = max_w.max(line_w);
                line_w = 0.0;
                lines += 1;
                continue;
            }
            let adv = self.glyph_advance(atlas, ch as u32);
            line_w += adv + tracking;
        }
        max_w = max_w.max(line_w);
        (max_w, lines as f32 * lh)
    }

    /// Soft-wrap break columns for ONE line of text under `max_w` px
    /// (ascending, UTF-16 code units; empty = the line fits). With a native
    /// wrapper installed it decides; otherwise greedy word wrap over
    /// whatever provider `measure_run` resolves to (atlas advances, or the
    /// native measurer for tracking-0 native apps) — break positions always
    /// derive from the metrics that size and paint the text.
    ///
    /// Greedy rules (pinned by the JS-fallback parity test): break BEFORE
    /// the word that overflows; space runs never break — they hang past
    /// `max_w` on the row they follow (classic Notepad); a word wider than a
    /// whole row splits at character level.
    pub fn wrap_text(&self, text: &str, slot: u8, max_w: f32) -> Vec<u32> {
        if let Some(f) = &self.wrap_native {
            return f(text, slot, max_w);
        }
        self.wrap_greedy(text, slot, max_w)
    }

    fn wrap_greedy(&self, text: &str, slot: u8, max_w: f32) -> Vec<u32> {
        let mut breaks = Vec::new();
        if text.is_empty() || max_w.is_nan() || max_w <= 0.0 {
            return breaks;
        }
        let width = |a: usize, b: usize| self.measure_run(&text[a..b], slot, 0.0, f32::NAN).0;
        if width(0, text.len()) <= max_w {
            return breaks;
        }
        // Per-char byte offsets + running UTF-16 columns (the guest slices
        // JS strings, whose indices are UTF-16 code units).
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        let n = chars.len();
        let mut u16_at = Vec::with_capacity(n + 1);
        let mut acc = 0u32;
        for &(_, c) in &chars {
            u16_at.push(acc);
            acc += c.len_utf16() as u32;
        }
        u16_at.push(acc);
        let byte_at = |ci: usize| if ci < n { chars[ci].0 } else { text.len() };
        let w = |a: usize, b: usize| width(byte_at(a), byte_at(b));

        let mut seg_from = 0usize; // char index of the current visual row start
        let mut x = 0f32; // committed row width (hanging spaces included)
        let mut i = 0usize;
        while i < n {
            if chars[i].1 == ' ' {
                let mut j = i;
                while j < n && chars[j].1 == ' ' {
                    j += 1;
                }
                x += w(i, j);
                i = j;
                continue;
            }
            let mut j = i;
            while j < n && chars[j].1 != ' ' {
                j += 1;
            }
            let word_w = w(i, j);
            if i > seg_from && x + word_w > max_w {
                breaks.push(u16_at[i]);
                seg_from = i;
                x = 0.0;
            }
            if word_w > max_w {
                // A word wider than a whole row: hard character chunks.
                let mut cw = 0f32;
                for k in i..j {
                    let ch_w = w(k, k + 1);
                    if k > seg_from && cw + ch_w > max_w {
                        breaks.push(u16_at[k]);
                        seg_from = k;
                        cw = 0.0;
                    }
                    cw += ch_w;
                }
                x = cw;
                i = j;
                continue;
            }
            x += word_w;
            i = j;
        }
        breaks
    }

    /// Inline-run layout (read-only): place every glyph (cell top-left, relative
    /// to the box origin) honoring text-align within `box_w` and per-line
    /// vertical centering of the glyph cell inside the line box.
    ///
    /// Never mutates atlas bitmaps or LRU cache state. Call [`prepare_run`] or
    /// [`layout_run_mut`] beforehand to rasterize uncached dynamic fallback
    /// glyphs into `atlas.bitmap`.
    pub fn layout_run(
        &self,
        text: &str,
        slot: u8,
        tracking: f32,
        line_h_override: f32,
        align: u8,
        box_w: f32,
        out: &mut Vec<GlyphPos>,
    ) {
        let _ = self.layout_run_readonly(text, slot, tracking, line_h_override, align, box_w, out);
    }

    /// Read-only inline-run layout that also reports whether any character
    /// resolved via dynamic fallback rather than a baked cmap entry.
    pub(crate) fn layout_run_readonly(
        &self,
        text: &str,
        slot: u8,
        tracking: f32,
        line_h_override: f32,
        align: u8,
        box_w: f32,
        out: &mut Vec<GlyphPos>,
    ) -> bool {
        let Some(atlas) = self.atlas(slot) else {
            return false;
        };
        if text.is_empty() {
            return false;
        }
        let lh = if line_h_override.is_nan() {
            atlas.line_height as f32
        } else {
            line_h_override
        };
        let cell_h = atlas.cell_h as f32;
        let mut line_top = 0.0f32;
        let mut used_dynamic = false;
        for line in text.split('\n') {
            let line_start = out.len();
            let mut pen = 0.0f32;
            let y = line_top + (lh - cell_h) * 0.5;
            for ch in line.chars() {
                let (gid, adv, xoff, is_dyn) = self.glyph_readonly(atlas, ch as u32);
                used_dynamic |= is_dyn;
                out.push(GlyphPos {
                    gid,
                    codepoint: ch as u32,
                    x: pen - xoff,
                    y,
                });
                pen += adv + tracking;
            }
            let offset = match align {
                a if a == spec::TextAlign::Center as u8 => (box_w - pen) * 0.5,
                a if a == spec::TextAlign::Right as u8 => box_w - pen,
                _ => 0.0,
            };
            if offset != 0.0 {
                for g in &mut out[line_start..] {
                    g.x += offset;
                }
            }
            line_top += lh;
        }
        used_dynamic
    }

    /// Mutable inline-run layout: starts a fresh batch epoch on `slot`,
    /// rasterizes and pins unbaked fallback glyphs under `&mut self` (so earlier
    /// placements in `out` are never overwritten), and places every glyph.
    #[allow(clippy::too_many_arguments)]
    pub fn layout_run_mut(
        &mut self,
        text: &str,
        slot: u8,
        tracking: f32,
        line_h_override: f32,
        align: u8,
        box_w: f32,
        out: &mut Vec<GlyphPos>,
    ) {
        let Some(atlas) = self.slots.get_mut(slot as usize).and_then(|s| s.as_mut()) else {
            return;
        };
        if text.is_empty() {
            return;
        }
        let epoch = atlas.begin_batch();
        let lh = if line_h_override.is_nan() {
            atlas.line_height as f32
        } else {
            line_h_override
        };
        let cell_h = atlas.cell_h as f32;
        let fallback_tofu_adv = atlas
            .stream
            .as_ref()
            .map_or(atlas.cell_w as f32, |s| s.advance as f32);
        let mut line_top = 0.0f32;
        for line in text.split('\n') {
            let line_start = out.len();
            let mut pen = 0.0f32;
            let y = line_top + (lh - cell_h) * 0.5;
            for ch in line.chars() {
                let cp = ch as u32;
                let (gid, adv, xoff) = if let Some(e) = atlas.lookup_entry(cp) {
                    (e.gid, e.advance as f32, e.xoff as f32)
                } else if cp >= 128 {
                    if let Some((gid, adv, xoff)) = atlas.prepare_dynamic_glyph(cp, epoch) {
                        if gid == 0 {
                            self.misses.set(self.misses.get().wrapping_add(1));
                        }
                        (gid, adv, xoff)
                    } else {
                        self.misses.set(self.misses.get().wrapping_add(1));
                        (0, fallback_tofu_adv, 0.0)
                    }
                } else {
                    self.misses.set(self.misses.get().wrapping_add(1));
                    (0, fallback_tofu_adv, 0.0)
                };
                out.push(GlyphPos {
                    gid,
                    codepoint: cp,
                    x: pen - xoff,
                    y,
                });
                pen += adv + tracking;
            }
            let offset = match align {
                a if a == spec::TextAlign::Center as u8 => (box_w - pen) * 0.5,
                a if a == spec::TextAlign::Right as u8 => box_w - pen,
                _ => 0.0,
            };
            if offset != 0.0 {
                for g in &mut out[line_start..] {
                    g.x += offset;
                }
            }
            line_top += lh;
        }
    }
}

#[cfg(test)]
mod cjk_fallback_tests {
    use super::*;
    use alloc::collections::BTreeSet;

    fn build_compact_atlas(slot: u8, cell_w: u8, cell_h: u8, baseline: u8, line_height: u8) -> Vec<u8> {
        use spec::font_atlas as fa;
        let glyphs: &[(u32, u16, u8)] = &[(65, 1, 7), (0xfffd, 0, cell_w)];
        let count = glyphs.len() as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&fa::MAGIC.to_le_bytes());
        out.extend_from_slice(&fa::VERSION.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.push(cell_w);
        out.push(cell_h);
        out.push(baseline);
        out.push(line_height);
        out.push(slot);
        out.push(0); // flags
        out.push(1); // raster_density
        out.push(0); // reserved
        for &(cp, gid, adv) in glyphs {
            out.extend_from_slice(&cp.to_le_bytes());
            out.extend_from_slice(&gid.to_le_bytes());
            out.push(adv);
            out.push(0);
        }
        out.extend_from_slice(&vec![0u8; count as usize * cell_w as usize * cell_h as usize]);
        out
    }

    #[test]
    fn dynamic_cjk_fallback_measures_rasterizes_and_caches_chinese() {
        let ttf_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../app/fonts/DroidSansFallbackFull.ttf");
        let ttf_bytes: &'static [u8] =
            Box::leak(std::fs::read(&ttf_path).expect("DroidSansFallbackFull.ttf must exist").into_boxed_slice());
        let font_ref = ab_glyph::FontRef::try_from_slice_and_index(ttf_bytes, 0)
            .expect("valid DroidSansFallbackFull.ttf");

        let blob = build_compact_atlas(0, 17, 15, 12, 15);
        let atlas = Atlas::parse_with_fallback(&blob, font_ref).expect("atlas parse");
        assert_eq!(atlas.baked_count, 2);
        assert!(atlas.dyn_cap() > 0 && atlas.dyn_cap() <= DYN_CAP);
        assert_eq!(atlas.glyph_count, 2 + atlas.dyn_cap() as u16);
        assert!(atlas.dynamic_ram_bytes() <= DYN_SLOT_BUDGET_BYTES);

        let mut fonts = Fonts::new();
        fonts.slots[0] = Some(atlas);

        let sample = "你好世界，极致省内存！";
        // Safe `&self` measurement while holding a live `bitmap_slice()` borrow:
        // zero interior mutation, zero UB, accurate fallback width.
        let (w, h) = {
            let live_slice = fonts.atlas(0).unwrap().bitmap_slice();
            let before_rev = fonts.atlas(0).unwrap().dynamic_revision();
            let res = fonts.measure_run(sample, 0, 0.0, f32::NAN);
            assert_eq!(fonts.atlas(0).unwrap().dynamic_revision(), before_rev);
            assert!(live_slice.iter().all(|&b| b == 0));
            res
        };
        assert!(w > 50.0, "expected non-zero measured width, got {w}");
        assert_eq!(h, 15.0);
        assert_eq!(fonts.misses.get(), 0, "all sample chars should resolve via fallback");

        let mut placed = Vec::new();
        fonts.layout_run_mut(sample, 0, 0.0, f32::NAN, spec::TextAlign::Left as u8, 320.0, &mut placed);
        assert_eq!(placed.len(), sample.chars().count());

        let atlas = fonts.atlas(0).unwrap();
        assert!(atlas.dynamic_revision() >= sample.chars().count() as u64);
        let mut distinct_gids = BTreeSet::new();
        for g in &placed {
            assert!(
                g.gid >= atlas.baked_count && g.gid < atlas.glyph_count,
                "expected dynamic gid >= {}, got {}",
                atlas.baked_count,
                g.gid
            );
            distinct_gids.insert(g.gid);
            let rows = atlas.glyph_rows(g.gid);
            let ink_pixels = rows.iter().filter(|&&a| a > 0).count();
            assert!(
                ink_pixels > 0,
                "expected non-zero alpha pixels for U+{:04X} (gid {})",
                g.codepoint,
                g.gid
            );
        }
        assert_eq!(distinct_gids.len(), sample.chars().count());

        // Second read-only pass hits the LRU cache and returns identical gids & positions.
        let mut placed_again = Vec::new();
        fonts.layout_run(sample, 0, 0.0, f32::NAN, spec::TextAlign::Left as u8, 320.0, &mut placed_again);
        for (a, b) in placed.iter().zip(placed_again.iter()) {
            assert_eq!(a.gid, b.gid);
            assert_eq!(a.x, b.x);
        }
    }

    #[test]
    fn dynamic_lru_evicts_oldest_and_keeps_hash_table_consistent() {
        let mut cache = DynLruCache::new(DYN_CAP);
        for i in 0..(DYN_CAP as u32 + 120) {
            let cp = 0x4E00 + i;
            assert!(cache.peek(cp).is_none());
            // Unpinned (`batch_epoch == 0`) allows LRU eviction across steps.
            let slot = cache.alloc_slot(cp, 12, 0, 0).expect("unpinned slot");
            assert!((slot as usize) < DYN_CAP);
            assert_eq!(cache.get_and_pin(cp, 0).map(|(s, _, _)| s), Some(slot));
        }
        // Oldest 120 entries were evicted; most recent DYN_CAP entries remain present.
        for i in 0..120u32 {
            assert!(cache.peek(0x4E00 + i).is_none());
        }
        for i in 120..(DYN_CAP as u32 + 120) {
            assert!(cache.peek(0x4E00 + i).is_some());
        }
    }

    #[test]
    fn dynamic_lru_batch_pinning_blocks_intra_batch_eviction() {
        let mut cache = DynLruCache::new(8);
        let epoch1 = cache.begin_batch();
        for i in 0..8u32 {
            assert!(cache.alloc_slot(0x4E00 + i, 12, 0, epoch1).is_some());
        }
        // 9th distinct glyph in the same batch MUST NOT evict any pinned entry.
        assert!(cache.alloc_slot(0x4E08, 12, 0, epoch1).is_none());
        for i in 0..8u32 {
            assert!(cache.peek(0x4E00 + i).is_some());
        }
        // Next batch unpins earlier entries so LRU eviction resumes.
        let epoch2 = cache.begin_batch();
        assert!(cache.alloc_slot(0x4E08, 12, 0, epoch2).is_some());
        assert!(cache.peek(0x4E00).is_none());
        assert!(cache.peek(0x4E08).is_some());
    }

    #[test]
    fn non_compact_slot_does_not_allocate_dynamic_tail() {
        let ttf_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../app/fonts/DroidSansFallbackFull.ttf");
        let ttf_bytes: &'static [u8] =
            Box::leak(std::fs::read(&ttf_path).expect("DroidSansFallbackFull.ttf must exist").into_boxed_slice());
        let font_ref = ab_glyph::FontRef::try_from_slice_and_index(ttf_bytes, 0).unwrap();

        let blob = build_compact_atlas(6, 36, 40, 32, 42);
        let atlas = Atlas::parse_with_fallback(&blob, font_ref).expect("atlas parse");
        assert_eq!(atlas.baked_count, 2);
        assert_eq!(atlas.glyph_count, 2);
        assert!(atlas.dyn_cache.is_none());
    }

    fn build_compact_atlas_density(
        slot: u8,
        cell_w: u8,
        cell_h: u8,
        baseline: u8,
        line_height: u8,
        density: u8,
    ) -> Vec<u8> {
        use spec::font_atlas as fa;
        let glyphs: &[(u32, u16, u8)] = &[(65, 1, 7), (0xfffd, 0, cell_w)];
        let count = glyphs.len() as u16;
        let mut out = Vec::new();
        out.extend_from_slice(&fa::MAGIC.to_le_bytes());
        out.extend_from_slice(&fa::VERSION.to_le_bytes());
        out.extend_from_slice(&count.to_le_bytes());
        out.push(cell_w);
        out.push(cell_h);
        out.push(baseline);
        out.push(line_height);
        out.push(slot);
        out.push(0); // flags
        out.push(density);
        out.push(0); // reserved
        for &(cp, gid, adv) in glyphs {
            out.extend_from_slice(&cp.to_le_bytes());
            out.extend_from_slice(&gid.to_le_bytes());
            out.push(adv);
            out.push(0);
        }
        let per_glyph = (cell_w as usize * density as usize) * (cell_h as usize * density as usize);
        out.extend_from_slice(&vec![0u8; count as usize * per_glyph]);
        out
    }

    fn load_test_fallback_font() -> ab_glyph::FontRef<'static> {
        let ttf_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../app/fonts/DroidSansFallbackFull.ttf");
        let ttf_bytes: &'static [u8] = Box::leak(
            std::fs::read(&ttf_path)
                .expect("DroidSansFallbackFull.ttf must exist")
                .into_boxed_slice(),
        );
        ab_glyph::FontRef::try_from_slice_and_index(ttf_bytes, 0).unwrap()
    }

    #[test]
    fn density_two_and_multi_slot_stay_within_dynamic_ram_budget() {
        let font_ref = load_test_fallback_font();

        // Single 17x16 density=2 compact atlas must respect per-slot 72 KiB budget.
        let blob_d2 = build_compact_atlas_density(0, 17, 16, 13, 16, 2);
        let atlas_d2 = Atlas::parse_with_fallback(&blob_d2, font_ref.clone()).expect("d2 parse");
        assert!(atlas_d2.dyn_cap() > 0);
        assert!(atlas_d2.dyn_cap() < DYN_CAP);
        assert!(
            atlas_d2.dynamic_ram_bytes() <= DYN_SLOT_BUDGET_BYTES,
            "density=2 dynamic RAM {} exceeded slot cap {}",
            atlas_d2.dynamic_ram_bytes(),
            DYN_SLOT_BUDGET_BYTES
        );

        // Loading all 8 compact slots into Fonts must stay <= 360 KiB combined.
        let mut fonts = Fonts::new();
        for slot in 0..spec::MAX_FONT_SLOTS as u8 {
            let blob = build_compact_atlas(slot, 17, 15, 12, 15);
            assert!(fonts.load_with_fallback(&blob, font_ref.clone()));
        }
        assert!(
            fonts.dynamic_ram_bytes() <= DYN_TOTAL_BUDGET_BYTES,
            "total dynamic RAM {} exceeded {}",
            fonts.dynamic_ram_bytes(),
            DYN_TOTAL_BUDGET_BYTES
        );

        // Merging 4 existing compact slots with 4 staged compact slots must stay
        // <= 360 KiB on ACTUAL allocated `Vec::capacity()` (bitmap + LRU vectors).
        let mut base = Fonts::new();
        for slot in 0..4u8 {
            assert!(base.load_with_fallback(&build_compact_atlas(slot, 17, 15, 12, 15), font_ref.clone()));
        }
        let mut staged = Fonts::new();
        for slot in 4..spec::MAX_FONT_SLOTS as u8 {
            assert!(staged.load_with_fallback(&build_compact_atlas(slot, 17, 15, 12, 15), font_ref.clone()));
        }
        base.merge_atlases(&mut staged);
        assert!(
            base.dynamic_ram_bytes() <= DYN_TOTAL_BUDGET_BYTES,
            "merged dynamic RAM {} exceeded {}",
            base.dynamic_ram_bytes(),
            DYN_TOTAL_BUDGET_BYTES
        );
        // Verify exact raw Vec capacities across every slot (including disabled
        // and partially trimmed slots) match `dynamic_ram_bytes()` and stay <= 360 KiB.
        let mut raw_cap_total = 0usize;
        let mut saw_disabled = false;
        for slot in 0..spec::MAX_FONT_SLOTS as u8 {
            let a = base.atlas(slot).unwrap();
            let baked_bytes = a.baked_count as usize * a.per_glyph_bytes();
            let bitmap_extra = a.bitmap.capacity().saturating_sub(baked_bytes);
            let meta_cap = a.dyn_cache.as_ref().map_or(0, |c| {
                c.entries.capacity() * core::mem::size_of::<DynSlot>()
                    + c.table.capacity() * core::mem::size_of::<u16>()
            });
            assert_eq!(a.dynamic_ram_bytes(), bitmap_extra + meta_cap);
            if a.dyn_cap() == 0 {
                saw_disabled = true;
                assert_eq!(
                    a.bitmap.capacity(),
                    baked_bytes,
                    "disabled slot {slot} must release excess dynamic bitmap capacity"
                );
            }
            raw_cap_total += bitmap_extra + meta_cap;
        }
        assert!(saw_disabled, "8x72KiB merge must disable overflow slots");
        assert!(
            raw_cap_total <= DYN_TOTAL_BUDGET_BYTES,
            "actual merged heap capacity {raw_cap_total} exceeded {DYN_TOTAL_BUDGET_BYTES}"
        );

        // Partial trim case: base uses ~340 KiB, staged adds 1 full 72 KiB slot
        // which must be partially trimmed AND release both bitmap and metadata capacity.
        let mut partial_base = Fonts::new();
        for slot in 0..4u8 {
            assert!(partial_base.load_with_fallback(
                &build_compact_atlas(slot, 17, 15, 12, 15),
                font_ref.clone()
            ));
        }
        let slot4_blob = build_compact_atlas(4, 17, 15, 12, 15);
        partial_base.slots[4] = Some(
            Atlas::parse_with_fallback_budget(&slot4_blob, font_ref.clone(), 40 * 1024).unwrap(),
        );
        let mut partial_staged = Fonts::new();
        assert!(partial_staged.load_with_fallback(
            &build_compact_atlas(5, 17, 15, 12, 15),
            font_ref.clone()
        ));
        let pre_trim_cap = partial_staged.atlas(5).unwrap().bitmap.capacity();
        let pre_trim_entries_cap = partial_staged.atlas(5).unwrap().dyn_cache.as_ref().unwrap().entries.capacity();
        partial_base.merge_atlases(&mut partial_staged);
        let trimmed = partial_base.atlas(5).unwrap();
        assert!(trimmed.dyn_cap() > 0, "slot 5 should be partially trimmed, not disabled");
        assert!(trimmed.bitmap.capacity() < pre_trim_cap);
        assert!(trimmed.dyn_cache.as_ref().unwrap().entries.capacity() < pre_trim_entries_cap);
        assert!(partial_base.dynamic_ram_bytes() <= DYN_TOTAL_BUDGET_BYTES);
    }

    #[test]
    fn layout_run_mut_preserves_measured_advance_and_alignment_when_batch_fills() {
        let font_ref = load_test_fallback_font();
        // Narrow cell_w = 6 with line_height = 15 so wide CJK advances (> 6)
        // differ markedly from cell_w. Small budget gives a small `dyn_cap`.
        let blob = build_compact_atlas(0, 6, 15, 12, 15);
        let atlas = Atlas::parse_with_fallback_budget(&blob, font_ref.clone(), 2048).unwrap();
        let dyn_cap = atlas.dyn_cap();
        assert!(dyn_cap >= 2 && dyn_cap < 32, "expected small dyn_cap, got {dyn_cap}");

        let mut fonts = Fonts::new();
        fonts.slots[0] = Some(atlas);

        // Build a line with `dyn_cap + 3` distinct wide CJK characters followed by 'A'.
        let mut sample = alloc::string::String::new();
        let mut count = 0usize;
        for cp in 0x4E00u32..0x9FFFu32 {
            let ch = char::from_u32(cp).unwrap();
            if font_ref.glyph_id(ch).0 != 0 {
                sample.push(ch);
                count += 1;
                if count == dyn_cap + 3 {
                    break;
                }
            }
        }
        sample.push('A');

        let (measured_w, _) = fonts.measure_run(&sample, 0, 0.0, f32::NAN);
        let (a_w, _) = fonts.measure_run("A", 0, 0.0, f32::NAN);
        let box_w = measured_w + 80.0;

        for align in [
            spec::TextAlign::Left as u8,
            spec::TextAlign::Center as u8,
            spec::TextAlign::Right as u8,
        ] {
            let mut placed = Vec::new();
            fonts.layout_run_mut(&sample, 0, 0.0, f32::NAN, align, box_w, &mut placed);
            assert_eq!(placed.len(), sample.chars().count());
            // Overflow CJK glyphs degrade to tofu (gid 0) without changing layout width.
            for g in &placed[dyn_cap..dyn_cap + 3] {
                assert_eq!(g.gid, 0);
            }
            let expected_offset = match align {
                a if a == spec::TextAlign::Center as u8 => (box_w - measured_w) * 0.5,
                a if a == spec::TextAlign::Right as u8 => box_w - measured_w,
                _ => 0.0,
            };
            let last_a = placed.last().unwrap();
            assert_eq!(
                last_a.x + a_w,
                expected_offset + measured_w,
                "align={align}: layout_run_mut line width/alignment drifted from measure_run after batch filled"
            );
        }
    }

    #[test]
    fn dynamic_lru_dual_root_pinning_protects_primary_and_auxiliary_independently() {
        let mut cache = DynLruCache::new(4);
        let p1 = cache.begin_batch_for(DrawRoot::Primary);
        for i in 0..4u32 {
            assert!(cache.alloc_slot_for(0x4E00 + i, 12, 0, DrawRoot::Primary, p1).is_some());
        }
        // Auxiliary draw begins its own epoch; primary's 4 entries remain pinned.
        let a1 = cache.begin_batch_for(DrawRoot::Auxiliary);
        assert!(
            cache.alloc_slot_for(0x5000, 12, 0, DrawRoot::Auxiliary, a1).is_none(),
            "auxiliary draw must not evict primary's active pinned glyphs"
        );
        // Auxiliary pins one shared glyph (0x4E00) as well.
        assert!(cache.get_and_pin_for(0x4E00, DrawRoot::Auxiliary, a1).is_some());

        // Primary advances to epoch p2: 0x4E01..=0x4E03 become evictable,
        // while 0x4E00 stays protected by auxiliary epoch a1!
        let p2 = cache.begin_batch_for(DrawRoot::Primary);
        for i in 0..3u32 {
            assert!(cache.alloc_slot_for(0x6000 + i, 12, 0, DrawRoot::Primary, p2).is_some());
        }
        assert!(cache.peek(0x4E00).is_some(), "0x4E00 must stay pinned for auxiliary");
        // 4th new glyph in p2 cannot evict 0x4E00 while a1 is active.
        assert!(cache.alloc_slot_for(0x6003, 12, 0, DrawRoot::Primary, p2).is_none());

        // Once auxiliary advances to a2 without 0x4E00, 0x4E00 becomes evictable.
        let a2 = cache.begin_batch_for(DrawRoot::Auxiliary);
        assert!(cache.alloc_slot_for(0x7000, 12, 0, DrawRoot::Auxiliary, a2).is_some());
        assert!(cache.peek(0x4E00).is_none());
        assert!(cache.peek(0x7000).is_some());
    }

    #[test]
    fn baseline_alignment_preserved_without_vertical_shift() {
        let font_ref = load_test_fallback_font();
        // Same baseline (11) and line_height (18), but `short` clips rows >= 11
        // while `tall` has room down to row 18. Without per-glyph vertical shifts,
        // rows 0..11 must be byte-for-byte identical.
        let short_blob = build_compact_atlas(0, 17, 11, 11, 18);
        let tall_blob = build_compact_atlas(0, 17, 18, 11, 18);
        let mut short = Atlas::parse_with_fallback(&short_blob, font_ref.clone()).unwrap();
        let mut tall = Atlas::parse_with_fallback(&tall_blob, font_ref).unwrap();

        // Pick a glyph whose ink extends below row 11 (below baseline).
        let cp = '你' as u32;
        let e1 = short.begin_batch();
        let e2 = tall.begin_batch();
        let (gid_s, _, _) = short.prepare_dynamic_glyph(cp, e1).unwrap();
        let (gid_t, _, _) = tall.prepare_dynamic_glyph(cp, e2).unwrap();
        let rows_s = short.glyph_rows(gid_s);
        let rows_t = tall.glyph_rows(gid_t);
        // Verify the glyph actually had ink below row 11 in the tall cell so the test is meaningful.
        assert!(
            rows_t[11 * 17..].iter().any(|&a| a > 0),
            "expected lower ink past row 11 in tall cell"
        );
        assert_eq!(
            rows_s,
            &rows_t[..11 * 17],
            "clipping overflow must preserve exact baseline alignment without shifting rows upward"
        );
    }

    #[test]
    fn zero_and_wide_logical_advances_are_preserved() {
        let font_ref = load_test_fallback_font();
        // Narrow cell_w = 6, line_height = 15: fullwidth CJK '你' has logical advance > 6.
        let blob = build_compact_atlas(0, 6, 15, 12, 15);
        let mut fonts = Fonts::new();
        assert!(fonts.load_with_fallback(&blob, font_ref.clone()));

        let (wide_w, _) = fonts.measure_run("你", 0, 0.0, f32::NAN);
        assert!(
            wide_w > 6.0,
            "wide glyph advance must not be clamped to cell_w (got {wide_w})"
        );
        let mut placed = Vec::new();
        fonts.layout_run_mut("你A", 0, 0.0, f32::NAN, spec::TextAlign::Left as u8, 100.0, &mut placed);
        assert_eq!(placed.len(), 2);
        assert_eq!(placed[1].x, wide_w);

        // Find a supported zero-advance combining mark in the fallback TTF (if present).
        let scale = PxScale::from(15.0 * 0.88);
        let scaled = font_ref.as_scaled(scale);
        let combining_cp = (0x0300u32..=0x036Fu32).find(|&cp| {
            let ch = char::from_u32(cp).unwrap();
            let gid = font_ref.glyph_id(ch);
            gid.0 != 0 && floor_i32(scaled.h_advance(gid) + 0.5) == 0
        });
        if let Some(cp) = combining_cp {
            let mut s = alloc::string::String::new();
            s.push(char::from_u32(cp).unwrap());
            let (zw, _) = fonts.measure_run(&s, 0, 0.0, f32::NAN);
            assert_eq!(zw, 0.0, "zero-advance combining mark must keep 0 advance");
            let epoch = fonts.atlas_mut(0).unwrap().begin_batch();
            let (_, adv, _) = fonts
                .atlas_mut(0)
                .unwrap()
                .prepare_dynamic_glyph(cp, epoch)
                .unwrap();
            assert_eq!(adv, 0.0);
        }
    }
}
