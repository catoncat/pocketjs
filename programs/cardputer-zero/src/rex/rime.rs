//! Hybrid Chinese Pinyin IME (`librime` dynamic FFI on Linux + built-in ~420-syllable
//! & phrase Simplified Chinese lexicon fallback on macOS/headless/bare systems).
//! Supports both `pinyin_simp` (全拼) and `double_pinyin` (自然码/小鹤双拼).

use crate::rex::types::{ImeComposeReply, ImeEngine, ImeSchema, ImeStatus};
use std::sync::Mutex;

const PAGE_SIZE: usize = 5;
const MAX_PAGE_DELTA: i32 = 16;
#[cfg(target_os = "linux")]
const MAX_NATIVE_PAGE_STEPS: usize = 32;

pub struct RimeIme {
    inner: Mutex<ImeInner>,
}

#[cfg(target_os = "linux")]
enum LazyRime {
    Unchecked,
    Available(LibrimeHandle),
    Unavailable,
}

struct ImeInner {
    schema: ImeSchema,
    page: usize,
    last_raw: String,
    #[cfg(target_os = "linux")]
    librime: LazyRime,
    #[cfg(target_os = "linux")]
    native_schema_ok: bool,
}

#[cfg(target_os = "linux")]
impl ImeInner {
    fn ensure_librime_loaded(&mut self) {
        if matches!(self.librime, LazyRime::Unchecked) {
            match LibrimeHandle::try_load() {
                Some(mut rime) => {
                    self.native_schema_ok = if matches!(self.schema, ImeSchema::PinyinSimp) {
                        true
                    } else {
                        rime.select_schema(self.schema)
                    };
                    self.librime = LazyRime::Available(rime);
                }
                None => {
                    self.native_schema_ok = false;
                    self.librime = LazyRime::Unavailable;
                }
            }
        }
    }
}

impl RimeIme {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ImeInner {
                schema: ImeSchema::PinyinSimp,
                page: 0,
                last_raw: String::new(),
                #[cfg(target_os = "linux")]
                librime: LazyRime::Unchecked,
                #[cfg(target_os = "linux")]
                native_schema_ok: false,
            }),
        }
    }

    pub fn status(&self) -> ImeStatus {
        #[allow(unused_mut)]
        let mut guard = self.inner.lock().unwrap();
        #[cfg(target_os = "linux")]
        let engine = {
            guard.ensure_librime_loaded();
            match &guard.librime {
                LazyRime::Available(_) if guard.native_schema_ok => ImeEngine::Librime,
                LazyRime::Unchecked | LazyRime::Available(_) | LazyRime::Unavailable => {
                    ImeEngine::Builtin
                }
            }
        };
        #[cfg(not(target_os = "linux"))]
        let engine = ImeEngine::Builtin;

        ImeStatus {
            available: true,
            engine,
            schema: guard.schema,
        }
    }

    pub fn compose(
        &self,
        raw: &str,
        select_idx: Option<usize>,
        page_delta: Option<i32>,
        toggle_schema: bool,
    ) -> ImeComposeReply {
        let mut guard = self.inner.lock().unwrap();
        if toggle_schema {
            guard.schema = match guard.schema {
                ImeSchema::PinyinSimp => ImeSchema::DoublePinyin,
                ImeSchema::DoublePinyin => ImeSchema::PinyinSimp,
            };
            guard.page = 0;
            #[cfg(target_os = "linux")]
            {
                let schema = guard.schema;
                let ok = match &mut guard.librime {
                    LazyRime::Available(rime) => rime.select_schema(schema),
                    LazyRime::Unchecked | LazyRime::Unavailable => false,
                };
                guard.native_schema_ok = ok;
            }
        }

        let clean: String = raw
            .chars()
            .filter(|c| c.is_ascii_alphabetic() || *c == '\'')
            .map(|c| c.to_ascii_lowercase())
            .collect();

        if clean != guard.last_raw {
            guard.page = 0;
            guard.last_raw = clean.clone();
        }
        if let Some(delta) = page_delta {
            let clamped = delta.clamp(-MAX_PAGE_DELTA, MAX_PAGE_DELTA);
            if clamped < 0 {
                guard.page = guard.page.saturating_sub(clamped.unsigned_abs() as usize);
            } else if clamped > 0 {
                guard.page = guard.page.saturating_add(clamped as usize);
            }
        }

        if clean.is_empty() {
            guard.page = 0;
            return ImeComposeReply {
                raw: String::new(),
                preedit: String::new(),
                candidates: Vec::new(),
                committed: None,
                page: 0,
                has_more: false,
                schema: guard.schema,
            };
        }

        #[cfg(target_os = "linux")]
        {
            guard.ensure_librime_loaded();
            if guard.native_schema_ok {
                let cur_page = guard.page.min(MAX_NATIVE_PAGE_STEPS);
                let cur_schema = guard.schema;
                let maybe_reply = match &mut guard.librime {
                    LazyRime::Available(rime) => {
                        rime.compose(&clean, cur_page, select_idx, cur_schema)
                    }
                    LazyRime::Unchecked | LazyRime::Unavailable => None,
                };
                if let Some(reply) = maybe_reply {
                    if reply.committed.is_some() {
                        guard.page = 0;
                        guard.last_raw.clear();
                    } else {
                        guard.page = reply.page;
                    }
                    return reply;
                }
            }
        }

        let (preedit, all_candidates, consumed_chars_per_candidate) =
            builtin_lookup(&clean, guard.schema);

        if all_candidates.is_empty() {
            return ImeComposeReply {
                raw: clean.clone(),
                preedit: clean.clone(),
                candidates: vec![clean],
                committed: None,
                page: 0,
                has_more: false,
                schema: guard.schema,
            };
        }

        let max_page = (all_candidates.len().saturating_sub(1)) / PAGE_SIZE;
        if guard.page > max_page {
            guard.page = max_page;
        }
        let start = guard.page * PAGE_SIZE;
        let end = (start + PAGE_SIZE).min(all_candidates.len());
        let page_candidates: Vec<String> = all_candidates[start..end].to_vec();
        let has_more = end < all_candidates.len();

        if let Some(idx) = select_idx {
            if let Some(chosen) = page_candidates.get(idx).cloned() {
                let consumed = consumed_chars_per_candidate
                    .get(start + idx)
                    .copied()
                    .unwrap_or(clean.len())
                    .min(clean.len());
                let remaining = clean[consumed..].trim_start_matches('\'').to_string();
                guard.page = 0;
                guard.last_raw = remaining.clone();
                if remaining.is_empty() {
                    return ImeComposeReply {
                        raw: String::new(),
                        preedit: String::new(),
                        candidates: Vec::new(),
                        committed: Some(chosen),
                        page: 0,
                        has_more: false,
                        schema: guard.schema,
                    };
                }
                let (next_preedit, next_all, _) = builtin_lookup(&remaining, guard.schema);
                let next_end = PAGE_SIZE.min(next_all.len());
                return ImeComposeReply {
                    raw: remaining,
                    preedit: next_preedit,
                    candidates: next_all[..next_end].to_vec(),
                    committed: Some(chosen),
                    page: 0,
                    has_more: next_all.len() > next_end,
                    schema: guard.schema,
                };
            }
        }

        ImeComposeReply {
            raw: clean,
            preedit,
            candidates: page_candidates,
            committed: None,
            page: guard.page,
            has_more,
            schema: guard.schema,
        }
    }
}

// ============================================================================
// Dynamic `librime.so.1` FFI (`#[cfg(target_os = "linux")]`)
// ============================================================================

#[cfg(target_os = "linux")]
struct LibrimeGlobal {
    lib: *mut libc::c_void,
    api: *const RimeApi,
    active_sessions: usize,
    initialized: bool,
    setup_done: bool,
    shared_dir_c: Option<std::ffi::CString>,
    prebuilt_dir_c: Option<std::ffi::CString>,
    user_dir_c: Option<std::ffi::CString>,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LibrimeGlobal {}

#[cfg(target_os = "linux")]
impl LibrimeGlobal {
    const fn new() -> Self {
        Self {
            lib: std::ptr::null_mut(),
            api: std::ptr::null(),
            active_sessions: 0,
            initialized: false,
            setup_done: false,
            shared_dir_c: None,
            prebuilt_dir_c: None,
            user_dir_c: None,
        }
    }
}

#[cfg(target_os = "linux")]
static LIBRIME_GLOBAL: Mutex<LibrimeGlobal> = Mutex::new(LibrimeGlobal::new());

#[cfg(target_os = "linux")]
struct LibrimeHandle {
    api: *const RimeApi,
    session: usize,
}

#[cfg(target_os = "linux")]
unsafe impl Send for LibrimeHandle {}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeTraits {
    data_size: libc::c_int,
    shared_data_dir: *const libc::c_char,
    user_data_dir: *const libc::c_char,
    distribution_name: *const libc::c_char,
    distribution_code_name: *const libc::c_char,
    distribution_version: *const libc::c_char,
    app_name: *const libc::c_char,
    modules: *const *const libc::c_char,
    min_log_level: libc::c_int,
    log_dir: *const libc::c_char,
    prebuilt_data_dir: *const libc::c_char,
    staging_dir: *const libc::c_char,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeComposition {
    length: libc::c_int,
    cursor_pos: libc::c_int,
    sel_start: libc::c_int,
    sel_end: libc::c_int,
    preedit: *mut libc::c_char,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeCandidate {
    text: *mut libc::c_char,
    comment: *mut libc::c_char,
    reserved: *mut libc::c_void,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeMenu {
    page_size: libc::c_int,
    page_no: libc::c_int,
    is_last_page: libc::c_int,
    highlighted_candidate_index: libc::c_int,
    num_candidates: libc::c_int,
    candidates: *mut RimeCandidate,
    select_keys: *mut libc::c_char,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeCommit {
    data_size: libc::c_int,
    text: *mut libc::c_char,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeContext {
    data_size: libc::c_int,
    composition: RimeComposition,
    menu: RimeMenu,
    commit_text_preview: *mut libc::c_char,
    select_labels: *mut *mut libc::c_char,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct RimeApi {
    data_size: libc::c_int,
    setup: Option<unsafe extern "C" fn(*mut RimeTraits)>,
    set_notification_handler: Option<unsafe extern "C" fn(*const libc::c_void, *mut libc::c_void)>,
    initialize: Option<unsafe extern "C" fn(*mut RimeTraits)>,
    finalize: Option<unsafe extern "C" fn()>,
    start_maintenance: Option<unsafe extern "C" fn(libc::c_int) -> libc::c_int>,
    is_maintenance_mode: Option<unsafe extern "C" fn() -> libc::c_int>,
    join_maintenance_thread: Option<unsafe extern "C" fn()>,
    deployer_initialize: Option<unsafe extern "C" fn(*mut RimeTraits)>,
    prebuild: Option<unsafe extern "C" fn() -> libc::c_int>,
    deploy: Option<unsafe extern "C" fn() -> libc::c_int>,
    deploy_schema: Option<unsafe extern "C" fn(*const libc::c_char) -> libc::c_int>,
    deploy_config_file:
        Option<unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int>,
    sync_user_data: Option<unsafe extern "C" fn() -> libc::c_int>,
    create_session: Option<unsafe extern "C" fn() -> usize>,
    find_session: Option<unsafe extern "C" fn(usize) -> libc::c_int>,
    destroy_session: Option<unsafe extern "C" fn(usize) -> libc::c_int>,
    cleanup_stale_sessions: Option<unsafe extern "C" fn()>,
    cleanup_all_sessions: Option<unsafe extern "C" fn()>,
    process_key: Option<unsafe extern "C" fn(usize, libc::c_int, libc::c_int) -> libc::c_int>,
    commit_composition: Option<unsafe extern "C" fn(usize) -> libc::c_int>,
    clear_composition: Option<unsafe extern "C" fn(usize)>,
    get_commit: Option<unsafe extern "C" fn(usize, *mut RimeCommit) -> libc::c_int>,
    free_commit: Option<unsafe extern "C" fn(*mut RimeCommit) -> libc::c_int>,
    get_context: Option<unsafe extern "C" fn(usize, *mut RimeContext) -> libc::c_int>,
    free_context: Option<unsafe extern "C" fn(*mut RimeContext) -> libc::c_int>,
    get_status: Option<unsafe extern "C" fn(usize, *mut libc::c_void) -> libc::c_int>,
    free_status: Option<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>,
    set_option: Option<unsafe extern "C" fn(usize, *const libc::c_char, libc::c_int)>,
    get_option: Option<unsafe extern "C" fn(usize, *const libc::c_char) -> libc::c_int>,
    set_property: Option<unsafe extern "C" fn(usize, *const libc::c_char, *const libc::c_char)>,
    get_property:
        Option<unsafe extern "C" fn(usize, *const libc::c_char, *mut libc::c_char, usize) -> libc::c_int>,
    get_schema_list: Option<unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int>,
    free_schema_list: Option<unsafe extern "C" fn(*mut libc::c_void)>,
    get_current_schema: Option<unsafe extern "C" fn(usize, *mut libc::c_char, usize) -> libc::c_int>,
    select_schema: Option<unsafe extern "C" fn(usize, *const libc::c_char) -> libc::c_int>,
}

#[cfg(target_os = "linux")]
impl LibrimeHandle {
    fn try_load() -> Option<Self> {
        use std::{ffi::CString, os::unix::fs::PermissionsExt, path::PathBuf};

        let mut global = LIBRIME_GLOBAL.lock().unwrap();

        if global.api.is_null() {
            let shared_dir = ["/usr/share/rime-data", "/usr/share/rime"]
                .into_iter()
                .map(PathBuf::from)
                .find(|p| p.is_dir())?;

            let lib = unsafe {
                let h = libc::dlopen(
                    b"librime.so.1\0".as_ptr().cast(),
                    libc::RTLD_NOW | libc::RTLD_LOCAL,
                );
                if !h.is_null() {
                    h
                } else {
                    libc::dlopen(
                        b"librime.so\0".as_ptr().cast(),
                        libc::RTLD_NOW | libc::RTLD_LOCAL,
                    )
                }
            };
            if lib.is_null() {
                return None;
            }

            let get_api_sym = unsafe { libc::dlsym(lib, b"rime_get_api\0".as_ptr().cast()) };
            if get_api_sym.is_null() {
                unsafe { libc::dlclose(lib) };
                return None;
            }
            let get_api: unsafe extern "C" fn() -> *const RimeApi =
                unsafe { std::mem::transmute(get_api_sym) };
            let api = unsafe { get_api() };
            if api.is_null() {
                unsafe { libc::dlclose(lib) };
                return None;
            }

            let state_base = std::env::var_os("XDG_STATE_HOME")
                .map(PathBuf::from)
                .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
                .unwrap_or_else(|| PathBuf::from("/tmp"));
            let user_dir = state_base.join("rex-zero/rime");
            let _ = std::fs::create_dir_all(&user_dir);
            let _ = std::fs::set_permissions(&user_dir, std::fs::Permissions::from_mode(0o700));

            // Point user_dir/build directly at system prebuilt binaries (e.g. /usr/share/rime-data/build)
            // and clean up any incomplete partial build directory left by older maintenance runs,
            // so librime loads precompiled prisms/tables in <5ms with 0 MiB YAML compilation RAM.
            let prebuilt_dir = shared_dir.join("build");
            let prebuilt_dir_c = if prebuilt_dir.is_dir() {
                if prebuilt_dir.join("pinyin_simp.table.bin").is_file() {
                    let user_build = user_dir.join("build");
                    if let Ok(meta) = std::fs::symlink_metadata(&user_build) {
                        if !meta.file_type().is_symlink()
                            && !user_build.join("pinyin_simp.table.bin").is_file()
                        {
                            let _ = std::fs::remove_dir_all(&user_build);
                        }
                    }
                    if std::fs::symlink_metadata(&user_build).is_err() {
                        let _ = std::os::unix::fs::symlink(&prebuilt_dir, &user_build);
                    }
                }
                CString::new(prebuilt_dir.to_string_lossy().as_bytes()).ok()
            } else {
                None
            };

            let Some(shared_dir_c) = CString::new(shared_dir.to_string_lossy().as_bytes()).ok()
            else {
                unsafe { libc::dlclose(lib) };
                return None;
            };
            let Some(user_dir_c) = CString::new(user_dir.to_string_lossy().as_bytes()).ok() else {
                unsafe { libc::dlclose(lib) };
                return None;
            };

            global.lib = lib;
            global.api = api;
            global.shared_dir_c = Some(shared_dir_c);
            global.prebuilt_dir_c = prebuilt_dir_c;
            global.user_dir_c = Some(user_dir_c);
        }

        let api = global.api;
        let session = unsafe {
            let api_ref = &*api;
            if !global.initialized {
                let shared_ptr = global.shared_dir_c.as_ref()?.as_ptr();
                let user_ptr = global.user_dir_c.as_ref()?.as_ptr();
                let prebuilt_ptr = global
                    .prebuilt_dir_c
                    .as_ref()
                    .map_or(std::ptr::null(), |c| c.as_ptr());
                let mut traits: RimeTraits = std::mem::zeroed();
                traits.data_size = (std::mem::size_of::<RimeTraits>()
                    - std::mem::size_of::<libc::c_int>())
                    as libc::c_int;
                traits.shared_data_dir = shared_ptr;
                traits.user_data_dir = user_ptr;
                traits.prebuilt_data_dir = prebuilt_ptr;
                traits.distribution_name = b"RexZero\0".as_ptr().cast();
                traits.distribution_code_name = b"rex-zero\0".as_ptr().cast();
                traits.distribution_version = b"0.2.0\0".as_ptr().cast();
                traits.app_name = b"rime.rex-zero\0".as_ptr().cast();
                traits.min_log_level = 2;
                traits.log_dir = b"\0".as_ptr().cast();

                if !global.setup_done {
                    (api_ref.setup?)(&mut traits);
                    global.setup_done = true;
                }
                // Never run `start_maintenance` / `join_maintenance_thread` on 352 MiB Pi Zero 2W:
                // compiling cangjie5/bopomofo YAML dictionaries in RAM swap-thrashes the device.
                (api_ref.initialize?)(&mut traits);
                global.initialized = true;
            }

            let session = (api_ref.create_session?)();
            if session == 0 {
                if global.active_sessions == 0 && global.initialized {
                    if let Some(fin) = api_ref.finalize {
                        fin();
                    }
                    global.initialized = false;
                }
                return None;
            }
            global.active_sessions += 1;
            session
        };
        drop(global);

        let mut handle = Self { api, session };
        if !handle.select_schema(ImeSchema::PinyinSimp) {
            return None;
        }
        // Sanity check that schema dictionary actually yields CJK candidates;
        // otherwise fall back cleanly to built-in Rust lexicon (Drop cleans up refcount).
        if handle
            .compose("nihao", 0, None, ImeSchema::PinyinSimp)
            .is_none_or(|r| r.candidates.is_empty())
        {
            return None;
        }
        Some(handle)
    }

    fn select_schema(&mut self, schema: ImeSchema) -> bool {
        unsafe {
            let api_ref = &*self.api;
            let Some(sel) = api_ref.select_schema else {
                return false;
            };
            match schema {
                ImeSchema::PinyinSimp => {
                    sel(self.session, b"pinyin_simp\0".as_ptr().cast()) != 0
                        || sel(self.session, b"luna_pinyin_simp\0".as_ptr().cast()) != 0
                }
                ImeSchema::DoublePinyin => {
                    sel(self.session, b"double_pinyin\0".as_ptr().cast()) != 0
                        || sel(self.session, b"double_pinyin_flypy\0".as_ptr().cast()) != 0
                }
            }
        }
    }

    unsafe fn peek_menu_page(
        &self,
        get_context: unsafe extern "C" fn(usize, *mut RimeContext) -> libc::c_int,
        free_context: unsafe extern "C" fn(*mut RimeContext) -> libc::c_int,
    ) -> (bool, usize, bool) {
        let mut ctx: RimeContext = std::mem::zeroed();
        ctx.data_size = (std::mem::size_of::<RimeContext>() - std::mem::size_of::<libc::c_int>())
            as libc::c_int;
        if get_context(self.session, &mut ctx) == 0 {
            return (true, 0, false);
        }
        let is_last = ctx.menu.is_last_page != 0 || ctx.menu.num_candidates <= 0;
        let page_no = ctx.menu.page_no.max(0) as usize;
        let _ = free_context(&mut ctx);
        (is_last, page_no, true)
    }

    fn compose(
        &mut self,
        clean: &str,
        page: usize,
        select_idx: Option<usize>,
        schema: ImeSchema,
    ) -> Option<ImeComposeReply> {
        unsafe {
            let api_ref = &*self.api;
            let clear = api_ref.clear_composition?;
            let process_key = api_ref.process_key?;
            let get_context = api_ref.get_context?;
            let free_context = api_ref.free_context?;
            let get_commit = api_ref.get_commit?;
            let free_commit = api_ref.free_commit?;

            clear(self.session);
            for b in clean.bytes() {
                let _ = process_key(self.session, b as libc::c_int, 0);
            }

            // Bounded candidate-page traversal: stop immediately on `is_last_page != 0`
            // or if `page_no` stops advancing.
            let target_steps = page.min(MAX_NATIVE_PAGE_STEPS);
            for _ in 0..target_steps {
                let (is_last, prev_page_no, ok) = self.peek_menu_page(get_context, free_context);
                if !ok || is_last {
                    break;
                }
                // XK_Page_Down = 0xff56
                let _ = process_key(self.session, 0xff56, 0);
                let (next_is_last, next_page_no, next_ok) =
                    self.peek_menu_page(get_context, free_context);
                if !next_ok || next_is_last || next_page_no <= prev_page_no {
                    break;
                }
            }

            if let Some(idx) = select_idx {
                if idx < 9 {
                    let digit = (b'1' + idx as u8) as libc::c_int;
                    let _ = process_key(self.session, digit, 0);
                }
            }

            let mut committed = None;
            let mut commit: RimeCommit = std::mem::zeroed();
            commit.data_size =
                (std::mem::size_of::<RimeCommit>() - std::mem::size_of::<libc::c_int>()) as libc::c_int;
            if get_commit(self.session, &mut commit) != 0 {
                if !commit.text.is_null() {
                    let s = std::ffi::CStr::from_ptr(commit.text)
                        .to_string_lossy()
                        .into_owned();
                    if !s.is_empty() {
                        committed = Some(s);
                    }
                }
                let _ = free_commit(&mut commit);
            }

            let mut ctx: RimeContext = std::mem::zeroed();
            ctx.data_size =
                (std::mem::size_of::<RimeContext>() - std::mem::size_of::<libc::c_int>()) as libc::c_int;
            if get_context(self.session, &mut ctx) == 0 {
                return committed.map(|c| ImeComposeReply {
                    raw: String::new(),
                    preedit: String::new(),
                    candidates: Vec::new(),
                    committed: Some(c),
                    page: 0,
                    has_more: false,
                    schema,
                });
            }

            let preedit = if !ctx.composition.preedit.is_null() {
                std::ffi::CStr::from_ptr(ctx.composition.preedit)
                    .to_string_lossy()
                    .into_owned()
            } else {
                clean.to_string()
            };
            let mut candidates = Vec::new();
            if ctx.menu.num_candidates > 0 && !ctx.menu.candidates.is_null() {
                let slice = std::slice::from_raw_parts(
                    ctx.menu.candidates,
                    ctx.menu.num_candidates as usize,
                );
                for cand in slice.iter().take(PAGE_SIZE) {
                    if !cand.text.is_null() {
                        candidates.push(
                            std::ffi::CStr::from_ptr(cand.text)
                                .to_string_lossy()
                                .into_owned(),
                        );
                    }
                }
            }
            let page_no = ctx.menu.page_no.max(0) as usize;
            let has_more = ctx.menu.is_last_page == 0 && !candidates.is_empty();
            let _ = free_context(&mut ctx);

            if candidates.is_empty() && committed.is_none() {
                return None;
            }
            let remaining_raw = if committed.is_some() && candidates.is_empty() {
                String::new()
            } else {
                clean.to_string()
            };
            Some(ImeComposeReply {
                raw: remaining_raw,
                preedit,
                candidates,
                committed,
                page: page_no,
                has_more,
                schema,
            })
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for LibrimeHandle {
    fn drop(&mut self) {
        let mut global = LIBRIME_GLOBAL.lock().unwrap();
        unsafe {
            if !self.api.is_null() {
                let api_ref = &*self.api;
                if self.session != 0 {
                    if let Some(destroy) = api_ref.destroy_session {
                        let _ = destroy(self.session);
                    }
                    self.session = 0;
                }
                global.active_sessions = global.active_sessions.saturating_sub(1);
                if global.active_sessions == 0 && global.initialized {
                    if let Some(fin) = api_ref.finalize {
                        fin();
                    }
                    global.initialized = false;
                }
            }
        }
    }
}

// ============================================================================
// Built-in Simplified Chinese Pinyin + Double-Pinyin Fallback Lexicon
// ============================================================================

fn builtin_lookup(raw: &str, schema: ImeSchema) -> (String, Vec<String>, Vec<usize>) {
    let normalized = raw.replace('\'', "");
    if normalized.is_empty() {
        return (String::new(), Vec::new(), Vec::new());
    }

    let (syllables, raw_spans) = match schema {
        ImeSchema::PinyinSimp => segment_quanpin(raw),
        ImeSchema::DoublePinyin => expand_double_pinyin(&normalized),
    };

    let preedit = syllables.join("'");
    let joined_pinyin = syllables.join("");
    let total_raw_len = raw.len();

    let mut candidates: Vec<String> = Vec::new();
    let mut consumed_lens: Vec<usize> = Vec::new();

    let mut push_unique = |word: String, consumed: usize| {
        if !word.is_empty() && !candidates.contains(&word) {
            candidates.push(word);
            consumed_lens.push(consumed);
        }
    };

    // 1. Exact multi-syllable phrase matches.
    for &(py, words) in PHRASES {
        if py == joined_pinyin {
            for w in words.split(',') {
                push_unique(w.to_string(), total_raw_len);
            }
        }
    }

    // 2. Prefix phrase matches when user is mid-typing a phrase.
    if syllables.len() >= 2 {
        for &(py, words) in PHRASES {
            if py.starts_with(&joined_pinyin) && py != joined_pinyin {
                if let Some(first) = words.split(',').next() {
                    push_unique(first.to_string(), total_raw_len);
                }
            }
        }
        // Synthesize top-character compound across all segmented syllables.
        let mut compound = String::new();
        let mut all_matched = true;
        for syl in &syllables {
            if let Some(chars) = syllable_chars(syl) {
                if let Some(ch) = chars.chars().next() {
                    compound.push(ch);
                }
            } else {
                all_matched = false;
                break;
            }
        }
        if all_matched && compound.chars().count() >= 2 {
            push_unique(compound, total_raw_len);
        }
    }

    // 3. First 2-syllable sub-phrase if user typed >= 3 syllables.
    if syllables.len() >= 3 {
        let two = format!("{}{}", syllables[0], syllables[1]);
        let two_consumed = raw_spans.get(1).copied().unwrap_or(total_raw_len);
        for &(py, words) in PHRASES {
            if py == two {
                for w in words.split(',').take(3) {
                    push_unique(w.to_string(), two_consumed);
                }
            }
        }
    }

    // 4. First syllable single-character candidates (supports step-by-step selection!).
    if let Some(first_syl) = syllables.first() {
        let first_consumed = raw_spans.first().copied().unwrap_or(total_raw_len);
        if let Some(chars) = syllable_chars(first_syl) {
            for ch in chars.chars() {
                push_unique(ch.to_string(), first_consumed);
            }
        } else {
            // Prefix syllable completion (e.g. "zh" -> "zh" matching "zhe", "zhong", "zhi").
            for &(syl, chars) in SYLLABLES {
                if syl.starts_with(first_syl.as_str()) {
                    for ch in chars.chars().take(3) {
                        push_unique(ch.to_string(), first_consumed);
                    }
                }
            }
        }
    }

    (preedit, candidates, consumed_lens)
}

/// Greedy longest-match Mandarin syllable splitter with apostrophe support.
fn segment_quanpin(raw: &str) -> (Vec<String>, Vec<usize>) {
    let mut syllables = Vec::new();
    let mut end_offsets = Vec::new();
    let bytes = raw.as_bytes();
    let mut pos = 0usize;

    while pos < bytes.len() {
        if bytes[pos] == b'\'' {
            pos += 1;
            continue;
        }
        let max_end = raw[pos..]
            .find('\'')
            .map(|rel| pos + rel)
            .unwrap_or(bytes.len());
        let slice = &raw[pos..max_end];

        let mut matched_len = 0usize;
        for len in (1..=slice.len().min(6)).rev() {
            let candidate = &slice[..len];
            if syllable_chars(candidate).is_some() {
                // Avoid splitting e.g. "nihao" into "nih"+"ao" (invalid) vs "ni"+"hao" (valid):
                // if there are leftover letters right after `len` that start with a vowel (`a/e/o/i/u/v`)
                // while `candidate` ended with `n` or `g` (`xian` vs `xi'an`, `fangan` vs `fan'gan` / `fang'an`),
                // check if `len - 1` makes the next syllable valid when `len` leaves an invalid start!
                if pos + len < max_end && len >= 3 {
                    let rem = &slice[len..];
                    let rem_has_valid_prefix = (1..=rem.len().min(6))
                        .any(|rlen| syllable_chars(&rem[..rlen]).is_some());
                    if !rem_has_valid_prefix && syllable_chars(&slice[..len - 1]).is_some() {
                        let alt_rem = &slice[len - 1..];
                        let alt_ok = (1..=alt_rem.len().min(6))
                            .any(|rlen| syllable_chars(&alt_rem[..rlen]).is_some());
                        if alt_ok {
                            matched_len = len - 1;
                            break;
                        }
                    }
                }
                matched_len = len;
                break;
            }
        }

        if matched_len == 0 {
            // Incomplete initial like "zh", "ch", "sh", or single consonant.
            matched_len = if slice.starts_with("zh")
                || slice.starts_with("ch")
                || slice.starts_with("sh")
            {
                2.min(slice.len())
            } else {
                1
            };
        }
        syllables.push(slice[..matched_len].to_string());
        pos += matched_len;
        end_offsets.push(pos);
    }

    (syllables, end_offsets)
}

/// Natural / Xiaohe Double-Pinyin (自然码/小鹤双拼) 2-key syllable decoder.
fn expand_double_pinyin(clean: &str) -> (Vec<String>, Vec<usize>) {
    let bytes = clean.as_bytes();
    let mut syllables = Vec::new();
    let mut offsets = Vec::new();
    let mut i = 0usize;

    while i < bytes.len() {
        if i + 1 >= bytes.len() {
            let single = match bytes[i] {
                b'u' => "sh".to_string(),
                b'i' => "ch".to_string(),
                b'v' => "zh".to_string(),
                c => (c as char).to_string(),
            };
            syllables.push(single);
            offsets.push(i + 1);
            break;
        }
        let c1 = bytes[i];
        let c2 = bytes[i + 1];
        let expanded = decode_dp_pair(c1, c2);
        syllables.push(expanded);
        i += 2;
        offsets.push(i);
    }
    (syllables, offsets)
}

fn decode_dp_pair(c1: u8, c2: u8) -> String {
    // Zero-initial two-letter syllables in Xiaohe / Ziranma:
    match (c1, c2) {
        (b'a', b'a') => return "a".into(),
        (b'a', b'i') => return "ai".into(),
        (b'a', b'n') => return "an".into(),
        (b'a', b'h') => return "ang".into(),
        (b'a', b'o') => return "ao".into(),
        (b'e', b'e') => return "e".into(),
        (b'e', b'i') => return "ei".into(),
        (b'e', b'n') => return "en".into(),
        (b'e', b'g') => return "eng".into(),
        (b'e', b'r') => return "er".into(),
        (b'o', b'o') => return "o".into(),
        (b'o', b'u') => return "ou".into(),
        _ => {}
    }

    let initial = match c1 {
        b'u' => "sh".to_string(),
        b'i' => "ch".to_string(),
        b'v' => "zh".to_string(),
        other => (other as char).to_string(),
    };

    let candidates: &[&str] = match c2 {
        b'a' => &["a"],
        b'o' => &["uo", "o"],
        b'e' => &["e"],
        b'i' => &["i"],
        b'u' => &["u"],
        b'v' => &["ui", "v", "ue"],
        b'q' => &["iu"],
        b'w' => &["ei", "ia"],
        b'r' => &["uan"],
        b't' => &["ue", "ve"],
        b'y' => &["un", "uai"],
        b'p' => &["ie", "un"],
        b's' => &["iong", "ong"],
        b'd' => &["uang", "iang"],
        b'f' => &["en"],
        b'g' => &["eng"],
        b'h' => &["ang"],
        b'j' => &["an"],
        b'k' => &["ing", "uai", "ao"],
        b'l' => &["ai", "uang", "iang"],
        b'z' => &["ou", "ei"],
        b'x' => &["ia", "ua", "ie"],
        b'c' => &["ao", "iao"],
        b'b' => &["in", "ou"],
        b'n' => &["iao", "in"],
        b'm' => &["ian"],
        _ => &[""],
    };

    for fin in candidates {
        let test = format!("{initial}{fin}");
        if syllable_chars(&test).is_some() {
            return test;
        }
    }
    format!("{initial}{}", c2 as char)
}

fn syllable_chars(syl: &str) -> Option<&'static str> {
    SYLLABLES
        .binary_search_by_key(&syl, |&(k, _)| k)
        .ok()
        .map(|idx| SYLLABLES[idx].1)
}

static PHRASES: &[(&str, &str)] = &[
    ("nihao", "你好,拟好,泥好,你号,昵好"),
    ("nihaoshijie", "你好世界"),
    ("xiexie", "谢谢,写写,歇歇"),
    ("keyi", "可以,刻意,可疑"),
    ("bukeyi", "不可以"),
    ("zenme", "怎么,怎嘛"),
    ("zenmeyang", "怎么样"),
    ("shenme", "什么"),
    ("weishenme", "为什么"),
    ("xianzai", "现在"),
    ("jintian", "今天"),
    ("mingtian", "明天"),
    ("zuotian", "昨天"),
    ("women", "我们"),
    ("nimen", "你们"),
    ("tamen", "他们,它们,她们"),
    ("zheli", "这里"),
    ("nali", "哪里,那里"),
    ("zhege", "这个"),
    ("nage", "那个"),
    ("yijing", "已经"),
    ("kaishi", "开始"),
    ("wancheng", "完成"),
    ("jixu", "继续"),
    ("queren", "确认"),
    ("quxiao", "取消"),
    ("tongyi", "同意,统一"),
    ("yunxu", "允许"),
    ("jujue", "拒绝"),
    ("pizhun", "批准"),
    ("daima", "代码"),
    ("bianyi", "编译,便宜"),
    ("ceshi", "测试"),
    ("yunxing", "运行"),
    ("bushu", "部署,步数"),
    ("fuwuqi", "服务器"),
    ("zhongduan", "终端,中断"),
    ("huihua", "会话,绘画"),
    ("lianjie", "连接,链接"),
    ("duankai", "断开"),
    ("rizhi", "日志"),
    ("baocuo", "报错"),
    ("chenggong", "成功"),
    ("shibai", "失败"),
    ("xiufu", "修复"),
    ("tijiao", "提交"),
    ("hebing", "合并"),
    ("fenzhi", "分支"),
    ("cangku", "仓库"),
    ("peizhi", "配置"),
    ("miyao", "密钥"),
    ("yuyin", "语音"),
    ("shuru", "输入"),
    ("shuchu", "输出"),
    ("jiancha", "检查"),
    ("zhuangtai", "状态"),
    ("wenti", "问题"),
    ("fangan", "方案"),
    ("bangzhu", "帮助"),
    ("baocun", "保存"),
    ("shanchu", "删除"),
    ("guanbi", "关闭"),
    ("dakai", "打开"),
    ("qiehuan", "切换"),
    ("sousuo", "搜索"),
    ("shuaxin", "刷新"),
    ("chakan", "查看"),
    ("qingqiu", "请求"),
    ("xiangying", "响应"),
    ("wangluo", "网络"),
    ("yanchi", "延迟"),
    ("benji", "本机"),
    ("yuancheng", "远程"),
    ("quanxian", "权限"),
    ("mingling", "命令"),
    ("zhixing", "执行"),
    ("zanting", "暂停"),
    ("zhongqi", "重启"),
    ("tuichu", "退出"),
];

/// Sorted alphabetically for O(log N) binary search! (~405 standard Mandarin syllables)
static SYLLABLES: &[(&str, &str)] = &[
    ("a", "啊阿吖呵腌"),
    ("ai", "爱矮挨哎碍癌艾哀"),
    ("an", "安按暗岸案俺胺"),
    ("ang", "昂盎肮"),
    ("ao", "奥傲熬凹袄懊"),
    ("ba", "把八吧爸拔罢巴疤"),
    ("bai", "白百败摆柏拜掰"),
    ("ban", "办半班版板伴搬扮"),
    ("bang", "帮棒绑傍榜膀"),
    ("bao", "包报保抱薄宝暴饱"),
    ("bei", "被北背杯备倍悲碑"),
    ("ben", "本奔笨苯夯"),
    ("beng", "崩蹦绷泵迸"),
    ("bi", "比必笔闭碧币彼避"),
    ("bian", "边变便编遍辨扁辩"),
    ("biao", "表标彪婊膘裱"),
    ("bie", "别憋瘪蹩"),
    ("bin", "宾滨斌濒鬓"),
    ("bing", "并病兵冰饼柄丙"),
    ("bo", "波播伯博薄玻璃脖"),
    ("bu", "不步部补布捕怖簿"),
    ("ca", "擦拆嚓"),
    ("cai", "才菜采猜财裁彩材"),
    ("can", "参残餐灿惨蚕"),
    ("cang", "藏仓苍舱沧"),
    ("cao", "草操槽糙曹嘈"),
    ("ce", "测策侧册厕"),
    ("cen", "岑涔"),
    ("ceng", "曾层蹭噌"),
    ("cha", "查差茶插叉察茬"),
    ("chai", "拆柴差豺钗"),
    ("chan", "产缠颤搀阐蝉铲"),
    ("chang", "长常场唱厂尝肠畅"),
    ("chao", "超吵抄潮朝炒巢"),
    ("che", "车撤扯彻澈掣"),
    ("chen", "趁称沉晨尘陈衬"),
    ("cheng", "成程城称乘盛撑诚"),
    ("chi", "吃尺迟池持齿赤翅"),
    ("chong", "冲重虫充宠崇"),
    ("chou", "抽愁臭仇丑稠筹"),
    ("chu", "出初处除础厨触楚"),
    ("chua", "欻"),
    ("chuai", "揣踹搋"),
    ("chuan", "穿船传串川喘椽"),
    ("chuang", "窗床创闯疮"),
    ("chui", "吹垂锤炊椎"),
    ("chun", "春纯唇蠢醇椿"),
    ("chuo", "戳绰辍啜"),
    ("ci", "次此词刺辞慈磁赐"),
    ("cong", "从聪丛匆葱囱"),
    ("cou", "凑楱辏"),
    ("cu", "粗促醋簇猝"),
    ("cuan", "窜篡蹿攒"),
    ("cui", "催脆翠粹摧衰"),
    ("cun", "存村寸忖皴"),
    ("cuo", "错措搓挫撮"),
    ("da", "大打达答搭塔哒"),
    ("dai", "带代待袋戴呆贷逮"),
    ("dan", "但单担蛋淡胆弹旦"),
    ("dang", "当党挡档荡铛"),
    ("dao", "到道导刀岛倒盗稻"),
    ("de", "的得地德底"),
    ("dei", "得"),
    ("den", "扽"),
    ("deng", "等灯登凳瞪蹬邓"),
    ("di", "地第低底弟滴敌递"),
    ("dia", "嗲"),
    ("dian", "点电店典垫颠淀碘"),
    ("diao", "掉调钓雕叼吊刁"),
    ("die", "跌爹叠碟蝶谍"),
    ("ding", "定顶订钉盯丁鼎锭"),
    ("diu", "丢铥"),
    ("dong", "动东懂洞冻冬董栋"),
    ("dou", "都斗豆逗抖陡兜"),
    ("du", "读度毒独堵肚渡赌"),
    ("duan", "段短断端锻缎"),
    ("dui", "对队堆兑敦"),
    ("dun", "顿盾蹲吨钝炖囤"),
    ("duo", "多朵夺躲舵剁惰"),
    ("e", "饿恶鹅额俄哦讹蛾"),
    ("ei", "诶欸"),
    ("en", "恩摁蒽"),
    ("eng", "鞥"),
    ("er", "而二耳儿尔饵贰"),
    ("fa", "发法罚乏伐阀筏"),
    ("fan", "反饭翻犯凡烦番范"),
    ("fang", "放方房防访仿芳纺"),
    ("fei", "非飞费废肥肺沸匪"),
    ("fen", "分份粉奋愤粪氛酚"),
    ("feng", "风封峰丰疯逢缝蜂"),
    ("fo", "佛"),
    ("fou", "否缶"),
    ("fu", "发服副府父负富付复"),
    ("ga", "嘎咖尬噶"),
    ("gai", "该改盖概钙溉丐"),
    ("gan", "干感敢赶甘肝杆乾"),
    ("gang", "刚钢港岗纲缸扛"),
    ("gao", "高搞告糕稿膏羔"),
    ("ge", "个各歌割哥格阁隔"),
    ("gei", "给"),
    ("gen", "跟根亘艮"),
    ("geng", "更耕颈梗耿庚"),
    ("gong", "工公功共供攻宫弓"),
    ("gou", "够狗沟钩购构苟"),
    ("gu", "古故股骨姑孤固雇"),
    ("gua", "挂刮瓜寡卦褂"),
    ("guai", "怪乖拐"),
    ("guan", "关管官观馆惯罐灌"),
    ("guang", "光广逛胱"),
    ("gui", "归贵鬼规轨柜桂硅"),
    ("gun", "滚棍辊"),
    ("guo", "过国果锅裹郭涡"),
    ("ha", "哈蛤呵"),
    ("hai", "还海害孩嗨亥骇"),
    ("han", "喊汉汗寒含旱焊酣"),
    ("hang", "行航巷杭夯"),
    ("hao", "好号毫豪耗浩郝嚎"),
    ("he", "和喝合河何核盒荷"),
    ("hei", "黑嘿"),
    ("hen", "很恨狠痕"),
    ("heng", "横衡恒哼亨"),
    ("hong", "红哄洪虹宏轰烘"),
    ("hou", "后候厚猴喉吼侯"),
    ("hu", "护湖户呼乎忽狐糊"),
    ("hua", "话花化画滑划华哗"),
    ("huai", "坏怀淮槐踝"),
    ("huan", "换还欢环缓患幻唤"),
    ("huang", "黄慌皇荒晃谎煌"),
    ("hui", "回会灰挥辉恢悔汇"),
    ("hun", "混婚魂昏荤浑"),
    ("huo", "活火或货获伙惑祸"),
    ("ji", "机几级计记己基集及"),
    ("jia", "家加假价架甲佳夹"),
    ("jian", "见件间建检减简键"),
    ("jiang", "将讲江降奖浆僵酱"),
    ("jiao", "叫教交角脚较觉焦"),
    ("jie", "接解姐节界借结街"),
    ("jin", "进近今金尽紧斤禁"),
    ("jing", "经静精京警镜净敬"),
    ("jiong", "窘炯迥"),
    ("jiu", "就九酒久旧救究纠"),
    ("ju", "局据举句具剧居拒"),
    ("juan", "卷捐圈倦眷绢"),
    ("jue", "觉决绝掘嚼爵倔"),
    ("jun", "军均君俊菌峻骏"),
    ("ka", "卡咖喀咯"),
    ("kai", "开凯慨揩楷"),
    ("kan", "看砍堪刊坎槛勘"),
    ("kang", "抗康扛糠慷亢"),
    ("kao", "考靠烤拷铐"),
    ("ke", "可科刻客课颗渴壳"),
    ("kei", "剋"),
    ("ken", "肯啃恳垦"),
    ("keng", "坑吭铿"),
    ("kong", "空控孔恐腔"),
    ("kou", "口扣抠寇叩"),
    ("ku", "苦哭库裤酷枯窟"),
    ("kua", "跨夸垮挎胯"),
    ("kuai", "快块筷会狡"),
    ("kuan", "宽款髋"),
    ("kuang", "况框矿狂旷筐眶"),
    ("kui", "亏愧魁窥溃葵盔"),
    ("kun", "困昆捆坤鲲"),
    ("kuo", "扩括阔廓"),
    ("la", "拉啦辣腊蜡喇垃圾"),
    ("lai", "来赖莱徕癞"),
    ("lan", "蓝拦篮懒烂兰览缆"),
    ("lang", "浪狼郎廊朗榔"),
    ("lao", "老劳牢捞涝姥酪"),
    ("le", "了乐勒肋"),
    ("lei", "类累雷泪垒勒蕾"),
    ("leng", "冷愣棱"),
    ("li", "里理力离立利礼历"),
    ("lia", "俩"),
    ("lian", "连脸练联恋怜镰链"),
    ("liang", "两亮量凉良辆粮梁"),
    ("liao", "了料聊疗辽僚寥"),
    ("lie", "列裂猎劣烈咧"),
    ("lin", "林临邻淋麟磷吝"),
    ("ling", "另领零灵铃龄岭凌"),
    ("liu", "六留流刘柳溜硫瘤"),
    ("lo", "咯"),
    ("long", "龙弄笼聋隆拢垄"),
    ("lou", "楼漏露搂陋篓"),
    ("lu", "路录陆露炉鹿卢碌"),
    ("luan", "乱卵峦孪滦"),
    ("lue", "略掠"),
    ("lun", "论轮伦沦抡仑"),
    ("luo", "落罗络逻辑裸锣骡"),
    ("lv", "率绿旅律虑履氯驴"),
    ("ma", "吗妈马嘛麻骂码抹"),
    ("mai", "买卖麦迈脉埋"),
    ("man", "满慢漫瞒蛮曼馒"),
    ("mang", "忙盲茫芒莽蟒"),
    ("mao", "毛猫冒帽矛貌茂锚"),
    ("me", "么麽"),
    ("mei", "没美每煤梅媒酶霉"),
    ("men", "们门闷扪焖"),
    ("meng", "梦猛蒙盟懵萌孟"),
    ("mi", "米密迷秘蜜谜弥觅"),
    ("mian", "面棉免眠绵勉缅"),
    ("miao", "秒苗庙妙描瞄渺"),
    ("mie", "灭蔑篾咩"),
    ("min", "民敏皿闽悯抿"),
    ("ming", "名明命鸣铭冥茗"),
    ("miu", "谬缪"),
    ("mo", "摸磨模末墨默莫膜"),
    ("mou", "某谋牟眸"),
    ("mu", "目木母亩幕墓牧慕"),
    ("na", "那拿哪纳娜钠呐"),
    ("nai", "奶耐奈乃氖"),
    ("nan", "难男南楠喃囡"),
    ("nang", "囊囔馕"),
    ("nao", "脑闹恼挠瑙淖"),
    ("ne", "呢哪呐"),
    ("nei", "内馁"),
    ("nen", "嫩恁"),
    ("neng", "能"),
    ("ni", "你泥拟逆呢尼匿腻昵"),
    ("nian", "年念粘捻碾廿黏"),
    ("niang", "娘酿"),
    ("niao", "鸟尿袅脲"),
    ("nie", "捏孽聂镊镍涅"),
    ("nin", "您恁"),
    ("ning", "宁凝拧柠泞狞"),
    ("niu", "牛扭纽钮拗"),
    ("nong", "弄农浓脓侬"),
    ("nou", "耨"),
    ("nu", "怒努奴弩驽"),
    ("nuan", "暖"),
    ("nue", "虐疟"),
    ("nuo", "诺挪懦糯娜"),
    ("nv", "女钕恧"),
    ("o", "哦喔噢"),
    ("ou", "偶欧呕鸥藕沤"),
    ("pa", "怕爬趴啪帕琶葩"),
    ("pai", "派排拍牌迫徘湃"),
    ("pan", "盘判盼攀叛畔潘"),
    ("pang", "旁胖耪庞螃"),
    ("pao", "跑泡炮抛袍咆疱"),
    ("pei", "配陪培赔佩坯沛"),
    ("pen", "喷盆湓"),
    ("peng", "朋碰棚捧蓬膨烹"),
    ("pi", "批皮披匹脾疲屁劈"),
    ("pian", "片篇骗偏便扁翩"),
    ("piao", "票飘漂瓢朴嫖"),
    ("pie", "撇瞥苤"),
    ("pin", "品拼贫频聘嫔"),
    ("ping", "平瓶评凭苹屏乒"),
    ("po", "破坡泼婆迫泊魄颇"),
    ("pou", "剖裒"),
    ("pu", "铺普扑葡蒲朴堡曝"),
    ("qi", "起其七期气器奇企齐"),
    ("qia", "恰掐洽卡"),
    ("qian", "前钱千签浅欠潜迁"),
    ("qiang", "强枪墙抢腔蔷锵"),
    ("qiao", "桥悄敲巧翘壳侨撬"),
    ("qie", "切且窃茄怯锲"),
    ("qin", "亲琴侵勤钦擒寝"),
    ("qing", "请轻清情青晴庆倾"),
    ("qiong", "穷琼穹"),
    ("qiu", "求球秋丘囚趋蚯"),
    ("qu", "去取区曲趣驱屈渠"),
    ("quan", "全权劝圈泉犬券醛"),
    ("que", "却缺确雀瘸鹊榷"),
    ("qun", "群裙逡"),
    ("ran", "然染燃冉髯"),
    ("rang", "让嚷壤攘瓤"),
    ("rao", "绕扰饶娆"),
    ("re", "热惹喏"),
    ("ren", "人认任忍刃仁韧妊"),
    ("reng", "仍扔"),
    ("ri", "日"),
    ("rong", "容融荣绒溶熔戎"),
    ("rou", "肉柔揉蹂鞣"),
    ("ru", "如入乳辱儒濡蠕"),
    ("ruan", "软阮朊"),
    ("rui", "瑞锐蕊睿蚋"),
    ("run", "润闰"),
    ("ruo", "若弱偌箬"),
    ("sa", "撒洒萨飒卅"),
    ("sai", "赛塞腮鳃噻"),
    ("san", "三散伞叁糁"),
    ("sang", "桑嗓丧搡"),
    ("sao", "扫嫂骚臊梢"),
    ("se", "色涩瑟塞啬"),
    ("sen", "森"),
    ("seng", "僧"),
    ("sha", "杀沙啥傻纱刹砂鲨"),
    ("shai", "晒筛色骰"),
    ("shan", "山闪衫善扇删杉珊"),
    ("shang", "上商伤尚赏裳晌"),
    ("shao", "少烧稍哨勺梢韶"),
    ("she", "设社射蛇舌舍涉摄"),
    ("shei", "谁"),
    ("shen", "什身深神审甚伸慎"),
    ("sheng", "生声省升胜剩绳圣"),
    ("shi", "是时十事市实使世试"),
    ("shou", "手受收首守瘦授兽"),
    ("shu", "书数树输属术熟署鼠"),
    ("shua", "刷耍唰"),
    ("shuai", "摔帅甩衰率"),
    ("shuan", "拴栓涮闩"),
    ("shuang", "双爽霜孀"),
    ("shui", "水睡谁税说"),
    ("shun", "顺瞬吮舜"),
    ("shuo", "说硕烁朔勺"),
    ("si", "四死丝司思斯撕私寺"),
    ("song", "送松耸宋讼诵嵩"),
    ("sou", "搜艘嗽擞馊"),
    ("su", "速素苏俗塑宿肃粟"),
    ("suan", "算酸蒜狻"),
    ("sui", "随岁碎虽穗遂髓"),
    ("sun", "孙损笋隼"),
    ("suo", "所缩锁索琐梭唆"),
    ("ta", "他她它踏塔塌榻獭"),
    ("tai", "太台态抬胎泰苔汰"),
    ("tan", "谈弹探滩贪摊炭坦"),
    ("tang", "汤糖堂躺趟烫塘膛"),
    ("tao", "套讨逃桃掏淘涛陶"),
    ("te", "特忑慝铽"),
    ("teng", "疼腾藤誊滕"),
    ("ti", "提题体替踢梯惕剔"),
    ("tian", "天田填甜添舔恬"),
    ("tiao", "条跳挑调迢笤"),
    ("tie", "铁贴帖餮"),
    ("ting", "听停挺厅亭艇廷霆"),
    ("tong", "同通统痛铜桶筒童"),
    ("tou", "头投偷透骰"),
    ("tu", "图土突途涂吐兔徒"),
    ("tuan", "团湍疃抟"),
    ("tui", "推退腿蜕颓褪"),
    ("tun", "吞屯臀豚囤"),
    ("tuo", "拖脱托妥陀驼拓唾"),
    ("wa", "挖哇蛙瓦娃袜凹"),
    ("wai", "外歪崴"),
    ("wan", "完万晚碗玩弯湾丸"),
    ("wang", "往王望网忘亡旺汪"),
    ("wei", "为位未围喂微味维卫"),
    ("wen", "问文闻稳温吻蚊纹"),
    ("weng", "翁嗡瓮"),
    ("wo", "我握窝卧沃涡蜗"),
    ("wu", "无五物务屋误舞污伍"),
    ("xi", "西系习洗细吸喜席析"),
    ("xia", "下夏吓瞎虾匣辖峡"),
    ("xian", "先现线限显险鲜县献"),
    ("xiang", "想向象项响香乡箱相"),
    ("xiao", "小笑校消效销晓肖削"),
    ("xie", "写些谢鞋斜血协泄蟹"),
    ("xin", "新心信辛欣薪锌衅"),
    ("xing", "行型星兴性醒姓刑幸"),
    ("xiong", "兄胸雄凶熊汹"),
    ("xiu", "修休秀袖锈羞嗅绣"),
    ("xu", "需许续序虚须畜絮蓄"),
    ("xuan", "选宣悬旋玄轩喧绚"),
    ("xue", "学雪血削穴靴薛"),
    ("xun", "寻训讯迅循旬勋熏"),
    ("ya", "呀压牙押鸭雅亚崖"),
    ("yan", "眼言严演烟盐研延验"),
    ("yang", "样阳养羊洋仰央痒"),
    ("yao", "要药摇咬腰邀耀窑"),
    ("ye", "也夜业叶野爷页液"),
    ("yi", "一以已意议义益易医"),
    ("yin", "因音引银印饮阴隐瘾"),
    ("ying", "应影硬营迎映鹰赢颖"),
    ("yo", "哟唷"),
    ("yong", "用永勇拥涌泳庸踊"),
    ("you", "有又由友右油游优幼"),
    ("yu", "与于鱼雨语育遇域预"),
    ("yuan", "远原员元院圆愿源缘"),
    ("yue", "月越约跃阅乐岳悦"),
    ("yun", "云运允晕韵孕匀陨"),
    ("za", "杂砸咋匝扎"),
    ("zai", "在再载灾栽宰崽"),
    ("zan", "咱赞暂攒錾"),
    ("zang", "脏葬藏赃臧"),
    ("zao", "早造糟澡燥灶枣躁"),
    ("ze", "则责择泽咋啧"),
    ("zei", "贼"),
    ("zen", "怎谮"),
    ("zeng", "增曾赠憎综"),
    ("zha", "扎炸渣闸眨榨诈铡"),
    ("zhai", "摘窄债斋寨宅"),
    ("zhan", "站展战占粘斩盏栈"),
    ("zhang", "张长涨章丈帐掌障"),
    ("zhao", "找着照招罩爪赵朝"),
    ("zhe", "这着者折哲遮浙蔗"),
    ("zhei", "这"),
    ("zhen", "真针阵镇振震珍枕"),
    ("zheng", "正整政争证症挣蒸"),
    ("zhi", "之只知直制指支治值"),
    ("zhong", "中种重众钟终忠肿"),
    ("zhou", "周州洲粥舟轴昼骤"),
    ("zhu", "主住注助猪竹煮筑柱"),
    ("zhua", "抓爪"),
    ("zhuai", "拽转"),
    ("zhuan", "转专砖赚撰篆"),
    ("zhuang", "装状撞庄壮桩妆"),
    ("zhui", "追坠缀锥赘"),
    ("zhun", "准谆屯"),
    ("zhuo", "捉桌着啄拙灼浊"),
    ("zi", "子自字资紫仔姿滋咨"),
    ("zong", "总纵宗踪棕鬃综"),
    ("zou", "走奏揍邹诹"),
    ("zu", "组足族租阻祖诅卒"),
    ("zuan", "钻纂攥"),
    ("zui", "最嘴醉罪堆"),
    ("zun", "尊遵樽鳟"),
    ("zuo", "做作坐左座昨佐琢"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syllables_table_is_strictly_sorted() {
        for pair in SYLLABLES.windows(2) {
            assert!(
                pair[0].0 < pair[1].0,
                "SYLLABLES out of order: {} >= {}",
                pair[0].0,
                pair[1].0
            );
        }
    }

    #[test]
    fn nihao_returns_exact_expected_candidates_and_commits() {
        let ime = RimeIme::new();
        let reply = ime.compose("nihao", None, None, false);
        assert_eq!(reply.preedit, "ni'hao");
        assert_eq!(
            &reply.candidates[..5],
            &["你好", "拟好", "泥好", "你号", "昵好"]
        );

        let commit = ime.compose("nihao", Some(0), None, false);
        assert_eq!(commit.committed.as_deref(), Some("你好"));
        assert!(commit.raw.is_empty());
    }

    #[test]
    fn double_pinyin_toggles_and_decodes_nihao() {
        let ime = RimeIme::new();
        // Toggle to double_pinyin and compose "nihc" (ni + h'ao) -> ni'hao -> 你好!
        let reply = ime.compose("nihc", None, None, true);
        assert_eq!(reply.schema, ImeSchema::DoublePinyin);
        assert_eq!(reply.preedit, "ni'hao");
        assert!(reply.candidates.contains(&"你好".to_string()));
    }

    #[test]
    fn page_delta_is_clamped_and_bounded_to_valid_last_page() {
        let ime = RimeIme::new();
        let first = ime.compose("nihao", None, None, false);
        assert_eq!(first.page, 0);
        let far = ime.compose("nihao", None, Some(10_000), false);
        assert!(far.page <= 16, "page must stay bounded, got {}", far.page);
        assert!(!far.has_more);
        let back = ime.compose("nihao", None, Some(-10_000), false);
        assert_eq!(back.page, 0);
    }

    #[test]
    fn concurrent_rime_instances_create_and_drop_cleanly() {
        let a = RimeIme::new();
        let b = RimeIme::new();
        let ra = a.compose("nihao", None, None, false);
        drop(a);
        let rb = b.compose("nihao", None, None, false);
        assert!(!ra.candidates.is_empty());
        assert!(!rb.candidates.is_empty());
    }

    #[test]
    fn new_starts_lazy_without_loading_librime() {
        let ime = RimeIme::new();
        assert_eq!(ime.status().engine, ImeEngine::Builtin);
        assert_eq!(ime.status().schema, ImeSchema::PinyinSimp);
        #[cfg(target_os = "linux")]
        assert!(matches!(
            ime.inner.lock().unwrap().librime,
            LazyRime::Unchecked
        ));

        // Empty compose and schema toggle without input should remain lazy.
        let empty = ime.compose("", None, None, true);
        assert!(empty.candidates.is_empty());
        assert_eq!(empty.schema, ImeSchema::DoublePinyin);
        assert_eq!(ime.status().engine, ImeEngine::Builtin);
        #[cfg(target_os = "linux")]
        assert!(matches!(
            ime.inner.lock().unwrap().librime,
            LazyRime::Unchecked
        ));
    }
}
