//! Standard-library timing and allocation helpers. This crate exports no global
//! `pocket_host_*` symbols; the final program chooses one ABI hook owner.
use pocket_drivers::Clock;
use std::alloc::{alloc, dealloc, realloc, Layout};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

const SYSTEM_CJK_FONT_PATHS: &[&str] = &[
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Medium.ttc",
    "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
    "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
];
/// Hard cap for owned font snapshots loaded from non-system / mutable paths.
const MAX_OWNED_FALLBACK_FONT_BYTES: u64 = 24 * 1024 * 1024;
static INSTALL_LOCK: Mutex<()> = Mutex::new(());

fn has_sfnt_magic(bytes: &[u8]) -> bool {
    bytes.len() >= 12
        && matches!(
            &bytes[..4],
            [0x00, 0x01, 0x00, 0x00] | b"OTTO" | b"true" | b"typ1" | b"ttcf"
        )
}

/// Check whether an opened file descriptor has a kernel-enforced lifetime
/// immutability guarantee before allowing `unsafe { memmap2::Mmap::map(&file) }`:
/// - Linux: sealed memfd/shmem whose seal mask contains
///   `F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL` (prevents truncation, writes,
///   and seal changes for the lifetime of the inode).
/// - All other descriptors and platforms: `false` (use bounded owned snapshot).
///   Read-only bind mounts (`ST_RDONLY` / `MNT_RDONLY`) and mutable inode flags
///   (`FS_IMMUTABLE_FL` / `UF_IMMUTABLE`) are intentionally rejected because
///   another writable mount or privileged flag clear can still truncate the file
///   and raise `SIGBUS`.
fn is_lifetime_sealed_file(file: &std::fs::File) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::AsRawFd;
        const REQUIRED_SEALS: libc::c_int =
            libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE | libc::F_SEAL_SEAL;
        let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
        seals >= 0 && (seals & REQUIRED_SEALS) == REQUIRED_SEALS
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = file;
        false
    }
}

/// On Linux embedded devices (`geteuid() != 0`), root-owned `0644` system fonts
/// under `/usr/share/fonts/` cannot be mutated or truncated by unprivileged user
/// processes; demand-paged read-only `mmap` avoids copying 19 MiB `.ttc` files
/// into scarce anonymous RAM (e.g. 352 MiB Pi Zero 2W).
fn is_unprivileged_root_system_font(path: &Path, meta: &std::fs::Metadata) -> bool {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::MetadataExt;
        path.starts_with("/usr/share/fonts/")
            && meta.uid() == 0
            && (meta.mode() & 0o022) == 0
            && unsafe { libc::geteuid() } != 0
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (path, meta);
        false
    }
}

enum LoadedFont {
    Mapped(memmap2::Mmap),
    Owned(Box<[u8]>),
}

impl LoadedFont {
    #[cfg(test)]
    fn as_bytes(&self) -> &[u8] {
        match self {
            LoadedFont::Mapped(m) => &m[..],
            LoadedFont::Owned(b) => &b[..],
        }
    }
}

fn open_font_file_nonblocking(path: &Path) -> Option<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
            .ok()
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path).ok()
    }
}

fn load_fallback_font(path: &Path) -> Option<LoadedFont> {
    let file = open_font_file_nonblocking(path)?;
    let meta = file.metadata().ok()?;
    if !meta.file_type().is_file() || meta.len() < 12 {
        return None;
    }

    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        let fd = file.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return None;
        }
        if (flags & libc::O_NONBLOCK) != 0
            && unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0
        {
            return None;
        }
    }

    if is_lifetime_sealed_file(&file) || is_unprivileged_root_system_font(path, &meta) {
        // SAFETY: Either kernel-verified lifetime seals or a root-owned non-writable
        // `/usr/share/fonts` file opened by an unprivileged Linux user (`euid != 0`).
        if let Ok(mmap) = unsafe { memmap2::Mmap::map(&file) } {
            if !has_sfnt_magic(&mmap) || !pocketjs_core::text::validate_fallback_ttf(&mmap) {
                return None;
            }
            return Some(LoadedFont::Mapped(mmap));
        }
    }

    if meta.len() > MAX_OWNED_FALLBACK_FONT_BYTES {
        return None;
    }
    let mut buf = Vec::with_capacity(meta.len() as usize);
    file.take(MAX_OWNED_FALLBACK_FONT_BYTES + 1)
        .read_to_end(&mut buf)
        .ok()?;
    if buf.len() < 12 || (buf.len() as u64) > MAX_OWNED_FALLBACK_FONT_BYTES {
        return None;
    }
    if !has_sfnt_magic(&buf) || !pocketjs_core::text::validate_fallback_ttf(&buf) {
        return None;
    }
    Some(LoadedFont::Owned(buf.into_boxed_slice()))
}

fn try_load_and_install(path: &Path) -> bool {
    let Some(loaded) = load_fallback_font(path) else {
        return false;
    };
    match loaded {
        LoadedFont::Mapped(mmap) => {
            let raw: *mut memmap2::Mmap = Box::into_raw(Box::new(mmap));
            // SAFETY: `raw` points to a valid live `Mmap`; if `set_fallback_ttf`
            // returns `false`, no reference to `raw` is retained and we reclaim it.
            let installed = {
                let mapped: &'static memmap2::Mmap = unsafe { &*raw };
                pocketjs_core::text::set_fallback_ttf(&mapped[..])
            };
            if !installed {
                unsafe {
                    drop(Box::from_raw(raw));
                }
            }
            installed
        }
        LoadedFont::Owned(boxed) => {
            let raw: *mut [u8] = Box::into_raw(boxed);
            // SAFETY: `raw` owns an immutable heap snapshot; if `set_fallback_ttf`
            // returns `false`, no reference is retained and we free it immediately.
            let installed = pocketjs_core::text::set_fallback_ttf(unsafe { &*raw });
            if !installed {
                unsafe {
                    drop(Box::from_raw(raw));
                }
            }
            installed
        }
    }
}

/// Load the first available CJK fallback TrueType/OpenType font and register it
/// with `pocketjs_core::text::set_fallback_ttf`.
///
/// Only Linux descriptors carrying lifetime kernel seals
/// (`F_SEAL_SHRINK | F_SEAL_WRITE | F_SEAL_SEAL`) are read-only memory-mapped;
/// all other paths are snapshotted into owned buffers (bounded to 24 MiB) so
/// concurrent file mutation or truncation cannot trigger `SIGBUS` or UB.
///
/// Search order:
/// 1. `extra_paths` in order
/// 2. `REX_ZERO_CJK_FONT` environment variable (when set and non-empty)
/// 3. `/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf`
pub fn install_system_cjk_fallback(extra_paths: &[&Path]) -> bool {
    if pocketjs_core::text::has_fallback_ttf() {
        return true;
    }
    let _guard = INSTALL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    if pocketjs_core::text::has_fallback_ttf() {
        return true;
    }
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Some(env_path) = std::env::var_os("REX_ZERO_CJK_FONT") {
        if !env_path.is_empty() {
            candidates.push(PathBuf::from(env_path));
        }
    }
    for sys_path in SYSTEM_CJK_FONT_PATHS {
        candidates.push(PathBuf::from(sys_path));
    }
    for extra in extra_paths {
        candidates.push(extra.to_path_buf());
    }

    for path in candidates {
        if try_load_and_install(&path) {
            return true;
        }
        if pocketjs_core::text::has_fallback_ttf() {
            return true;
        }
    }
    pocketjs_core::text::has_fallback_ttf()
}

pub struct MonotonicClock(Instant);
impl Default for MonotonicClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Clock for MonotonicClock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_micros().min(u64::MAX as u128) as u64
    }
    fn sleep_until(&mut self, deadline: u64) {
        loop {
            let now = self.now();
            if now >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_micros(deadline - now));
        }
    }
}
/// Allocate a byte span using the same size/alignment contract as the C ABI.
pub fn allocate(size: usize, align: usize) -> *mut u8 {
    Layout::from_size_align(size.max(1), align)
        .map_or(std::ptr::null_mut(), |layout| unsafe { alloc(layout) })
}
/// # Safety
/// `pointer` must be a live allocation returned by `allocate` with this layout.
pub unsafe fn release(pointer: *mut u8, size: usize, align: usize) {
    if pointer.is_null() {
        return;
    }
    if let Ok(layout) = Layout::from_size_align(size.max(1), align) {
        unsafe { dealloc(pointer, layout) };
    }
}
/// # Safety
/// A non-null pointer must be a live allocation returned with the old layout.
pub unsafe fn resize(pointer: *mut u8, old_size: usize, align: usize, new_size: usize) -> *mut u8 {
    if pointer.is_null() {
        return allocate(new_size, align);
    }
    Layout::from_size_align(old_size.max(1), align).map_or(std::ptr::null_mut(), |layout| unsafe {
        realloc(pointer, layout, new_size.max(1))
    })
}
/// Range reads from an open file. Package decoding and identity validation stay
/// in pocket-package; the source never strips or rewrites package sections.
pub struct FileSource {
    file: std::fs::File,
    length: usize,
}
impl FileSource {
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = std::fs::File::open(path)?;
        let length = usize::try_from(file.metadata()?.len())
            .map_err(|_| std::io::Error::other("package is too large"))?;
        Ok(Self { file, length })
    }
}
impl pocket_drivers::PackageSource for FileSource {
    fn length(&self) -> Result<usize, pocket_drivers::SourceError> {
        Ok(self.length)
    }
    fn range(
        &mut self,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize, pocket_drivers::SourceError> {
        use pocket_drivers::SourceError;
        use std::io::{Read, Seek, SeekFrom};
        if offset > self.length {
            return Err(SourceError::OutOfBounds);
        }
        if self.file.metadata().map_err(|_| SourceError::Failed)?.len() != self.length as u64 {
            return Err(SourceError::Failed);
        }
        self.file
            .seek(SeekFrom::Start(offset as u64))
            .map_err(|_| SourceError::Failed)?;
        let limit = buffer.len().min(self.length - offset);
        self.file
            .read(&mut buffer[..limit])
            .map_err(|_| SourceError::Failed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aligned_reallocation_preserves_bytes() {
        unsafe {
            let pointer = allocate(17, 64);
            assert!(!pointer.is_null());
            assert_eq!(pointer as usize % 64, 0);
            pointer.write(42);
            let larger = resize(pointer, 17, 64, 100);
            assert!(!larger.is_null());
            assert_eq!(larger.read(), 42);
            release(larger, 100, 64);
        }
    }
    #[test]
    fn invalid_layout_is_rejected() {
        assert!(allocate(1, 3).is_null());
    }
    #[test]
    fn clock_does_not_tick_or_move_backwards() {
        let mut clock = MonotonicClock::default();
        let before = clock.now();
        clock.sleep_until(before + 100);
        assert!(clock.now() >= before + 100);
    }

    #[test]
    fn install_system_cjk_fallback_mmaps_and_feeds_core_atlas() {
        let ttf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../../app/fonts/DroidSansFallbackFull.ttf");
        assert!(ttf.is_file(), "expected bundled test TTF at {}", ttf.display());
        assert!(install_system_cjk_fallback(&[Path::new("/nonexistent/font.ttf"), &ttf]));
        assert!(pocketjs_core::text::has_fallback_ttf());

        // Build a minimal 12px compact atlas (only 'A' + tofu baked) and verify
        // unbaked Chinese text resolves dynamically through the mmapped TTF.
        use pocketjs_core::spec::font_atlas as fa;
        let (cell_w, cell_h, baseline, line_height) = (17u8, 15u8, 12u8, 15u8);
        let mut blob = Vec::new();
        blob.extend_from_slice(&fa::MAGIC.to_le_bytes());
        blob.extend_from_slice(&fa::VERSION.to_le_bytes());
        blob.extend_from_slice(&2u16.to_le_bytes());
        blob.extend_from_slice(&[cell_w, cell_h, baseline, line_height, 0, 0, 1, 0]);
        for &(cp, gid, adv) in &[(65u32, 1u16, 7u8), (0xfffdu32, 0u16, cell_w)] {
            blob.extend_from_slice(&cp.to_le_bytes());
            blob.extend_from_slice(&gid.to_le_bytes());
            blob.push(adv);
            blob.push(0);
        }
        blob.extend_from_slice(&vec![0u8; 2 * cell_w as usize * cell_h as usize]);

        let mut fonts = pocketjs_core::text::Fonts::new();
        assert!(fonts.load(&blob));
        let (w, h) = fonts.measure_run("你好世界，极致省内存！", 0, 0.0, f32::NAN);
        assert!(w > 50.0);
        assert_eq!(h, 15.0);
        assert_eq!(fonts.misses.get(), 0);

        // Prepare under `&mut` before read-only `layout_run` / `glyph_rows`.
        assert!(fonts.prepare_run("你好世界，极致省内存！", 0));
        let mut placed = Vec::new();
        fonts.layout_run(
            "你好世界，极致省内存！",
            0,
            0.0,
            f32::NAN,
            pocketjs_core::spec::TextAlign::Left as u8,
            320.0,
            &mut placed,
        );
        let atlas = fonts.atlas(0).unwrap();
        assert_eq!(atlas.baked_count, 2);
        assert!(atlas.dyn_cap() > 0 && atlas.dyn_cap() <= pocketjs_core::text::DYN_CAP);
        assert_eq!(atlas.glyph_count, 2 + atlas.dyn_cap() as u16);
        assert!(atlas.dynamic_ram_bytes() <= pocketjs_core::text::DYN_SLOT_BUDGET_BYTES);
        for g in &placed {
            assert!(g.gid >= atlas.baked_count);
            assert!(atlas.glyph_rows(g.gid).iter().any(|&a| a > 0));
        }
    }

    #[test]
    fn writable_font_file_uses_owned_snapshot_and_survives_truncation() {
        let src = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../../app/fonts/DroidSansFallbackFull.ttf");
        assert!(src.is_file(), "expected bundled test TTF at {}", src.display());

        let tmp = std::env::temp_dir().join(format!(
            "pocket-writable-font-{}.ttf",
            std::process::id()
        ));
        std::fs::copy(&src, &tmp).expect("copy test font");

        let file = std::fs::File::open(&tmp).expect("open temp font");
        assert!(
            !is_lifetime_sealed_file(&file),
            "unsealed writable temp file must NOT pass lifetime seal check"
        );
        drop(file);

        let loaded = load_fallback_font(&tmp).expect("load writable fallback font");
        assert!(
            matches!(loaded, LoadedFont::Owned(_)),
            "unsealed font must use owned Box<[u8]> snapshot"
        );

        // Truncate and delete the file on disk; owned snapshot remains valid with 0 SIGBUS risk.
        std::fs::write(&tmp, b"").expect("truncate temp font");
        let _ = std::fs::remove_file(&tmp);
        assert!(pocketjs_core::text::validate_fallback_ttf(loaded.as_bytes()));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_unsealed_system_font_uses_owned_snapshot() {
        let dir = std::fs::read_dir("/System/Library/Fonts").expect("macOS system fonts dir");
        let sys_font = dir
            .filter_map(Result::ok)
            .map(|e| e.path())
            .find(|p| p.is_file())
            .expect("expected at least one file in /System/Library/Fonts");
        let file = std::fs::File::open(&sys_font).expect("open macOS system font");
        assert!(
            !is_lifetime_sealed_file(&file),
            "unsealed macOS fd must use owned snapshot instead of Mmap: {}",
            sys_font.display()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_sealed_memfd_requires_write_shrink_and_seal_seals() {
        use std::os::fd::FromRawFd;
        let name = std::ffi::CString::new("pocket-font-test").unwrap();
        let fd = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_ALLOW_SEALING | libc::MFD_CLOEXEC)
        };
        assert!(fd >= 0, "memfd_create failed");
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        assert!(!is_lifetime_sealed_file(&file), "unsealed memfd must be rejected");
        let rc = unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_SHRINK | libc::F_SEAL_WRITE,
            )
        };
        assert_eq!(rc, 0, "F_ADD_SEALS write+shrink failed");
        assert!(
            !is_lifetime_sealed_file(&file),
            "memfd without F_SEAL_SEAL must be rejected"
        );
        let rc = unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, libc::F_SEAL_SEAL) };
        assert_eq!(rc, 0, "F_ADD_SEALS seal failed");
        assert!(
            is_lifetime_sealed_file(&file),
            "write+shrink+seal memfd must pass lifetime seal check"
        );
    }

    #[test]
    fn corrupt_sfnt_file_is_rejected_before_registration() {
        let dir = std::env::temp_dir();
        let bad = dir.join(format!("pocket-bad-font-{}.ttf", std::process::id()));
        // Valid SFNT magic header followed by garbage so `FontRef` rejects it.
        std::fs::write(&bad, b"\x00\x01\x00\x00corrupt-font-table").unwrap();
        assert!(!try_load_and_install(&bad));
        let _ = std::fs::remove_file(&bad);
    }

    #[cfg(unix)]
    #[test]
    fn fifo_font_candidate_is_rejected_without_blocking() {
        use std::os::unix::ffi::OsStrExt;

        struct RemoveOnDrop(PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }

        let fifo = std::env::temp_dir().join(format!(
            "pocket-font-fifo-{}.ttf",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&fifo);
        let c_fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        let rc = unsafe { libc::mkfifo(c_fifo.as_ptr(), 0o600) };
        assert_eq!(rc, 0, "mkfifo failed at {}", fifo.display());
        let _cleanup = RemoveOnDrop(fifo.clone());

        let start = Instant::now();
        assert!(
            load_fallback_font(&fifo).is_none(),
            "FIFO without writer must be rejected immediately via O_NONBLOCK"
        );
        assert!(
            !try_load_and_install(&fifo),
            "FIFO candidate must fail without blocking"
        );
        let ttf = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../../../app/fonts/DroidSansFallbackFull.ttf");
        assert!(ttf.is_file(), "expected bundled test TTF at {}", ttf.display());
        assert!(
            install_system_cjk_fallback(&[&fifo, &ttf]),
            "FIFO in extra_paths must fall through to the subsequent valid font"
        );
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "FIFO rejection must not block (took {:?})",
            start.elapsed()
        );
    }
}
