//! The M5Stack CardputerZero program: one package on the 320x170 panel
//! (fbdev, RGB565), the keyboard as buttons and as text keys (evdev, with the
//! Zero's symbol layer from keymap.rs), and the package's worker domain
//! (worker.rs), whose `http` node reaches this machine (http.rs): Pocket
//! Companion's control API, and the device API (device/) under
//! `http://zero/dev/`: sensors, radios, microphone, camera and infrared as
//! JSON. The camera's live picture is the runtime's video plane (video.rs),
//! so its frames never cross JavaScript. Pocket Companion's own screen
//! (apps/companion-zero) and Pocket Tools (pocket-nexus/pocket-zero-tools)
//! run on it.
//!
//! `--shot DIR --script "…"` runs the same program on any system without the
//! panel and keyboard: a scripted button and key source and an in-memory
//! RGB565 framebuffer of the panel's geometry, written to DIR/<tick>.rgb565
//! at each `shot` event (shot.rs). `--mock` answers the device API from
//! synthesized readings (device/mock.rs).
use pocket_drivers::{Clock, InputClasses};
use pocket_guest_rquickjs::RquickjsGuest;
use pocket_linux_hooks::{FileSource, MonotonicClock};
use pocket_package::source::LoadedPackage;
use pocket_runtime::{
    timing::TickSchedule, Guest, GuestEnvironment, GuestFrame, OpContext, Runtime, RuntimeConfig,
    RuntimeError,
};
use std::{
    error::Error,
    io,
    os::fd::AsRawFd,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

mod device;
mod http;
mod keymap;
mod rex;
mod shot;
mod video;
mod worker;

#[allow(dead_code)] // The export defines every fact; the program reads some.
mod profile {
    include!(concat!(env!("OUT_DIR"), "/pocket_profile.rs"));
}

const PACKAGE_LIMIT: usize = 16 * 1024 * 1024;
const DEFAULT_PACKAGE: &str = "/usr/share/pocketjs/companion.pocket";
const DEFAULT_CONTROL: &str = "/opt/pocket/store/control.json";
/// `auto` picks the codec card by name (device/linux.rs `pcm_device`).
const DEFAULT_AUDIO_DEVICE: &str = "auto";

static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn stop(_: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
fn error(value: impl std::fmt::Debug) -> io::Error {
    io::Error::other(format!("{value:?}"))
}

#[derive(Default)]
struct Options {
    package: Option<PathBuf>,
    fb: Option<PathBuf>,
    inputs: Vec<PathBuf>,
    control: Option<PathBuf>,
    unit: Option<String>,
    shot: Option<PathBuf>,
    script: Option<String>,
    store: Option<PathBuf>,
    audio_device: Option<String>,
    mock: bool,
    connect_local: bool,
    check: bool,
}

/// Where the device layer keeps an application's files (calibration, saved
/// signals, recordings, photos, the guest's store) when `--store` names no
/// directory: `$XDG_CONFIG_HOME` or `~/.config`, then the package file's
/// name without its extension, as the CardputerZero's application guidelines
/// ask (`$HOME/.config/<app>/`).
fn default_store(package: &std::path::Path) -> PathBuf {
    let name = package.file_stem().map(|stem| stem.to_string_lossy().into_owned()).unwrap_or_else(|| "pocket".into());
    let config = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")));
    match config {
        Some(config) => config.join(name),
        None => PathBuf::from("/tmp").join(name),
    }
}

fn options() -> Result<Option<Options>, Box<dyn Error>> {
    let mut output = Options::default();
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" => {
                println!("pocket-cardputer-zero [--package app.pocket] [--fb /dev/fb0] [--input /dev/input/eventN] [--control control.json] [--unit pocket-companion.service]\n                     [--store DIR] [--audio-device NAME] [--mock] [--check]\n                     [--shot DIR --script \"30:DOWN 45:key:Enter 60:type:hello 90:shot\"]\nProfile {} is compiled in. Default package: {DEFAULT_PACKAGE}; default control file: {DEFAULT_CONTROL}; default store: ~/.config/<package name>. The program exits on SIGINT, SIGTERM, when the worker requests http://zero/quit, or after the script's last event.", profile::ID);
                return Ok(None);
            }
            "--check" => output.check = true,
            "--mock" => output.mock = true,
            "--connect-local" => output.connect_local = true,
            "--package" | "--fb" | "--input" | "--control" | "--unit" | "--shot" | "--script" | "--store" | "--audio-device" => {
                let value = args.next().ok_or_else(|| error("missing option value"))?;
                match arg.as_str() {
                    "--package" => output.package = Some(value.into()),
                    "--fb" => output.fb = Some(value.into()),
                    "--input" => output.inputs.push(value.into()),
                    "--control" => output.control = Some(value.into()),
                    "--unit" => output.unit = Some(value),
                    "--shot" => output.shot = Some(value.into()),
                    "--store" => output.store = Some(value.into()),
                    "--audio-device" => output.audio_device = Some(value),
                    _ => output.script = Some(value),
                }
            }
            _ => return Err(error(format!("unknown option {arg}")).into()),
        }
    }
    Ok(Some(output))
}

/// The rquickjs guest with the package's worker domain: the worker boots
/// after the UI realm and before the UI bundle evaluates, so its channels
/// exist when the bridge attaches; the bridge latches the worker's records
/// before every frame and detaches before the worker stops.
struct ZeroGuest {
    inner: RquickjsGuest,
    http: Arc<http::Http>,
    notify: Arc<worker::Notify>,
    bridge: *mut worker::Bridge,
    worker: Option<worker::Worker>,
}

impl ZeroGuest {
    fn fail(message: impl std::fmt::Display) -> RuntimeError {
        eprintln!("pocket-cardputer-zero: worker: {message}");
        RuntimeError::Guest
    }
    fn detach(&mut self) {
        if !self.bridge.is_null() {
            let bridge = std::mem::replace(&mut self.bridge, std::ptr::null_mut());
            self.inner
                .with(|_| unsafe { worker::pocket_worker_ui_detach(bridge) });
        }
    }
}

impl Guest for ZeroGuest {
    fn initialize(
        &mut self,
        ops: OpContext,
        environment: &GuestEnvironment<'_>,
    ) -> Result<(), RuntimeError> {
        self.shutdown();
        self.inner.initialize(ops, environment)?;
        if environment.worker_javascript.is_empty() {
            return Ok(());
        }
        let worker = worker::Worker::start(
            environment.worker_javascript,
            self.http.clone(),
            self.notify.clone(),
        )
        .map_err(Self::fail)?;
        let core = worker.core();
        self.worker = Some(worker);
        self.bridge = self
            .inner
            .with(|ctx| unsafe { worker::pocket_worker_ui_attach(ctx.as_raw().as_ptr(), core) })
            .unwrap_or(std::ptr::null_mut());
        if self.bridge.is_null() {
            return Err(Self::fail("channel bridge attachment failed"));
        }
        Ok(())
    }
    fn evaluate(&mut self, code: &[u8]) -> Result<(), RuntimeError> {
        self.inner.evaluate(code).inspect_err(|_| {
            if let Some(err) = self.inner.last_error() {
                eprintln!("pocket-cardputer-zero: guest evaluate: {err}");
            }
        })
    }
    fn frame(&mut self, frame: &GuestFrame<'_>) -> Result<(), RuntimeError> {
        if let Some(fault) = self.worker.as_ref().and_then(worker::Worker::fault) {
            return Err(Self::fail(fault));
        }
        if !self.bridge.is_null() {
            let bridge = self.bridge;
            let latched = self.inner.with(|ctx| {
                if unsafe { worker::pocket_worker_ui_latch(bridge) } >= 0 {
                    return Ok(());
                }
                let thrown = ctx.catch();
                Err(thrown
                    .as_exception()
                    .and_then(|exception| exception.message())
                    .unwrap_or_else(|| "channel latch failed".into()))
            });
            if let Some(Err(message)) = latched {
                return Err(Self::fail(message));
            }
        }
        self.inner.frame(frame).inspect_err(|_| {
            if let Some(err) = self.inner.last_error() {
                eprintln!("pocket-cardputer-zero: guest frame: {err}");
            }
        })
    }
    fn collect(&mut self) -> Result<(), RuntimeError> {
        self.inner.collect().inspect_err(|_| {
            if let Some(err) = self.inner.last_error() {
                eprintln!("pocket-cardputer-zero: guest collect: {err}");
            }
        })
    }
    fn shutdown(&mut self) {
        self.detach();
        self.worker = None;
        self.inner.shutdown()
    }
}

struct CleanupGuard {
    rex: Arc<rex::RexZeroEngine>,
    device: Option<device::Device>,
}

impl Drop for CleanupGuard {
    fn drop(&mut self) {
        self.rex.shutdown();
        // A microphone capture, a camera stream and a raised preamplifier must
        // not outlive the program — even if boot, tick, or shutdown fails.
        if let Some(device) = &self.device {
            device.stop();
        }
    }
}

fn hash_draw_words(words: &[u32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &w in words {
        h ^= w as u64;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

fn run(options: Options) -> Result<(), Box<dyn Error>> {
    let profile = profile::profile().ok_or_else(|| error("missing exported profile"))?;
    if profile.dynamic_viewport.is_some()
        || profile.auxiliary.is_some()
        || !(InputClasses::BUTTONS | InputClasses::TEXT).contains(profile.required_inputs)
    {
        return Err(error("profile promises facts this program cannot honor").into());
    }
    let size = profile.viewport;
    let path = options.package.unwrap_or_else(|| DEFAULT_PACKAGE.into());
    let mut source = FileSource::open(&path)?;
    if options.check {
        LoadedPackage::load(
            &mut source,
            profile::ID,
            profile::HOST_ABI,
            &profile::PROFILE_HASH,
            PACKAGE_LIMIT,
        )
        .map_err(error)?;
        println!("package admitted: {} ({})", path.display(), profile.id);
        return Ok(());
    }
    if pocket_drivers::PackageSource::length(&source).map_err(error)? > PACKAGE_LIMIT {
        return Err(error("package exceeds 16 MiB").into());
    }
    // Register on-demand CJK fallback TTF/TTC (`mmap`, 0 KB anonymous heap on cp0) before loading atlases.
    let pkg_noto = path
        .parent()
        .and_then(|p| p.parent())
        .map(|r| r.join("app/fonts/NotoSansCJKsc-Regular.otf"));
    let pkg_font = path
        .parent()
        .and_then(|p| p.parent())
        .map(|r| r.join("app/fonts/DroidSansFallbackFull.ttf"));
    let cwd_noto = PathBuf::from("app/fonts/NotoSansCJKsc-Regular.otf");
    let vendor_noto = PathBuf::from("../../app/fonts/NotoSansCJKsc-Regular.otf");
    let cwd_font = PathBuf::from("app/fonts/DroidSansFallbackFull.ttf");
    let vendor_font = PathBuf::from("../../app/fonts/DroidSansFallbackFull.ttf");
    let mut font_candidates: Vec<&std::path::Path> = Vec::new();
    if let Some(ref pn) = pkg_noto {
        font_candidates.push(pn.as_path());
    }
    font_candidates.push(cwd_noto.as_path());
    font_candidates.push(vendor_noto.as_path());
    if let Some(ref pf) = pkg_font {
        font_candidates.push(pf.as_path());
    }
    font_candidates.push(cwd_font.as_path());
    font_candidates.push(vendor_font.as_path());
    pocket_linux_hooks::install_system_cjk_fallback(&font_candidates);

    let mut runtime = Runtime::new(RuntimeConfig {
        profile_hash: profile::PROFILE_HASH,
        host_abi: profile::HOST_ABI,
        heap_limit: 24 * 1024 * 1024,
        frame_buffer_budget: size[0] as usize * size[1] as usize * 8,
        profile: profile.clone(),
    })
    .map_err(error)?;
    let ops = runtime.op_context();
    let renderer = runtime
        .add_renderer(pocket_raster::RasterRenderer::new(profile.density).map_err(error)?)
        .map_err(error)?;
    let headless = options.shot.is_some();
    let activity_seq = Arc::new(AtomicU64::new(1));
    let mut idle_evdev_watchers: Vec<std::fs::File> = Vec::new();
    let mut shot = match options.shot {
        Some(directory) => Some(shot::attach(
            &mut runtime,
            renderer,
            size,
            directory,
            options.script.as_deref().unwrap_or(""),
        )?),
        None => {
            idle_evdev_watchers = attach_devices(
                &mut runtime,
                renderer,
                &profile,
                options.fb,
                options.inputs,
                activity_seq.clone(),
            )?;
            None
        }
    };
    runtime
        .set_package_source(Box::new(source))
        .map_err(error)?;
    // The device layer runs when the program has the hardware (a Linux
    // machine, with or without the panel) or stands in for it with --mock;
    // a shot elsewhere keeps the API absent.
    let device = if options.mock || !headless || cfg!(target_os = "linux") {
        Some(device::Device::new(
            options.store.unwrap_or_else(|| default_store(&path)),
            options.mock,
            options.audio_device.unwrap_or_else(|| DEFAULT_AUDIO_DEVICE.into()),
        ))
    } else {
        None
    };
    if let Some(device) = &device {
        runtime
            .add_provider(Box::new(video::CameraPlane::new(device.clone())))
            .map_err(error)?;
    }
    let notify = Arc::new(worker::Notify::default());
    let (ui_wake_pipe, ui_waker) = rex::transport::WakePipe::new().map_err(error)?;
    let connect_local =
        options.connect_local || std::env::var_os("REX_ZERO_CONNECT_LOCAL").is_some();
    let rex_engine = if options.mock {
        Arc::new(rex::RexZeroEngine::new_mock(device.clone()))
    } else {
        Arc::new(rex::RexZeroEngine::new_live(
            device.clone(),
            headless,
            connect_local,
        ))
    };
    let cleanup = CleanupGuard {
        rex: rex_engine.clone(),
        device: device.clone(),
    };
    rex_engine.attach_ui_waker(activity_seq.clone(), ui_waker.clone());
    let http = Arc::new(
        http::Http::new(
            options.control.unwrap_or_else(|| DEFAULT_CONTROL.into()),
            options.unit.unwrap_or_else(|| http::COMPANION_UNIT.into()),
            notify.clone(),
            device,
        )
        .with_rex(rex_engine)
        .with_ui_waker(activity_seq.clone(), ui_waker),
    );
    runtime
        .set_guest(Box::new(ZeroGuest {
            inner: RquickjsGuest::default(),
            http,
            notify,
            bridge: std::ptr::null_mut(),
            worker: None,
        }))
        .map_err(error)?;
    runtime.boot().map_err(error)?;
    unsafe {
        libc::signal(libc::SIGINT, stop as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, stop as *const () as libc::sighandler_t);
    }
    let mut clock = MonotonicClock::default();
    let mut schedule = TickSchedule::new(profile.tick_hz, clock.now(), 1).map_err(error)?;
    let active_window = Duration::from_millis(2200);
    let mut active_until = Instant::now() + active_window;
    let mut seen_activity = activity_seq.load(Ordering::Acquire);
    let mut last_draw_hash = ops
        .core()
        .map(|c| hash_draw_words(&c.ui.current_draw_list().words))
        .unwrap_or(0);
    let mut ui_frame_pending = true;

    while !STOP.load(Ordering::Relaxed) && !http::QUIT.load(Ordering::Relaxed) {
        if let Some(shot) = shot.as_mut() {
            schedule.wait_next(&mut clock).map_err(error)?;
            if !shot.before_tick() {
                break;
            }
            runtime.tick().map_err(error)?;
            shot.after_tick()?;
            continue;
        }

        // 1. Drain wakeup pipe and evdev watchers BEFORE sampling `activity_seq` so a
        // completion between load and drain can never lose its wake byte!
        ui_wake_pipe.drain();
        let evdev_woke = drain_evdev_watchers(&mut idle_evdev_watchers);
        let cur_activity = activity_seq.load(Ordering::Acquire);
        if evdev_woke || cur_activity != seen_activity {
            seen_activity = cur_activity;
            active_until = Instant::now() + active_window;
        }

        if Instant::now() >= active_until {
            // Re-check `activity_seq` immediately before parking in `poll()`.
            let recheck = activity_seq.load(Ordering::Acquire);
            if recheck != seen_activity {
                seen_activity = recheck;
                active_until = Instant::now() + active_window;
                schedule.wait_next(&mut clock).map_err(error)?;
            } else {
                // Include pending UI frame deadlines (`schedule.deadline()`) when an animation
                // or UI update is still active past `active_until`, so animations stay at 30fps!
                let poll_timeout_ms = if ui_frame_pending {
                    let next_us = schedule.deadline().map_err(error)?;
                    let rem_us = next_us.saturating_sub(clock.now());
                    ((rem_us + 999) / 1000).min(250) as i32
                } else {
                    250
                };

                let mut pfds = Vec::with_capacity(1 + idle_evdev_watchers.len());
                pfds.push(libc::pollfd {
                    fd: ui_wake_pipe.read_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
                for f in &idle_evdev_watchers {
                    pfds.push(libc::pollfd {
                        fd: f.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    });
                }
                let _ = unsafe {
                    libc::poll(pfds.as_mut_ptr(), pfds.len() as libc::nfds_t, poll_timeout_ms)
                };
                if STOP.load(Ordering::Relaxed) || http::QUIT.load(Ordering::Relaxed) {
                    break;
                }

                // Retire any disconnected/errored evdev descriptors (`POLLHUP`/`POLLERR`/`POLLNVAL`).
                for idx in (0..idle_evdev_watchers.len()).rev() {
                    let rev = pfds[1 + idx].revents;
                    if (rev & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL)) != 0
                        && (rev & libc::POLLIN) == 0
                    {
                        idle_evdev_watchers.swap_remove(idx);
                    }
                }

                ui_wake_pipe.drain();
                let post_evdev_woke = drain_evdev_watchers(&mut idle_evdev_watchers);
                let next_activity = activity_seq.load(Ordering::Acquire);
                if post_evdev_woke || next_activity != seen_activity {
                    seen_activity = next_activity;
                    active_until = Instant::now() + active_window;
                    schedule = TickSchedule::new(profile.tick_hz, clock.now(), 1).map_err(error)?;
                } else if ui_frame_pending {
                    schedule.wait_next(&mut clock).map_err(error)?;
                } else {
                    schedule = TickSchedule::new(profile.tick_hz, clock.now(), 1).map_err(error)?;
                }
            }
        } else {
            schedule.wait_next(&mut clock).map_err(error)?;
        }

        let epoch_before = ops.core().map(|c| c.epoch).unwrap_or(0);
        runtime.tick().map_err(error)?;
        let (epoch_after, draw_hash) = ops
            .core()
            .map(|c| (c.epoch, hash_draw_words(&c.ui.current_draw_list().words)))
            .unwrap_or((epoch_before, last_draw_hash));
        // An idle `runtime.tick()` with zero guest UI ops borrows `core_mut` 3 times (`encode`,
        // `ui.tick`, `present`). Any guest UI op (`epoch_delta > 3`) or changed `DrawList` means
        // UI work / animation is active and expects the next frame on `schedule.deadline()`.
        ui_frame_pending =
            epoch_after.wrapping_sub(epoch_before) > 3 || draw_hash != last_draw_hash;
        last_draw_hash = draw_hash;

        let post_tick_activity = activity_seq.load(Ordering::Acquire);
        if post_tick_activity != seen_activity {
            seen_activity = post_tick_activity;
            active_until = Instant::now() + active_window;
        }
    }
    let shutdown_res = runtime.shutdown().map_err(error);
    drop(cleanup);
    shutdown_res?;
    Ok(())
}

fn drain_evdev_watchers(files: &mut Vec<std::fs::File>) -> bool {
    use std::io::Read;
    let mut any = false;
    let mut buf = [0u8; 512];
    files.retain_mut(|f| loop {
        match f.read(&mut buf) {
            Ok(0) => return false,
            Ok(_) => {
                any = true;
            }
            Err(ref e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                return true;
            }
            Err(_) => return false,
        }
    });
    any
}

#[cfg(target_os = "linux")]
struct TrackedInput<S> {
    inner: S,
    activity: Arc<AtomicU64>,
}

#[cfg(target_os = "linux")]
impl<S: pocket_drivers::InputSource> pocket_drivers::InputSource for TrackedInput<S> {
    fn classes(&self) -> InputClasses {
        self.inner.classes()
    }
    fn poll(&mut self, frame: &mut pocket_drivers::InputFrameBuilder) {
        let prev_text = frame.text.len();
        let prev_contacts = frame.contacts.len();
        let prev_cancelled = frame.cancelled.len();
        self.inner.poll(frame);
        if frame.buttons != 0
            || frame.text.len() != prev_text
            || frame.contacts.len() != prev_contacts
            || frame.cancelled.len() != prev_cancelled
        {
            self.activity.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// The panel and the keyboard. Linux only: on another system the program
/// builds for its unit tests and refuses to run.
#[cfg(target_os = "linux")]
fn attach_devices(
    runtime: &mut Runtime,
    renderer: pocket_runtime::RendererId,
    profile: &pocket_runtime::Profile,
    fb: Option<PathBuf>,
    inputs: Vec<PathBuf>,
    activity: Arc<AtomicU64>,
) -> Result<Vec<std::fs::File>, Box<dyn Error>> {
    use std::os::unix::fs::OpenOptionsExt;
    let size = profile.viewport;
    let mut display = pocket_linux_fbdev::open(fb.unwrap_or_else(|| "/dev/fb0".into()))?;
    // The panel is this program's while it runs: frames redraw what changed.
    display.set_partial_refresh(true);
    let descriptor = pocket_drivers::DisplayOutput::descriptor(&display);
    if [descriptor.width, descriptor.height] != size {
        return Err(error(format!(
            "the framebuffer is {}x{}, the profile {}x{}",
            descriptor.width, descriptor.height, size[0], size[1]
        ))
        .into());
    }
    runtime.add_display(display, renderer).map_err(error)?;
    // The keyboard is the tca8418 matrix; other devices that report buttons
    // (the HDMI CEC keys, the IR receiver) join it. Text keys name the symbol
    // layer from the vendor's key codes (keymap.rs).
    let symbols = keymap::load();
    let mut inputs = inputs;
    if inputs.is_empty() {
        if let Ok(entries) = std::fs::read_dir("/dev/input") {
            inputs = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| {
                    path.file_name()
                        .is_some_and(|name| name.to_string_lossy().starts_with("event"))
                })
                .collect();
            inputs.sort();
        }
    }
    let mut watchers = Vec::new();
    for (index, path) in inputs.iter().take(16).enumerate() {
        let mut device = pocket_linux_evdev::Evdev::open(
            path,
            profile.logical_viewports[0],
            index as u32 * 16,
            16,
        )?;
        device.set_symbols(symbols.clone());
        runtime
            .add_input_source(Box::new(TrackedInput {
                inner: device,
                activity: activity.clone(),
            }))
            .map_err(error)?;
        if let Ok(watcher) = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(path)
        {
            watchers.push(watcher);
        }
    }
    Ok(watchers)
}

#[cfg(not(target_os = "linux"))]
fn attach_devices(
    _: &mut Runtime,
    _: pocket_runtime::RendererId,
    _: &pocket_runtime::Profile,
    _: Option<PathBuf>,
    _: Vec<PathBuf>,
    _: Arc<AtomicU64>,
) -> Result<Vec<std::fs::File>, Box<dyn Error>> {
    Err(error("the panel and keyboard drivers require Linux").into())
}

fn main() {
    let raw_args: Vec<String> = std::env::args().collect();
    if raw_args.get(1).map(String::as_str) == Some("--rex-socks5-stdio") {
        if let (Some(proxy), Some(host), Some(port_s)) =
            (raw_args.get(2), raw_args.get(3), raw_args.get(4))
        {
            if let Ok(port) = port_s.parse::<u16>() {
                if let Err(err) = rex::transport::run_socks5_stdio_bridge(proxy, host, port) {
                    eprintln!("rex-socks5-stdio: {err}");
                    std::process::exit(1);
                }
                return;
            }
        }
        eprintln!("usage: pocket-cardputer-zero --rex-socks5-stdio <127.0.0.1:port> <host> <port>");
        std::process::exit(2);
    }

    match options().and_then(|options| match options {
        Some(options) => run(options),
        None => Ok(()),
    }) {
        Ok(()) => {}
        Err(error) => {
            eprintln!("pocket-cardputer-zero: {error}");
            std::process::exit(1);
        }
    }
}
