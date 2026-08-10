//! The session lifecycle loop: one SDL context on the caller's main thread driving the
//! window, the Vulkan presenter, input capture, the pumped gamepad service, and the
//! shared session pump's event/frame channels.
//!
//! Two modes over one loop: **single** (`run_session` — one `--connect` stream, exit on
//! end; the shell↔session contract) and **browse** (`run_browse` — the console library
//! idles between streams; overlay actions launch sessions, session end returns to the
//! library; the app quits only on B/window-close).
//!
//! Stdout is the machine interface (the shell↔session contract): one `{"ready":true}`
//! line after the first presented frame, `stats: …` lines once per window while the
//! overlay tier isn't Off (Ctrl+Alt+Shift+S cycles Off → Compact → Normal → Detailed;
//! the stdout line always carries the full Detailed text so parsers see a stable
//! shape). Logs go to stderr (the binary configures tracing so).
//!
//! In-stream chords all share the Ctrl+Alt+Shift prefix: Q release/engage, M mouse model,
//! D disconnect, S stats tier, V microphone mute.

use crate::input::{Capture, FingerPhase};
use crate::overlay::{
    FrameCtx, Overlay, OverlayAction, OverlayFrame, PointerButton, PointerInput, SessionPhase,
};
use crate::present_pace::{
    Cadence, CadenceProbe, FrameStore, LatchClock, PresentGate, MARGIN_MAX_NS, MARGIN_STEP_NS,
};
use crate::touch::Abs;
use crate::vk::{FrameInput, Presenter};
use anyhow::{Context as _, Result};
use pf_client_core::gamepad::GamepadService;
use pf_client_core::session::{self, SessionEvent, SessionHandle, SessionParams, Stats};
use pf_client_core::trust::{MouseMode, PresentPriority, StatsVerbosity, TouchMode};
use pf_client_core::video::VulkanDecodeDevice;
use pf_client_core::video::{DecodedFrame, DecodedImage};
use punktfunk_core::client::NativeClient;
use punktfunk_core::config::{CompositorPref, Mode};
use sdl3::event::{Event, WindowEvent};
use sdl3::keyboard::Mod;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct SessionOpts {
    pub window_title: String,
    /// Start fullscreen (gamescope / `--fullscreen`).
    pub fullscreen: bool,
    /// The window's top-left in desktop coordinates; `None` = centered on the primary
    /// display. The shells pass their own window's position so the stream opens on the
    /// SAME monitor (and the shell⇄session visibility handoff reads as one window
    /// changing content, not a window jumping displays). Fullscreen follows the display
    /// this lands on.
    pub window_pos: Option<(i32, i32)>,
    /// Stats overlay tier at start — gates the OSD panel AND the stdout `stats:` lines
    /// (Ctrl+Alt+Shift+S cycles Off → Compact → Normal → Detailed live).
    pub stats_verbosity: StatsVerbosity,
    /// Touchscreen input model (Deck/tablet): `Trackpad` (relative cursor + gestures),
    /// `Pointer` (absolute cursor), or `Touch` (real multi-touch passthrough). Latched per
    /// session — a mouse-only client leaves this at the default and never sees a finger.
    pub touch_mode: TouchMode,
    /// Physical-mouse model: `Capture` (pointer lock + relative, the default) or `Desktop`
    /// (uncaptured absolute pointer — design/remote-desktop-sweep.md M1). Ctrl+Alt+Shift+M
    /// flips it live; silently resolves to capture on hosts without absolute injection
    /// (gamescope).
    pub mouse_mode: MouseMode,
    /// Reverse the scroll direction sent to the host ([`Settings::invert_scroll`]).
    pub invert_scroll: bool,
    /// Send system chords (Alt+Tab, the Windows key / Super) to the host while input is
    /// captured ([`Settings::inhibit_shortcuts`], default on). Off keeps them local — the
    /// work profile that streams on a second screen and still Alt-Tabs here. Never applies
    /// under the `desktop` mouse model, which is something you Alt-Tab *away* from.
    pub inhibit_shortcuts: bool,
    /// Presentation intent ([`Settings::present_priority`] resolved): `Latency` keeps the
    /// shipped arrival pacing (newest-wins, present the moment a frame can go out);
    /// `Smooth { buffer }` runs the smoothing FIFO drained one frame per latch slot
    /// (design/desktop-presentation-rebuild.md). `PUNKTFUNK_PRESENTER=arrival` overrides
    /// the whole engine back to the legacy drain for field A/B without a rebuild.
    pub present_priority: PresentPriority,
    /// Tear-free presentation ([`Settings::vsync`], default on). Off asks for a tearing
    /// present mode for the lowest possible latch — best-effort, and the mode that
    /// actually took is named in the stats line.
    pub vsync: bool,
    /// Let a variable-refresh display follow the stream cadence ([`Settings::allow_vrr`],
    /// default on) — prefers the present mode that drives VRR panels directly when the
    /// session starts fullscreen.
    pub allow_vrr: bool,
    /// Emit the `{"ready":true}` stdout line after the first presented frame.
    pub json_status: bool,
    /// Called once on `Connected` with the host's fingerprint (trust persistence is the
    /// binary's business — this loop stays store-agnostic).
    pub on_connected: Option<Box<dyn FnMut([u8; 32])>>,
    /// The console-UI overlay (§6.1) — `None` is the Skia-free power-user build (stats
    /// stay stdout-only). An overlay whose `init` fails degrades to `None` with a
    /// warning rather than killing the session. Browse mode requires one.
    pub overlay: Option<Box<dyn Overlay>>,
    /// The window's starting logical size; `None` = the 1280×720 default. The binary
    /// passes the persisted last-window size under the Match-window policy so the first
    /// connect's mode already matches what the user will be looking at.
    pub window_size: Option<(u32, u32)>,
    /// Match-window resolution policy (design/midstream-resolution-resize.md D1/D2):
    /// `Some` = the stream mode follows the window. At session start the params' mode
    /// w/h are replaced by the window's physical pixel size; a mid-session resize sends
    /// a debounced `Reconfigure` so the host's virtual display + encoder follow. The
    /// callback receives the window's logical size at each resize-end — the binary
    /// persists it for the next launch. `None` = never auto-resize (Auto-native /
    /// Explicit keep today's behavior).
    pub match_window: Option<Box<dyn FnMut(u32, u32)>>,
    /// Render-resolution multiplier applied to the window pixel size under Match-window (the
    /// fixed-mode path scales in the binary's `session_params`). `> 1` supersamples (host renders
    /// larger, the presenter downscales); `1.0` = the window's native pixels. See
    /// [`punktfunk_core::render_scale`].
    pub render_scale: f64,
    /// The codec's per-axis ceiling for the render-scale clamp (4096 for H.264, else 8192).
    pub render_scale_max_dim: u32,
}

pub enum Outcome {
    /// The session ran and ended: `None` = deliberate exit (user quit), `Some` = the
    /// reason the pump reported (host ended, transport error…).
    Ended(Option<String>),
    ConnectFailed {
        msg: String,
        trust_rejected: bool,
    },
}

/// What the session binary decided about an overlay action (browse mode).
pub enum ActionOutcome {
    /// Consumed binary-side (a Retry respawned the fetch, …).
    Handled,
    /// Start this session (a Launch action; `force_software` from the callback args is
    /// wired into these params). Boxed: SessionParams is large next to the unit variants.
    Start(Box<SessionParams>),
    /// Quit the launcher.
    Quit,
}

/// One `--connect` stream session; returns when it ends (the shell↔session contract).
pub fn run_session<F>(opts: SessionOpts, build_params: F) -> Result<Outcome>
where
    F: FnOnce(&GamepadService, Mode, Arc<AtomicBool>, Option<VulkanDecodeDevice>) -> SessionParams,
{
    let mut build = Some(build_params);
    run_inner(
        opts,
        ModeCtl::Single(Box::new(move |gp, native, fs, vk| {
            (build.take().expect("single build runs once"))(gp, native, fs, vk)
        })),
    )
    .map(|o| o.expect("single mode always yields an outcome"))
}

/// Browse mode: the console library idles between streams. `on_action` receives every
/// overlay action (Launch/Retry/Quit) plus what a launch needs to build its params —
/// the gamepad service (`auto_pref`), the native display mode, and a fresh
/// per-session `force_software` flag.
pub fn run_browse<F>(opts: SessionOpts, on_action: F) -> Result<()>
where
    F: FnMut(
        OverlayAction,
        &GamepadService,
        Mode,
        Arc<AtomicBool>,
        Option<VulkanDecodeDevice>,
    ) -> ActionOutcome,
{
    anyhow::ensure!(
        opts.overlay.is_some(),
        "--browse needs the console UI (a build with the `ui` feature)"
    );
    run_inner(opts, ModeCtl::Browse(Box::new(on_action))).map(|_| ())
}

/// Params builder for the one single-mode session (called exactly once, post-setup).
type BuildParams<'a> = Box<
    dyn FnMut(&GamepadService, Mode, Arc<AtomicBool>, Option<VulkanDecodeDevice>) -> SessionParams
        + 'a,
>;
/// The browse-mode action callback (Launch → params, Retry/Quit → outcome).
type OnAction<'a> = Box<
    dyn FnMut(
            OverlayAction,
            &GamepadService,
            Mode,
            Arc<AtomicBool>,
            Option<VulkanDecodeDevice>,
        ) -> ActionOutcome
        + 'a,
>;

/// The two run modes, type-erased so one loop serves both.
enum ModeCtl<'a> {
    Single(BuildParams<'a>),
    Browse(OnAction<'a>),
}

/// The custom SDL event a decoded frame's arrival pushes (see [`StreamState::new`]):
/// pure wake-up — the loop drains the frame channel regardless of why it woke.
struct FrameWake;

/// Everything one stream session accumulates — created at session start, dropped at
/// session end (browse mode cycles through several per process lifetime).
struct StreamState {
    handle: SessionHandle,
    /// Decoded frames, re-queued by the wake forwarder (newest-wins, like the pump's
    /// own queue). The loop drains THIS, never `handle.frames` — the forwarder is that
    /// channel's one consumer.
    frames: async_channel::Receiver<DecodedFrame>,
    connector: Option<Arc<NativeClient>>,
    capture: Option<Capture>,
    force_software: Arc<AtomicBool>,
    /// The user canceled this connect from the console — never engage the stream
    /// (skip capture/attach on a late `Connected`) and route its end back silently.
    canceled: bool,
    ready_announced: bool,
    mode_line: String,
    /// The settings profile this session resolved with, for the stats overlay's first line
    /// ("which profile am I on?"). `None` = the global defaults, and nothing is shown.
    profile: Option<String>,
    /// The latch grid the pump's PhaseReports read (see `session::LatchGrid`), written by
    /// the 1 Hz present-timing fold. `None` = the session didn't advertise phase lock
    /// (no present-wait, or an embedder that opted out).
    latch_grid: Option<Arc<session::LatchGrid>>,
    /// Live host↔client clock offset handle (None until Connected): loaded per present so
    /// mid-stream re-syncs keep the end-to-end number honest after an NTP step / drift.
    clock_offset: Option<Arc<std::sync::atomic::AtomicI64>>,
    /// Where the audio plane reads the video leg it must land with (ns). Published on every
    /// presented frame; see the two `e2e` sites. The presenter deliberately knows nothing about
    /// audio beyond writing this number.
    video_e2e: Option<Arc<std::sync::atomic::AtomicU64>>,
    hdr: bool,
    /// The presented lane shows a PQ stream RAW — no tone-map pass ran — so the OSD badge
    /// reads `HDR→SDR (raw)` instead of claiming one that never did.
    ///
    /// Nothing sets it since M8. It used to mark the software lane, which arrived as
    /// swscale RGBA and skipped the CSC pass entirely; that lane now uploads planes into
    /// the same planar CSC pass as the hardware lanes and tone-maps in mode 1 like them.
    /// Kept — not deleted — because the badge's distinction is real and the next lane that
    /// bypasses the pass must be able to say so rather than quietly claim a tone-map.
    hdr_untonemapped: bool,
    // Presenter-side 1 s window (design/stats-unification.md): end-to-end
    // capture→displayed (host-clock corrected) p50+p95, display = decoded→displayed p50.
    win_e2e_us: Vec<u64>,
    win_disp_us: Vec<u64>,
    /// The display stage's two halves (present-timing sessions only): decoded→submit and
    /// submit→on-glass. See [`PresentedWindow::pace_ms`].
    win_pace_us: Vec<u64>,
    win_latch_us: Vec<u64>,
    win_start: Instant,
    presented: PresentedWindow,
    /// The intent engine (design/desktop-presentation-rebuild.md WP2): the decoded-frame
    /// store between the wake channel and the present call — a newest-wins slot under
    /// the latency intent (behaviorally the shipped drain), the smoothing FIFO under
    /// smoothness. NOTE: a smoothing store holds decoder-pool frames (Vulkan-Video
    /// AVFrames) up to `buffer` deep on top of the depth-2 wake channels — within pool
    /// headroom for 1..=3, but any deeper store must revisit pool sizing.
    store: FrameStore<DecodedFrame>,
    /// The panel latch grid (present-wait glass stamps; submit-anchored fallback) — the
    /// smoothness slot clock, and the values published to the host-facing `latch_grid`.
    clock: LatchClock,
    /// The FIFO glass budget (one undisplayed present in flight) — inert off FIFO modes
    /// or without present timing.
    gate: PresentGate,
    /// Is variable refresh actually live? Measured from the same on-glass stamps (no
    /// portable query exists) — see [`CadenceProbe`].
    cadence: CadenceProbe,
    /// The DISPLAY MODE's refresh period — the vblank grid presents quantize to when
    /// VRR is off, and so the cadence probe's reference. Deliberately not the learned
    /// period (see the probe's call site).
    mode_period_ns: u64,
    /// The latch slot the last smoothness present served (one present per slot); 0 =
    /// none yet.
    last_target_ns: u64,
    /// Smoothness slot-pick margin: starts 0 (a fixed lead is pure display tax —
    /// measured on Android), widens +500 µs per >2-miss window toward 2.5 ms.
    margin_ns: u64,
    /// This window's latch misses (a present that reached glass > 1.5 latch periods
    /// after submit) — the adaptive margin's error signal.
    win_misses: u32,
    /// This window's peak undisplayed-presents-in-flight (present timing only).
    win_out_max: usize,
    /// One-shot log latch: smoothness was requested but a PyroWave stream collapsed the
    /// store to latency (its plane-ring retirement assumes the newest-wins hand-off).
    #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
    pyro_latency_forced: bool,
    // Hardware-path health: a failure streak (or a device with no import support at
    // all) demotes the decoder to software via the shared flag — once per session.
    dmabuf_demoted: bool,
    /// PyroWave present has no demote rung (nothing else decodes the codec), so a
    /// persistent non-device-lost present failure would warn on every frame. Latch it:
    /// warn on the first failure of a streak, then stay quiet until a present succeeds.
    #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
    pyro_present_warned: bool,
    /// The same latch for the SOFTWARE lane, which since M8 has real failure modes (three
    /// plane images + their allocations and views, rebuilt on every size change, plus a
    /// render pass) and — being the ladder's LAST rung — nothing left to demote to.
    cpu_present_warned: bool,
    hw_fails: u32,
    /// The OSD's text (multi-line; rebuilt each Stats window and on a live tier cycle).
    osd_text: String,
    /// The last pump window, kept so a Ctrl+Alt+Shift+S tier cycle can re-render the
    /// OSD immediately instead of waiting up to 1 s for the next Stats event.
    last_stats: Option<Stats>,
    /// Match-window (D2) debounce state: the last resize event's stamp. `Some` = a
    /// resize is pending; the tick fires the request once ~400 ms pass with no further
    /// size events (never per drag-frame — each accepted switch is a full host rebuild).
    resize_pending: Option<Instant>,
    /// When the last `Reconfigure` was sent — the ≥ 1 s spacing between requests (D2).
    /// The accept ack round-trips in milliseconds (it precedes the host's rebuild), so
    /// this spacing also serializes: at most ~one request is ever outstanding.
    resize_sent_at: Option<Instant>,
    /// The last size actually requested. Each distinct size is requested at most once:
    /// this both implements "don't re-request a rejected size until it changes" (D2) and
    /// keeps a host-side rollback (accept ack, rebuild failed, corrective ack restored
    /// the old mode) from looping request → rollback → request forever.
    resize_requested: Option<(u32, u32)>,
    /// The connector mode last shown in the HUD/title — a change (an accepted switch's
    /// ack, or a corrective rollback) refreshes both.
    shown_mode: Option<Mode>,
    /// Resize-in-progress overlay (scrim + spinner) — armed by [`resize_tick`] when it
    /// requests a switch, cleared when a decoded frame reaches the target (or on timeout).
    resize_overlay: ResizeIndicator,
    /// The last presented frame's video dimensions — the source rect touch passthrough
    /// maps a finger into (the video is letterboxed within the window, so a finger's
    /// window-normalized position must be re-based onto the content rect). `None` until
    /// the first frame; touches before then have nothing to map onto and are dropped.
    last_video: Option<(u32, u32)>,
    /// Client-side cursor rendering (M2 cursor channel) — created with the connector; inert
    /// when the host didn't negotiate the channel.
    cursor_chan: Option<crate::cursor::CursorChannel>,
    /// Last observed `relative_hint` (M3): the auto-flip fires on CHANGES only, so it never
    /// fights a user who chorded away from the hinted model.
    last_hint: Option<bool>,
    /// The user flipped the model manually (⌃⌥⇧M) — the standing hint stops driving until
    /// the HOST's intent next changes (a fresh hint edge clears this and applies).
    hint_override: bool,
    /// Last `CursorRenderMode.client_draws` told to the host (§8 mid-stream render flip);
    /// `None` = nothing sent yet. Edge-detected each iteration from the live mouse model, so
    /// the chord, the M3 auto-flip, and engage/release all reconcile through one path.
    sent_client_draws: Option<bool>,
    /// The params this session was started with, kept so a codec fallback can re-dial
    /// with `exclude_codecs` widened — see [`SessionEvent::CodecFallback`]. Cloned once
    /// per session start, so anything the SESSION changed after launch (an accepted mode
    /// switch) is not in here and the retry re-reads it from the connector.
    ///
    /// The latch grid rides along by `Arc` on purpose — it is the presenter's, not the
    /// session's. `force_software` does NOT: it is a per-session demote latch, and the
    /// retry replaces it (a fallback would otherwise open on software).
    params: SessionParams,
}

impl StreamState {
    /// `wake`: pushes a [`FrameWake`] SDL event as each decoded frame lands, via a tiny
    /// forwarder thread that owns the pump's frame channel. This is what lets the run
    /// loop BLOCK in `wait_event_timeout` (instead of a 1 ms poll — measured as a full
    /// core burned at any frame rate) yet still present a frame the instant it arrives:
    /// input events and frames both wake the same wait. The forwarder exits when the
    /// pump drops its sender (session end/shutdown).
    fn new(
        params: SessionParams,
        force_software: Arc<AtomicBool>,
        wake: sdl3::event::EventSender,
        priority: PresentPriority,
        native_refresh_hz: u32,
    ) -> StreamState {
        let profile = params.profile.clone();
        // The presenter's half of phase-locked capture: it writes the latch grid the
        // pump reads (see `LatchGrid`), so keep the Arc before the params move. `None`
        // when the session didn't advertise the cap — the 1 Hz fold then skips the work.
        let latch_grid = params.phase_lock.then(|| params.latch_grid.clone());
        // Kept for a codec-fallback re-dial (`SessionEvent::CodecFallback`).
        let retry_params = params.clone();
        let handle = session::start(params);
        let (wake_tx, wake_rx) = async_channel::bounded(2);
        let pump_rx = handle.frames.clone();
        let _ = std::thread::Builder::new()
            .name("pf-frame-wake".into())
            .spawn(move || {
                while let Ok(f) = pump_rx.recv_blocking() {
                    let _ = wake_tx.force_send(f); // newest wins, like the pump's queue
                    let _ = wake.push_custom_event(FrameWake);
                }
            });
        StreamState {
            handle,
            frames: wake_rx,
            connector: None,
            capture: None,
            cursor_chan: None,
            last_hint: None,
            hint_override: false,
            sent_client_draws: None,
            force_software,
            canceled: false,
            ready_announced: false,
            mode_line: String::new(),
            profile,
            latch_grid,
            clock_offset: None,
            video_e2e: None,
            hdr: false,
            hdr_untonemapped: false,
            win_e2e_us: Vec::with_capacity(256),
            win_disp_us: Vec::with_capacity(256),
            win_pace_us: Vec::with_capacity(256),
            win_latch_us: Vec::with_capacity(256),
            win_start: Instant::now(),
            presented: PresentedWindow::default(),
            store: FrameStore::new(usize::from(priority.fifo_capacity())),
            clock: LatchClock::new(native_refresh_hz),
            gate: PresentGate::default(),
            cadence: CadenceProbe::new(),
            mode_period_ns: 1_000_000_000 / u64::from(native_refresh_hz.max(1)),
            last_target_ns: 0,
            margin_ns: 0,
            win_misses: 0,
            win_out_max: 0,
            #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
            pyro_latency_forced: false,
            dmabuf_demoted: false,
            #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
            pyro_present_warned: false,
            cpu_present_warned: false,
            hw_fails: 0,
            osd_text: String::new(),
            last_stats: None,
            resize_pending: None,
            resize_sent_at: None,
            resize_requested: None,
            shown_mode: None,
            resize_overlay: ResizeIndicator::default(),
            last_video: None,
            params: retry_params,
        }
    }

    /// Stop the pump and JOIN its thread — required before any device-wide idle or
    /// teardown (the pump submits decode work to the shared device). Quick: the pump
    /// notices `stop` within its 20 ms receive timeout, and on a normal end it's
    /// already returning.
    fn shutdown(mut self) {
        self.handle.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.handle.thread.take() {
            let _ = t.join();
        }
    }

    /// Deliberate user exit (chord / window close): release capture, close with
    /// QUIT_CLOSE_CODE so the host tears down instead of lingering, stop the pump.
    /// The pump then emits `Ended(None)` — the loop's normal end path picks it up.
    fn request_quit(&mut self) {
        if let Some(cap) = &mut self.capture {
            cap.release(true);
        }
        if let Some(c) = &self.connector {
            c.disconnect_quit();
        }
        self.handle.stop.store(true, Ordering::SeqCst);
    }

    /// The event-loop wait bound: a smoothness stream with buffered frames sleeps only
    /// to its next latch-slot deadline; everything else keeps the 15 ms housekeeping
    /// tick (frames, input, and present completions all wake the loop early anyway).
    fn wake_timeout(&self) -> Duration {
        const TICK: Duration = Duration::from_millis(15);
        if !self.store.is_smoothing() || self.store.is_empty() {
            return TICK;
        }
        let now = session::now_ns();
        let mut target = self
            .clock
            .next_slot_after(now.saturating_add(self.margin_ns));
        if target == self.last_target_ns {
            // This slot is already served — the next boundary is the deadline.
            target += self.clock.period_ns();
        }
        Duration::from_nanos(target.saturating_sub(now)).clamp(Duration::from_millis(1), TICK)
    }
}

/// Whether a present error is `VK_ERROR_DEVICE_LOST` anywhere in its chain. A lost
/// device is unrecoverable by spec — every object on it (decoder frames, swapchain,
/// the Skia context) is dead, and the demote-to-software path would rebuild the
/// decoder against that same dead device (observed live 2026-07-09: the decode lane wedges
/// inside the rebuild, the decode thread never returns, and the client zombies with
/// the pump flushing a never-draining backlog every 2 s). The only correct response
/// is to fail the session loudly and let the shell relaunch.
fn device_lost(e: &anyhow::Error) -> bool {
    e.chain()
        .any(|c| c.downcast_ref::<ash::vk::Result>() == Some(&ash::vk::Result::ERROR_DEVICE_LOST))
}

fn run_inner(mut opts: SessionOpts, mut mode: ModeCtl) -> Result<Option<Outcome>> {
    // Before any window exists: unpackaged runs adopt the shell's AppUserModelID so the
    // shell⇄session windows group as one taskbar app (win32.rs; MSIX identity wins).
    #[cfg(windows)]
    crate::win32::set_app_user_model_id();
    sdl3::hint::set("SDL_JOYSTICK_THREAD", "1");
    // Hold SDL's Valve HIDAPI drivers off BEFORE SDL_Init: the Deck driver clears the pad's
    // digital mappings at *enumeration*, which is part of bringing the gamepad subsystem up, so a
    // hint set after `sdl.gamepad()` — where this used to live, inside GamepadService::pumped —
    // only detached a driver that had already killed the built-in trackpad-mouse system-wide. The
    // symptom was the Deck losing its trackpad cursor at the start of every session until the
    // firmware watchdog restored lizard mode. They are still enabled for an attached session.
    pf_client_core::gamepad::preinit_disable_valve_hidapi();
    // A touchscreen (the Deck's glass) is forwarded as REAL touch passthrough below — so
    // suppress SDL's default synthesis of mouse events from touch. Left on, every touch
    // ALSO warps a synthetic mouse to the touch point, which under the stream's relative
    // mouse lock becomes a large positive delta that walks the host cursor into the
    // bottom-right corner (the reported bug). The menu/library is keyboard+gamepad-driven
    // and consumes no mouse, so nothing wanted these synthetic events anyway.
    sdl3::hint::set("SDL_TOUCH_MOUSE_EVENTS", "0");
    // The Wayland `app_id` (and X11 WM_CLASS) — compositors match it against
    // io.unom.Punktfunk.desktop for the window/taskbar icon. Without it SDL uses a generic
    // identity and the session window gets the default-Wayland icon (the Linux analog of
    // the AppUserModelID adoption above).
    sdl3::hint::set("SDL_APP_ID", "io.unom.Punktfunk");
    // `PUNKTFUNK_DRM_CARD=<n>` → SDL's KMSDRM device index, for a compositor-less (kiosk/embedded)
    // run. SDL enumerates /dev/dri/card* and takes the first one it can open, which on a
    // multi-GPU box is regularly the WRONG one: measured on a two-card machine it chose the card
    // a live compositor already held DRM master on and failed at swapchain creation, while the
    // idle card with the connected display sat unused. There is no reliable way to pick from
    // inside the process (detecting "already mastered" needs the ioctl that taking master IS), so
    // this stays an explicit operator choice rather than fragile auto-detection.
    // Ignored unless the kmsdrm backend is actually in use.
    if let Ok(card) = std::env::var("PUNKTFUNK_DRM_CARD") {
        if card.chars().all(|c| c.is_ascii_digit()) && !card.is_empty() {
            tracing::info!(
                card,
                "PUNKTFUNK_DRM_CARD: pinning SDL's KMSDRM device index"
            );
            sdl3::hint::set("SDL_KMSDRM_DEVICE_INDEX", &card);
        } else {
            tracing::warn!(
                card,
                "PUNKTFUNK_DRM_CARD must be a card NUMBER (e.g. 0) — ignoring"
            );
        }
    }
    let sdl = sdl3::init().context("SDL init")?;
    let video = sdl.video().context("SDL video")?;
    let events = sdl.event().context("SDL events")?;
    events
        .register_custom_event::<FrameWake>()
        .map_err(|e| anyhow::anyhow!("register FrameWake event: {e}"))?;
    let mut window = {
        // Match-window (D1): open at the persisted last size, so the first connect's
        // mode already matches the glass. 1280×720 stays the fallback/default.
        let (ww, wh) = opts.window_size.unwrap_or((1280, 720));
        let mut b = video.window(&opts.window_title, ww.max(320), wh.max(200));
        match opts.window_pos {
            Some((x, y)) => b.position(x, y),
            None => b.position_centered(),
        };
        // HIGH_PIXEL_DENSITY: give us a backbuffer in the panel's REAL pixels. Without it
        // SDL leaves the Wayland surface at buffer scale 1, so on a fractionally scaled
        // output (KDE at 150 %: a 2560×1600 panel reported as 1707×1067 points) the
        // swapchain is built at 1707×1067 and the compositor upscales it to the glass —
        // a 2560×1600 stream is resampled DOWN and back UP, and looks it. The flag only
        // widens `size_in_pixels()`; `size()` stays logical, which is what the persisted
        // window size and SDL's own mouse coordinates are in, and both callers already
        // use the right one.
        b.resizable().vulkan().high_pixel_density();
        if opts.fullscreen {
            b.fullscreen();
        }
        b.build().context("SDL window")?
    };
    // The exe-embedded icon onto the title bar/taskbar/Alt-Tab (SDL's class icon is the
    // generic default); a no-op for exes that embed none.
    #[cfg(windows)]
    crate::win32::stamp_window_icon(&window);
    let instance_exts = window
        .vulkan_instance_extensions()
        .map_err(|e| anyhow::anyhow!("vulkan instance extensions: {e}"))?;
    let mut presenter = Presenter::new(
        &window,
        &instance_exts,
        crate::vk::PresentPref {
            vsync: opts.vsync,
            allow_vrr: opts.allow_vrr,
            fullscreen: opts.fullscreen,
            // `vrr_fifo_opt_in` (env) and `fifo_latest_ready` (device capability) are
            // both resolved inside `Presenter::new` — the swapchain owns those, so every
            // caller gets the same answer. `..Default` keeps this site from breaking each
            // time the struct learns another one.
            ..Default::default()
        },
    )
    .context("vulkan presenter")?;
    // A valid black frame immediately — the window is honest while the connect runs.
    presenter.present(&window, FrameInput::Redraw, None)?;

    // `PUNKTFUNK_PRESENTER=arrival` — the legacy drain, the intent engine's field-A/B
    // kill switch (the Android sysprop pattern: no rebuild to bisect a pacing suspicion).
    let arrival_override = std::env::var("PUNKTFUNK_PRESENTER").ok().as_deref() == Some("arrival");
    let present_priority = if arrival_override {
        tracing::info!("PUNKTFUNK_PRESENTER=arrival — presentation pacing disabled");
        PresentPriority::Latency
    } else {
        opts.present_priority
    };
    let pacing_active = !arrival_override;
    let present_debug = std::env::var_os("PUNKTFUNK_PRESENT_DEBUG").is_some();
    // Present completions wake the loop exactly like decoded frames: a glass-gate
    // reopen or a smoothness slot must not wait out the event timeout.
    {
        let sender = events.event_sender();
        presenter.set_present_wake(Box::new(move || {
            let _ = sender.push_custom_event(FrameWake);
        }));
    }
    // Browse mode is "ready" the moment the library window presents — there may never be
    // a stream. (Single mode announces on the first VIDEO frame instead, further down, so
    // a shell only yields to a window that actually shows the stream.)
    if opts.json_status && matches!(mode, ModeCtl::Browse(_)) {
        println!("{{\"ready\":true}}");
    }

    // Operator preference on top of the display's own DPI scale — for a TV across the room, or to
    // shrink chrome that a compositor reports an aggressive scale for. Read once (a preference,
    // not session state); the DPI part is re-read per frame.
    let osd_scale_pref = std::env::var("PUNKTFUNK_OSD_SCALE")
        .ok()
        .and_then(|s| s.trim().parse::<f32>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(1.0);

    let mut overlay = opts.overlay.take();
    if let Some(o) = overlay.as_mut() {
        if let Err(e) = o.init(&presenter.shared_device()) {
            if matches!(mode, ModeCtl::Browse(_)) {
                return Err(e).context("console UI init (required for --browse)");
            }
            tracing::warn!(error = %format!("{e:#}"),
                "console-UI overlay init failed — continuing without it");
            overlay = None;
        }
    }

    let gamepad_subsystem = sdl.gamepad().context("SDL gamepad")?;
    let (gamepad, mut pump) = GamepadService::pumped(gamepad_subsystem);
    let escape_rx = gamepad.escape_events();
    let disconnect_rx = gamepad.disconnect_events();
    let menu_rx = gamepad.menu_events();
    if matches!(mode, ModeCtl::Browse(_)) {
        // Menu mode for the launcher's lifetime (an attached session supersedes
        // translation automatically — the GTK launcher never turned it off either).
        gamepad.set_menu_mode(true);
    }
    // Gaming Mode's Steam menu / QAM drive the SAME physical pad we forward, and gamescope
    // never takes our X focus away (it resolves focus per Xwayland ctx, and we are alone in
    // ours), so SDL's own background-input gate cannot fire there. `None` everywhere else,
    // where window focus IS the signal — see the FocusLost/FocusGained arms below.
    #[cfg(target_os = "linux")]
    let overlay_focus = pf_client_core::overlay_focus::OverlayFocus::start();
    // Two independent reasons the pad is not ours — window focus and the gamescope overlay —
    // OR'd into ONE value that is pushed to the service on an edge. Kept as separate inputs
    // rather than one flag each source writes: either would otherwise clear the other's mask
    // (a focus-loss mask undone by the next overlay poll saying "no overlay", and vice versa).
    let mut focus_lost = false;
    let mut mask_applied = false;

    // The native display mode — the `0 = native` fallback for the requested stream mode
    // (the GTK client reads the monitor under its window; same idea).
    let native = window
        .get_display()
        .and_then(|d| d.get_mode())
        .map(|m| native_mode(m.w, m.h, m.pixel_density, m.refresh_rate))
        .ok()
        // A zero-sized mode is as useless as no mode at all — only `Err` used to reach
        // the fallback, so a display that reported 0×0 streamed a 0×0 request.
        .filter(|m: &Mode| m.width > 0 && m.height > 0)
        .unwrap_or(Mode {
            width: 1920,
            height: 1080,
            refresh_hz: 60,
        });

    let mut stream: Option<StreamState> = match &mut mode {
        ModeCtl::Single(build) => {
            let force_software = Arc::new(AtomicBool::new(false));
            let mut params = build(
                &gamepad,
                native,
                force_software.clone(),
                presenter.vulkan_decode(),
            );
            if opts.match_window.is_some() {
                apply_match_window(
                    &mut params,
                    &window,
                    opts.render_scale,
                    opts.render_scale_max_dim,
                );
            }
            Some(StreamState::new(
                params,
                force_software,
                events.event_sender(),
                present_priority,
                native.refresh_hz,
            ))
        }
        ModeCtl::Browse(_) => None,
    };

    let mut event_pump = sdl
        .event_pump()
        .map_err(|e| anyhow::anyhow!("SDL event pump: {e}"))?;
    let mouse = sdl.mouse();

    let mut fullscreen = opts.fullscreen;
    // Latched for the loop's life, like the other input models: `opts` is borrowed mutably
    // for its callbacks at several of the `apply_capture` sites.
    let inhibit_shortcuts = opts.inhibit_shortcuts;
    let mut stats_verbosity = opts.stats_verbosity;
    let mut overlay_frame: Option<OverlayFrame> = None;
    // SDL text input tracks the overlay's editing state (started = IME/`TextInput`
    // events on desktop, and the door Steam's on-screen keyboard types through under
    // gamescope). Toggled edge-wise — start/stop are not free on Wayland.
    let mut text_input_on = false;

    let outcome = 'main: loop {
        // --- SDL events (input, window, gamepads) ---------------------------------------
        // Block in SDL's own wait: input/window events AND decoded frames (the wake
        // forwarder's FrameWake) all land in this one queue, so the loop wakes exactly
        // when there is work — a short-timeout poll here burned a full core (measured;
        // the timeout only bounds stop-flag/pump-tick latency now). In browse-idle the
        // per-iteration FIFO present vsync-throttles the loop anyway. A smoothness
        // stream tightens the bound to its next latch-slot deadline.
        let timeout = stream
            .as_ref()
            .map_or(Duration::from_millis(15), |st| st.wake_timeout());
        let first = event_pump.wait_event_timeout(timeout);
        let mut queued: Vec<Event> = Vec::new();
        if let Some(e) = first {
            queued.push(e);
        }
        while let Some(e) = event_pump.poll_event() {
            queued.push(e);
        }
        for event in queued {
            // The console UI sees input first: a consumed event (the library's keyboard
            // navigation, a menu) never reaches capture/forwarding.
            if let Some(o) = overlay.as_mut() {
                if o.handle_event(&event) {
                    continue;
                }
                // …and the same for mouse/touch, which the console hit-tests in its own
                // pixel space. Consumed while the console is up; ignored while streaming,
                // where these belong to `Capture` below.
                if let Some(input) = overlay_pointer(&event, &window) {
                    if o.handle_pointer(input) {
                        continue;
                    }
                }
            }
            match event {
                Event::Quit { .. } => {
                    // Window close / SIGINT: deliberate exit, host teardown now.
                    if let Some(st) = &mut stream {
                        st.request_quit();
                    }
                    break 'main Some(Outcome::Ended(None));
                }
                Event::Window { win_event, .. } => match win_event {
                    WindowEvent::FocusLost => {
                        if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                            if cap.release(false) {
                                apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                                tracing::info!("focus lost — input released");
                            }
                        }
                        // Controllers go with the keyboard and mouse. SDL already stops
                        // delivering their PRESSES here, but nothing zeroed what the host
                        // still believes is held — so a stick deflected at the moment focus
                        // went away kept steering. Masking flushes it neutral.
                        focus_lost = true;
                    }
                    WindowEvent::FocusGained => {
                        // Unlike capture, the controller mask has no "the user meant it"
                        // variant to respect — it exists only to mirror who owns the pad —
                        // so regaining focus always lifts its half.
                        focus_lost = false;
                        // An auto-release (Alt-Tab) undoes itself; a chord release
                        // stays released until the user opts back in.
                        if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                            if cap.should_reengage() {
                                cap.engage();
                                apply_capture(
                                    &mut window,
                                    &mouse,
                                    true,
                                    cap.desktop(),
                                    inhibit_shortcuts,
                                );
                                tracing::info!("focus gained — input recaptured");
                            }
                        }
                    }
                    WindowEvent::PixelSizeChanged(..) | WindowEvent::Resized(..) => {
                        presenter.recreate_swapchain(&window)?;
                        presenter.present(&window, FrameInput::Redraw, overlay_frame.as_ref())?;
                        // Match-window (D2): (re)stamp the debounce — the request fires
                        // once ~400 ms pass with no further size events, never per
                        // drag-frame (each accepted switch is a full host rebuild).
                        if opts.match_window.is_some() {
                            if let Some(st) = stream.as_mut() {
                                st.resize_pending = Some(Instant::now());
                            }
                        }
                    }
                    // Dragged to another monitor (or the mode changed under us): the
                    // latch grid and the VRR verdict both belong to the OLD panel. The
                    // refresh rate used to be read once at startup and never revisited,
                    // so a 60 Hz-seeded clock would keep pacing a 144 Hz panel.
                    WindowEvent::DisplayChanged(..) => {
                        let hz = window
                            .get_display()
                            .and_then(|d| d.get_mode())
                            .map(|m| m.refresh_rate.round().max(0.0) as u32)
                            .unwrap_or(0);
                        if let Some(st) = stream.as_mut() {
                            if hz > 0 {
                                st.clock = LatchClock::new(hz);
                                st.mode_period_ns = 1_000_000_000 / u64::from(hz);
                            }
                            st.cadence.reset();
                            st.last_target_ns = 0;
                            tracing::info!(
                                refresh_hz = hz,
                                "display changed — relearning the latch grid"
                            );
                        }
                    }
                    WindowEvent::Exposed => {
                        presenter.present(&window, FrameInput::Redraw, overlay_frame.as_ref())?;
                    }
                    _ => {}
                },
                Event::KeyDown {
                    scancode: Some(sc),
                    keymod,
                    repeat: false,
                    ..
                } => {
                    let chord = keymod.intersects(Mod::LCTRLMOD | Mod::RCTRLMOD)
                        && keymod.intersects(Mod::LALTMOD | Mod::RALTMOD)
                        && keymod.intersects(Mod::LSHIFTMOD | Mod::RSHIFTMOD);
                    use sdl3::keyboard::Scancode;
                    if chord && sc == Scancode::Q {
                        if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                            if cap.captured() {
                                cap.release(true);
                                apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                            } else {
                                cap.engage();
                                apply_capture(
                                    &mut window,
                                    &mouse,
                                    true,
                                    cap.desktop(),
                                    inhibit_shortcuts,
                                );
                            }
                            tracing::info!(captured = cap.captured(), "chord: release/engage");
                        }
                        continue;
                    }
                    // Mouse model flip (capture ⇄ desktop) — applies immediately when
                    // engaged; a released stream just changes what the next engage does.
                    if chord && sc == Scancode::M {
                        if let Some(st) = stream.as_mut() {
                            let mut flipped = false;
                            if let Some(cap) = st.capture.as_mut() {
                                match cap.toggle_desktop() {
                                    Some(desktop) => {
                                        if cap.captured() {
                                            apply_capture(
                                                &mut window,
                                                &mouse,
                                                true,
                                                desktop,
                                                inhibit_shortcuts,
                                            );
                                        }
                                        flipped = true;
                                        tracing::info!(desktop, "chord: mouse mode");
                                    }
                                    None => tracing::info!(
                                        "chord: mouse mode — host has no absolute pointer \
                                         (gamescope), staying captured"
                                    ),
                                }
                            }
                            // A manual flip outranks the standing hint until the host's
                            // intent next CHANGES (M3 — the hint edge clears this).
                            if flipped {
                                st.hint_override = true;
                            }
                        }
                        continue;
                    }
                    if chord && sc == Scancode::D {
                        if let Some(st) = &mut stream {
                            tracing::info!("chord: disconnect");
                            st.request_quit();
                            apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                            // The pump emits Ended(None); the end path routes per mode.
                        }
                        continue;
                    }
                    if chord && sc == Scancode::S {
                        bump_stats_tier(&mut stats_verbosity, &mut stream, &presenter);
                        tracing::info!(tier = ?stats_verbosity, "chord: stats verbosity");
                        continue;
                    }
                    // Mic mute (B4) — "V" for voice; M and S are taken. Per session and never
                    // persisted: this is the doorbell/cough key, not a settings change. The
                    // uplink keeps running while muted (see `MicStreamer::spawn`); only the
                    // sending stops. A session streaming no mic says so instead of silently
                    // swallowing the chord — the overlay would have nothing to show either.
                    if chord && sc == Scancode::V {
                        if let Some(st) = &stream {
                            match st.handle.mic.toggle() {
                                Some(muted) => tracing::info!(muted, "chord: microphone mute"),
                                None => tracing::info!(
                                    "chord: microphone mute — this session streams no \
                                     microphone (turn it on in Settings)"
                                ),
                            }
                        }
                        continue;
                    }
                    // F11 or Alt+Enter (some keyboards' Fn layer sends a media key for
                    // plain F11 — the Moonlight-standard alias always exists).
                    let alt_enter =
                        sc == Scancode::Return && keymod.intersects(Mod::LALTMOD | Mod::RALTMOD);
                    if sc == Scancode::F11 || alt_enter {
                        fullscreen = !fullscreen;
                        tracing::debug!(fullscreen, "fullscreen toggle");
                        if let Err(e) = window.set_fullscreen(fullscreen) {
                            tracing::warn!(error = %e, fullscreen, "failed to toggle fullscreen");
                        }
                        continue;
                    }
                    if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                        cap.on_key_down(sc);
                    }
                }
                Event::KeyUp {
                    scancode: Some(sc), ..
                } => {
                    if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                        cap.on_key_up(sc);
                    }
                }
                Event::MouseMotion {
                    x, y, xrel, yrel, ..
                } => {
                    if let Some(st) = stream.as_mut() {
                        let video = st.last_video;
                        if let Some(cap) = st.capture.as_mut() {
                            if cap.desktop() {
                                // Desktop model: the cursor's window position through the
                                // letterbox (same mapping as a pointer-mode finger).
                                // Before the first decoded frame there is nothing to map
                                // onto — dropped, like touch.
                                if let Some(video) = video {
                                    let (lw, lh) = window.size();
                                    let nx = x / lw.max(1) as f32;
                                    let ny = y / lh.max(1) as f32;
                                    let (ax, ay, aw, ah) =
                                        finger_to_content(window.size_in_pixels(), video, nx, ny);
                                    cap.on_motion_abs(Abs {
                                        x: ax,
                                        y: ay,
                                        w: aw,
                                        h: ah,
                                    });
                                }
                            } else {
                                cap.on_motion(xrel, yrel);
                            }
                        }
                    }
                }
                Event::MouseButtonDown { mouse_btn, .. } => {
                    if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                        if !cap.captured() {
                            // The engaging click is suppressed toward the host.
                            cap.engage();
                            apply_capture(
                                &mut window,
                                &mouse,
                                true,
                                cap.desktop(),
                                inhibit_shortcuts,
                            );
                        } else {
                            cap.on_button_down(mouse_btn);
                        }
                    }
                }
                Event::MouseButtonUp { mouse_btn, .. } => {
                    if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                        cap.on_button_up(mouse_btn);
                    }
                }
                Event::MouseWheel { x, y, .. } => {
                    if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                        cap.on_wheel(x, y);
                    }
                }
                // Touchscreen fingers (the Deck's glass) → the session's touch model
                // (Trackpad/Pointer mouse, or real Touch passthrough), routed by `Capture`.
                // `x`/`y` are window-normalized (0..1); the dispatcher gets physical window
                // pixels AND the letterbox mapping. Only DIRECT devices (touchscreens) — an
                // INDIRECT trackpad drives the mouse and must not be mistaken for one. A
                // three-finger tap returns `cycle` → bump the stats tier, same as Ctrl+⌥+⇧+S.
                Event::FingerDown {
                    touch_id,
                    finger_id,
                    x,
                    y,
                    timestamp,
                    ..
                } => {
                    if is_direct_touch(touch_id)
                        && dispatch_finger(
                            FingerPhase::Down,
                            &window,
                            &mut stream,
                            finger_id,
                            x,
                            y,
                            timestamp,
                        )
                    {
                        bump_stats_tier(&mut stats_verbosity, &mut stream, &presenter);
                    }
                }
                Event::FingerMotion {
                    touch_id,
                    finger_id,
                    x,
                    y,
                    timestamp,
                    ..
                } => {
                    if is_direct_touch(touch_id)
                        && dispatch_finger(
                            FingerPhase::Move,
                            &window,
                            &mut stream,
                            finger_id,
                            x,
                            y,
                            timestamp,
                        )
                    {
                        bump_stats_tier(&mut stats_verbosity, &mut stream, &presenter);
                    }
                }
                Event::FingerUp {
                    touch_id,
                    finger_id,
                    x,
                    y,
                    timestamp,
                    ..
                } => {
                    if is_direct_touch(touch_id)
                        && dispatch_finger(
                            FingerPhase::Up,
                            &window,
                            &mut stream,
                            finger_id,
                            x,
                            y,
                            timestamp,
                        )
                    {
                        bump_stats_tier(&mut stats_verbosity, &mut stream, &presenter);
                    }
                }
                // The wake forwarder's FrameWake (and any other user event): pure
                // wake-up — the frame drain below runs this iteration either way.
                Event::User { .. } => {}
                // Everything else (gamepad add/remove/button/axis/touchpad/sensor…) is
                // the pumped gamepad worker's — it ignores what it doesn't know.
                other => pump.handle_event(other),
            }
        }
        // Who owns the pad right now: window focus, plus Gaming Mode's overlay signal where it
        // exists (one relaxed atomic load; `None` off gamescope). Edge-triggered — the service
        // hears only about CHANGES, so an open QAM doesn't re-flush the pads every iteration.
        #[cfg(target_os = "linux")]
        let overlay_now = overlay_focus.as_ref().is_some_and(|of| of.is_open());
        #[cfg(not(target_os = "linux"))]
        let overlay_now = false;
        let want_mask = focus_lost || overlay_now;
        if want_mask != mask_applied {
            mask_applied = want_mask;
            gamepad.set_masked(want_mask);
        }
        pump.tick();
        // One coalesced MouseMove per iteration — pure motion must reach the host
        // without waiting for a click/key to flush it.
        if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
            cap.flush_motion();
        }
        // Cursor channel (M2): drain forwarded shape/state and drive the local OS cursor —
        // only meaningful in the desktop mouse model (capture's relative lock hides it).
        if let Some(st) = stream.as_mut() {
            // Host-framebuffer px → window px: the aspect-fit factor the video is drawn at
            // (same `min(surface/content)` as `finger_to_content`). The forwarded pointer is
            // resampled by it so a high-DPI host's oversized bitmap lands sized to the streamed
            // desktop rather than ballooning. 1:1 until the first frame gives `last_video`.
            let fit_scale = st.last_video.map_or(1.0, |(vw, vh)| {
                let (pw, ph) = window.size_in_pixels();
                (pw as f32 / vw.max(1) as f32).min(ph as f32 / vh.max(1) as f32)
            });
            if let (Some(chan), Some(c)) = (st.cursor_chan.as_mut(), st.connector.as_ref()) {
                let desktop_active = st
                    .capture
                    .as_ref()
                    .is_some_and(|cap| cap.captured() && cap.desktop());
                chan.pump(c, &mouse, desktop_active, fit_scale);
                // §8 mid-stream render flip: tell the host who renders the pointer whenever the
                // local model changes. The host may composite one ONLY while we hold a grabbed,
                // hidden pointer — the capture model, engaged — because that is the one state
                // with no local cursor on screen. Note this is deliberately NOT `desktop_active`:
                // a RELEASED pointer leaves the ordinary window cursor visible over the video,
                // and a host-composited pointer then sits UNDER it as a second cursor that never
                // moves (released forwards no motion), which reads on glass as a frozen
                // duplicate. Released therefore counts as "we draw it" — the host stops
                // compositing and keeps forwarding shape/state, so re-engaging is seamless.
                // One edge-detected reconciler covers the chord, the M3 auto-flip, and
                // engage/release alike.
                let client_draws = match st.capture.as_ref() {
                    Some(cap) => !cap.captured() || cap.desktop(),
                    None => true,
                };
                if chan.negotiated() && st.sent_client_draws != Some(client_draws) {
                    st.sent_client_draws = Some(client_draws);
                    let _ = c.set_cursor_render(client_draws);
                }
            }
            // M3 — host-driven mode flip: `relative_hint` set = a host app grabbed/hid the
            // pointer (run captured relative, like a game expects); clear = the desktop is
            // back (return to absolute, local cursor reappearing at the host's position).
            // Edge-triggered so a user's manual chord isn't fought: the override latch
            // holds until the HOST's intent next changes.
            let hint_state = st.cursor_chan.as_ref().and_then(|ch| ch.state());
            if let Some(hs) = hint_state {
                let hint = hs.relative_hint();
                if st.last_hint != Some(hint) {
                    st.last_hint = Some(hint);
                    st.hint_override = false;
                }
                if !st.hint_override {
                    let video = st.last_video;
                    if let Some(cap) = st.capture.as_mut() {
                        // Desired model: hint ⇒ capture (desktop off); clear ⇒ desktop on.
                        if cap.captured() && cap.set_desktop(!hint) {
                            apply_capture(
                                &mut window,
                                &mouse,
                                true,
                                cap.desktop(),
                                inhibit_shortcuts,
                            );
                            if cap.desktop() {
                                // Reappear where the host last had the pointer, so the
                                // hand-back is seamless (Parsec's positionX/Y idea).
                                if let Some(video) = video {
                                    let (wx, wy) = content_to_window(
                                        window.size(),
                                        window.size_in_pixels(),
                                        video,
                                        hs.x,
                                        hs.y,
                                    );
                                    mouse.warp_mouse_in_window(&window, wx, wy);
                                }
                            }
                            tracing::info!(
                                desktop = cap.desktop(),
                                "host cursor hint: mouse model flipped"
                            );
                        }
                    }
                }
            }
        }

        // Text input follows the overlay's editing state (edge-triggered).
        let want_text = overlay.as_ref().is_some_and(|o| o.text_input_active());
        if want_text != text_input_on {
            text_input_on = want_text;
            let ti = video.text_input();
            if want_text {
                ti.start(&window);
            } else {
                ti.stop(&window);
            }
        }

        // Controller escape chord: release capture (+ leave fullscreen on desktop — under
        // a `--fullscreen` gamescope launch there is nothing to release into). Only
        // emitted while a session is attached.
        while escape_rx.try_recv().is_ok() {
            if let Some(cap) = stream.as_mut().and_then(|s| s.capture.as_mut()) {
                if cap.release(true) {
                    apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                }
            }
            if fullscreen && !opts.fullscreen {
                fullscreen = false;
                let _ = window.set_fullscreen(false);
            }
        }
        // Escape chord held past the threshold: the controller's Ctrl+Alt+Shift+D.
        if disconnect_rx.try_recv().is_ok() {
            if let Some(st) = &mut stream {
                tracing::info!("controller chord: disconnect");
                st.request_quit();
                apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
            }
        }

        // --- Browse: menu navigation + overlay actions (console visible only) ------------
        if let ModeCtl::Browse(on_action) = &mut mode {
            // Menu events flow while no stream is engaged — including a connect in
            // flight (connector still None), so B can cancel the dial. Once attached,
            // the gamepad worker forwards raw input instead of translating.
            if stream.as_ref().is_none_or(|s| s.connector.is_none()) {
                while let Ok(ev) = menu_rx.try_recv() {
                    if let Some(o) = overlay.as_mut() {
                        if let Some(pulse) = o.handle_menu(ev) {
                            gamepad.menu_rumble(pulse);
                        }
                    }
                }
            }
            if let Some(action) = overlay.as_mut().and_then(|o| o.take_action()) {
                match action {
                    OverlayAction::CancelConnect => {
                        if let Some(st) = &mut stream {
                            if st.connector.is_none() && !st.canceled {
                                tracing::info!("connect canceled from the console");
                                st.canceled = true;
                                st.handle.stop.store(true, Ordering::SeqCst);
                            }
                        }
                    }
                    // The console already toasted "Link copied"; a clipboard SDL refuses is
                    // worth a log line but not worth contradicting the toast over.
                    OverlayAction::CopyText(text) => {
                        if let Err(e) = video.clipboard().set_clipboard_text(&text) {
                            tracing::warn!(error = %e, "copying to the clipboard");
                        }
                    }
                    action => {
                        let force_software = Arc::new(AtomicBool::new(false));
                        match on_action(
                            action,
                            &gamepad,
                            native,
                            force_software.clone(),
                            presenter.vulkan_decode(),
                        ) {
                            ActionOutcome::Handled => {}
                            ActionOutcome::Start(mut params) => {
                                if opts.match_window.is_some() {
                                    apply_match_window(
                                        &mut params,
                                        &window,
                                        opts.render_scale,
                                        opts.render_scale_max_dim,
                                    );
                                }
                                // A live pump here would be DETACHED by the assignment
                                // below — `StreamState` has no `Drop`, so its thread
                                // would keep decoding onto the shared Vulkan device that
                                // gets destroyed at exit. The console normally gates the
                                // launch behind `in_stream`/`connecting`, but M8's
                                // Reconnecting phase is the first state that is neither
                                // while the stream is still alive. Every other
                                // replacement site takes-and-shuts-down; so does this
                                // one.
                                if let Some(prev) = stream.take() {
                                    tracing::warn!(
                                        "launch while a session was still attached — \
                                         stopping it first"
                                    );
                                    prev.shutdown();
                                }
                                stream = Some(StreamState::new(
                                    *params,
                                    force_software,
                                    events.event_sender(),
                                    present_priority,
                                    native.refresh_hz,
                                ));
                                if let Some(o) = overlay.as_mut() {
                                    o.session_phase(SessionPhase::Connecting);
                                }
                            }
                            ActionOutcome::Quit => break Some(Outcome::Ended(None)),
                        }
                    }
                }
            }
        }

        // --- Session events --------------------------------------------------------------
        // `stream` may become None mid-drain (browse-mode session end) — re-borrow each
        // event, act, and stop draining on the terminal ones.
        while let Some(st) = stream.as_mut() {
            let Ok(ev) = st.handle.events.try_recv() else {
                break;
            };
            match ev {
                SessionEvent::Connected {
                    connector: c,
                    mode: m,
                    fingerprint,
                } => {
                    if st.canceled {
                        // The dial won the race against the cancel: quit-close the host
                        // side now; the stop flag (already set) ends the pump and the
                        // Ended path routes back to the console without ever engaging.
                        c.disconnect_quit();
                        continue;
                    }
                    st.mode_line = format!("{}×{}@{}", m.width, m.height, m.refresh_hz);
                    tracing::info!(mode = %st.mode_line, "connected");
                    window
                        .set_title(&format!("{} · {}", opts.window_title, st.mode_line))
                        .ok();
                    gamepad.attach(c.clone());
                    st.clock_offset = Some(c.clock_offset_shared());
                    st.video_e2e = Some(c.video_e2e_shared());
                    // gamescope's EIS grants only a relative pointer — absolute sends
                    // would be dropped, so the desktop model is pinned off there. Auto
                    // (an older host that didn't say) stays allowed: Windows hosts and
                    // pre-Welcome-compositor Linux hosts both take absolute.
                    let abs_ok = c.resolved_compositor != CompositorPref::Gamescope;
                    if opts.mouse_mode == MouseMode::Desktop && !abs_ok {
                        tracing::info!(
                            "desktop mouse mode unavailable on a gamescope host \
                             (relative-only input) — using capture"
                        );
                    }
                    let mut cap = Capture::new(
                        c.clone(),
                        opts.touch_mode,
                        opts.invert_scroll,
                        opts.mouse_mode,
                        abs_ok,
                    );
                    cap.engage(); // capture engages when the stream starts (ui_stream parity)
                    apply_capture(&mut window, &mouse, true, cap.desktop(), inhibit_shortcuts);
                    st.capture = Some(cap);
                    st.cursor_chan = Some(crate::cursor::CursorChannel::new(&c));
                    st.connector = Some(c);
                    if let Some(f) = opts.on_connected.as_mut() {
                        f(fingerprint);
                    }
                    if let Some(o) = overlay.as_mut() {
                        o.session_phase(SessionPhase::Streaming);
                    }
                }
                SessionEvent::Stats(s) => {
                    st.osd_text = stats_text(
                        stats_verbosity,
                        &st.mode_line,
                        &s,
                        &st.presented,
                        st.hdr,
                        presenter.hdr_active(),
                        st.hdr_untonemapped,
                        st.profile.as_deref(),
                    );
                    if stats_verbosity != StatsVerbosity::Off {
                        // The stdout line is the machine interface (shell status card,
                        // scripts) — always the full Detailed text, whatever the OSD tier.
                        let full = stats_text(
                            StatsVerbosity::Detailed,
                            &st.mode_line,
                            &s,
                            &st.presented,
                            st.hdr,
                            presenter.hdr_active(),
                            st.hdr_untonemapped,
                            st.profile.as_deref(),
                        );
                        println!("stats: {}", full.replace('\n', " | "));
                    }
                    st.last_stats = Some(s);
                }
                SessionEvent::Failed {
                    msg,
                    trust_rejected,
                } => match &mode {
                    ModeCtl::Single(_) => {
                        break 'main Some(Outcome::ConnectFailed {
                            msg,
                            trust_rejected,
                        })
                    }
                    ModeCtl::Browse(_) => {
                        tracing::warn!(%msg, "connect failed — back to the console");
                        let canceled = st.canceled;
                        if let Some(st) = stream.take() {
                            st.shutdown();
                        }
                        apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                        if let Some(o) = overlay.as_mut() {
                            // A user-canceled dial ends silently — no error scene.
                            if canceled {
                                o.session_phase(SessionPhase::Ended(None));
                            } else {
                                o.session_phase(SessionPhase::Failed(&msg));
                            }
                        }
                        break;
                    }
                },
                SessionEvent::Ended(reason) => {
                    gamepad.detach();
                    if let Some(cap) = &mut st.capture {
                        cap.release(true);
                    }
                    apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                    match &mode {
                        ModeCtl::Single(_) => break 'main Some(Outcome::Ended(reason)),
                        ModeCtl::Browse(_) => {
                            window.set_title(&opts.window_title).ok();
                            let canceled = st.canceled;
                            if let Some(st) = stream.take() {
                                st.shutdown();
                            }
                            if let Some(o) = overlay.as_mut() {
                                // A canceled connect's end carries no reason strip.
                                o.session_phase(SessionPhase::Ended(if canceled {
                                    None
                                } else {
                                    reason.as_deref()
                                }));
                            }
                            break;
                        }
                    }
                }
                // M8's HEVC path, as a first-class flow rather than a dead session: the
                // negotiated codec ran out of decode rungs, so re-dial the SAME host with
                // that codec removed from the advertised caps and let the host pick
                // again. The pump computed the retry (never re-offering the failed codec,
                // and — when the CODEC is what has no CPU rung — never offering one
                // without a CPU rung either) and left nothing of its own running before
                // sending this: the mid-stream site joins the audio/pad/clipboard threads
                // and drops the connector, the construction-time site never spawned them.
                // So starting the new session here is a clean start, not an overlap.
                //
                // Applies in BOTH modes. In single (`--connect`) mode there is no console
                // to fall back to, which is exactly where limping-on-software used to be
                // the only option; browse mode gets the same retry plus a toast.
                SessionEvent::CodecFallback {
                    exclude_codecs,
                    retry_caps,
                    msg,
                } => {
                    tracing::warn!(
                        %msg,
                        exclude_codecs,
                        retry_caps,
                        "decode ladder exhausted — reconnecting with reduced codec caps"
                    );
                    gamepad.detach();
                    if let Some(cap) = &mut st.capture {
                        cap.release(true);
                    }
                    apply_capture(&mut window, &mouse, false, false, inhibit_shortcuts);
                    // Widen the exclusion rather than replace it: a second fallback in the
                    // same run must not re-offer what the first one already ruled out.
                    let mut params = st.params.clone();
                    params.exclude_codecs |= exclude_codecs;
                    // The mode this session ENDED on, not the one it dialled with: a
                    // mid-session `Reconfigure` the host accepted lives only in the
                    // connector, and `st.params` is a clone taken at launch — re-sending
                    // it would silently undo the switch on the retry.
                    if let Some(c) = &st.connector {
                        params.mode = c.mode();
                    }
                    // ...and then the window follower on top, exactly as
                    // `ActionOutcome::Start` does, so a retry lands on the size the
                    // window is NOW rather than the size it was at launch.
                    if opts.match_window.is_some() {
                        apply_match_window(
                            &mut params,
                            &window,
                            opts.render_scale,
                            opts.render_scale_max_dim,
                        );
                    }
                    // A FRESH demote flag, like `ActionOutcome::Start` builds — never the
                    // old session's. `force_software` is a latch the presenter sets when
                    // the hardware PRESENT path fails three times; inheriting it made an
                    // HEVC→H.264 retry open a SOFTWARE H.264 decoder on a box with
                    // perfectly good hardware H.264. It is shared with `params` because
                    // both ends of it belong to this presenter.
                    let force_software = Arc::new(AtomicBool::new(false));
                    params.force_software = force_software.clone();
                    // ⚠ `params.launch` rides along VERBATIM, and that is a deliberate
                    // choice between two wrong answers, not an assumption of idempotence.
                    // The host has no "already running → attach" branch on the launch
                    // path (`punktfunk-host`'s `native/stream.rs` launches
                    // unconditionally; its "launched ONCE" guarantee is scoped to
                    // mid-stream rebuilds WITHIN a session), and the game survives the
                    // session end under the default `GameOnSessionEnd::Keep`. So the
                    // re-send is idempotent only where the LAUNCHER dedupes it —
                    // `steam://rungameid` focuses the running copy, an Epic/AUMID URI
                    // likewise — while a `gog:`/`custom:` target really does start a
                    // second copy. Dropping the field instead is worse where it matters
                    // most: on Linux the per-session gamescope is re-adopted through
                    // `pf-vdisplay`'s display registry, whose reuse key INCLUDES the
                    // launch command, so a retry without it would miss the lingering
                    // display and orphan the running game inside it. Keeping it is the
                    // only option that preserves that attach; the real fix is host-side
                    // (an idempotency key on `Hello::launch`, or a running-title check
                    // before the spawn) and is not M8's to make.
                    //
                    // Known and unfixed here for the same reason: the RETRY's game lease
                    // cannot adopt a game that predates its own launch stamp (`procscan`
                    // rejects anything started more than 2 s before it), so a reconnected
                    // session has no game-exit detection for the rest of its life.
                    if let Some(st) = stream.take() {
                        st.shutdown();
                    }
                    if let Some(o) = overlay.as_mut() {
                        o.session_phase(SessionPhase::Reconnecting(&msg));
                    }
                    stream = Some(StreamState::new(
                        params,
                        force_software,
                        events.event_sender(),
                        present_priority,
                        native.refresh_hz,
                    ));
                    break;
                }
            }
        }

        // HUD/title follow the live mode slot on ANY accepted switch — also when the
        // match-window follower is off (a switch can come from elsewhere, e.g. the
        // PUNKTFUNK_DEBUG_RECONFIGURE lever, or a host-side corrective rollback).
        if let Some(st) = stream.as_mut() {
            hud_mode_tick(st, &mut window, &opts.window_title);
        }
        // --- Match-window (D2): debounced mode-follow ----
        if let Some(persist) = opts.match_window.as_mut() {
            if let Some(st) = stream.as_mut() {
                resize_tick(
                    st,
                    &mut window,
                    persist.as_mut(),
                    opts.render_scale,
                    opts.render_scale_max_dim,
                );
            }
        }
        // Resize overlay timeout: a switch the host rejected/capped never delivers the exact
        // target frame — drop the scrim so it can't linger. A no-op unless one is showing.
        if let Some(st) = stream.as_mut() {
            st.resize_overlay.tick(Instant::now());
        }

        // --- Console UI: damage-driven overlay re-render for this iteration --------------
        if let Some(o) = overlay.as_mut() {
            let (pw, ph) = window.size_in_pixels();
            let (stats, hint) = match &stream {
                Some(st) if st.connector.is_some() => {
                    let hint = match &st.capture {
                        Some(cap) if !cap.captured() => Some(if gamepad.active().is_some() {
                            HINT_WITH_PAD
                        } else {
                            HINT_KEYBOARD
                        }),
                        _ => None,
                    };
                    (
                        (stats_verbosity != StatsVerbosity::Off && !st.osd_text.is_empty())
                            .then_some(st.osd_text.as_str()),
                        hint,
                    )
                }
                _ => (None, None),
            };
            let pad = gamepad.active();
            let pads = gamepad.pads();
            let resizing = stream
                .as_ref()
                .is_some_and(|st| st.connector.is_some() && st.resize_overlay.active());
            // Read live from the session's control rather than mirrored into StreamState: the
            // pump is what knows whether an uplink exists (it may have failed to open), and a
            // mirrored copy would be the thing that goes stale at session end.
            let mic_muted = stream.as_ref().is_some_and(|st| st.handle.mic.muted());
            let ctx = FrameCtx {
                width: pw,
                height: ph,
                // Re-read per frame, not once at startup: dragging the window to a second monitor
                // with a different scale (or changing the scale setting live) updates this, and the
                // overlay's damage gate picks the new value up on the next redraw.
                scale: overlay_scale(window.display_scale(), osd_scale_pref),
                stats,
                hint,
                mic_muted,
                resizing,
                pad: pad.as_ref().map(|p| p.name.as_str()),
                pad_pref: pad.as_ref().map(|p| p.pref),
                pads: &pads,
            };
            match o.frame(&ctx) {
                Ok(f) => overlay_frame = f,
                Err(e) => {
                    if matches!(mode, ModeCtl::Browse(_)) {
                        return Err(e).context("console UI frame (required for --browse)");
                    }
                    tracing::warn!(error = %format!("{e:#}"),
                        "overlay frame failed — disabling the console UI");
                    overlay = None;
                    overlay_frame = None;
                }
            }
        }

        // --- Frames: drain to the newest, upload + present -------------------------------
        let mut presented_video = false;
        if let Some(st) = &mut stream {
            // Mastering metadata (0xCE) → the presentation engine, ahead of the frame
            // that needs it. Low-rate (session start + mastering changes / keyframes).
            if let Some(c) = &st.connector {
                while let Ok(m) = c.next_hdr_meta(Duration::ZERO) {
                    presenter.set_hdr_metadata(m);
                }
            }
            // Present-wait completions drive the latch clock, the glass gate, and the
            // host-facing grid — drained every pass (a 1 Hz batch would starve all
            // three; the waiter's SDL wake pairs with this so completions never wait
            // out the event timeout).
            if presenter.present_timing_active() {
                let samples = presenter.take_presented_samples();
                if !samples.is_empty() {
                    let clock_offset_ns = st
                        .clock_offset
                        .as_ref()
                        .map_or(0, |o| o.load(Ordering::Relaxed));
                    let period = st.clock.period_ns();
                    let mut stamps = Vec::with_capacity(samples.len());
                    for s in &samples {
                        let e2e = (s.displayed_ns as i128 + clock_offset_ns as i128
                            - s.pts_ns as i128)
                            .max(0) as u64;
                        if e2e > 0 && e2e < 10_000_000_000 {
                            st.win_e2e_us.push(e2e / 1000);
                            // Hand the audio plane the figure it has to hit. This is the TRUE
                            // on-glass branch, so it is the best reference we can offer.
                            if let Some(c) = st.video_e2e.as_ref() {
                                c.store(e2e, Ordering::Relaxed);
                            }
                        }
                        st.win_disp_us
                            .push(s.displayed_ns.saturating_sub(s.decoded_ns) / 1000);
                        // The display split (WP4): our pipeline vs the vsync latch. Only
                        // meaningful with true glass stamps, which is exactly when this
                        // branch runs.
                        st.win_pace_us
                            .push(s.submitted_ns.saturating_sub(s.decoded_ns) / 1000);
                        st.win_latch_us
                            .push(s.displayed_ns.saturating_sub(s.submitted_ns) / 1000);
                        // Latch miss (the adaptive margin's error signal): glass later
                        // than one panel period past submit, PLUS the lead we already
                        // applied — i.e. the slot we aimed at was missed. Measuring the
                        // real latch rather than the store's own evictions is the
                        // Android 0.23.0 correction: policy drops happen whenever the
                        // stream out-runs the panel and say nothing about the latch, and
                        // widening on them walked the margin to its ceiling on healthy
                        // devices, re-imposing the very display latency it had removed.
                        if st.store.is_smoothing()
                            && s.displayed_ns.saturating_sub(s.submitted_ns) > period + st.margin_ns
                        {
                            st.win_misses += 1;
                        }
                        stamps.push(s.displayed_ns);
                    }
                    st.clock.note_batch(&stamps);
                    // Same stamps answer "is VRR live" — the panel either quantizes them
                    // to its grid or follows our cadence. Evidence only counts from a
                    // window whose presents were flowing normally: a distressed pipeline
                    // (stale force-opens) smears spacings for reasons that have nothing
                    // to do with the panel, and on glass that flapped the verdict.
                    //
                    // ⚠ The reference is the DISPLAY MODE's period, NOT the learned one.
                    // The learned grid comes from our own present spacings, and a stream
                    // running below panel rate only ever produces multiples ≥ its frame
                    // interval — so the learner adopts our cadence as "the grid" and every
                    // delta then looks on-grid by construction. Measured on .21
                    // (2026-08-02): a 40-50 fps stream on a 60 Hz panel learned 18-22 ms
                    // and the probe reported VRR on a display with VRR provably disabled.
                    // The vblank grid is the mode's refresh; that is what presents
                    // quantize to when VRR is off.
                    //
                    // ⚠⚠ And it is only asked under a FIFO-family mode. The whole test
                    // rests on "with VRR off, a present waits for vblank" — MAILBOX and
                    // IMMEDIATE deliberately break that, so their stamps are never
                    // grid-quantized and the probe would call every mailbox session VRR.
                    // Measured on .21: same panel, same second — fifo read `no`
                    // (correct, period 16.56 ms), mailbox read `yes` (wrong). Outside
                    // FIFO the honest answer is "cannot tell", i.e. Unknown.
                    let healthy = st.presented.forced == 0;
                    if presenter.vblank_locked() {
                        st.cadence.note(&stamps, st.mode_period_ns, healthy);
                    }
                    // Phase-locked capture, the presenter's half: publish the grid the
                    // local clock just learned — a recent TRUE on-glass instant plus
                    // the latch period — for the pump's ~1 Hz PhaseReport. One learner
                    // feeds both, so the report and the scheduler cannot disagree.
                    if let Some(grid) = &st.latch_grid {
                        grid.period_ns
                            .store(st.clock.period_ns(), Ordering::Relaxed);
                        grid.anchor_ns
                            .store(st.clock.anchor_ns(), Ordering::Relaxed);
                    }
                }
            }

            // Intake into the intent store: a newest-wins slot under latency (the
            // shipped drain, now with displacement counters), the smoothing FIFO under
            // smoothness. PyroWave collapses smoothness to latency for the stream: its
            // plane-ring retirement accounting assumes the newest-wins hand-off
            // (`video_pyrowave::RETIRE_HANDOVERS`), and all-intra frames make
            // buffering moot anyway.
            while let Ok(f) = st.frames.try_recv() {
                #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
                if st.store.is_smoothing() && matches!(f.image, DecodedImage::PyroWave(_)) {
                    st.store.force_latency();
                    if !st.pyro_latency_forced {
                        st.pyro_latency_forced = true;
                        tracing::info!(
                            "PyroWave stream — smoothness buffering does not apply \
                             (latency pacing)"
                        );
                    }
                }
                st.store.submit(f);
            }

            // One frame out, by intent: latency takes the newest whenever the glass
            // gate allows; smoothness serves at most one frame per latch slot (the
            // preroll/underflow behavior lives in the store).
            let now_ns = session::now_ns();
            let mut slot_target = 0u64;
            let mut to_present = if st.store.is_smoothing() {
                let target = st
                    .clock
                    .next_slot_after(now_ns.saturating_add(st.margin_ns));
                if target != st.last_target_ns {
                    slot_target = target;
                    st.store.take()
                } else {
                    None
                }
            } else {
                st.store.take()
            };
            // The FIFO glass budget: one undisplayed present in flight, so the
            // swapchain's own FIFO can never become a standing queue (a measured
            // 11-13 ms at 60 Hz on MAILBOX-less drivers). Only FIFO modes queue and
            // only present timing can count, so everywhere else this stays inert and
            // behavior is the shipped arrival pacing.
            if pacing_active && presenter.needs_glass_gate() && presenter.present_timing_active() {
                if let Some(f) = to_present.take() {
                    if st.gate.open(presenter.presents_outstanding(), now_ns) {
                        to_present = Some(f);
                    } else {
                        // Parked: a newest-wins store replaces it if a fresher frame
                        // lands; the waiter's wake (or the 100 ms stale force-open)
                        // retries.
                        st.store.put_back(f);
                    }
                }
            }
            if let Some(f) = to_present {
                // Resize END: a frame at the steered target size means the sharp new-mode
                // picture is here — lift the scrim. A no-op unless a switch is in flight.
                let (fw, fh) = f.image.dimensions();
                st.resize_overlay.decoded(fw, fh);
                st.last_video = Some((fw, fh)); // touch passthrough's source rect
                let DecodedFrame {
                    pts_ns,
                    decoded_ns,
                    image,
                } = f;
                let did_present = match image {
                    // PyroWave planar frames: already on the presenter's device and
                    // fence-complete — a present failure has no demote rung (nothing
                    // else decodes the codec); only device loss ends the session.
                    #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
                    DecodedImage::PyroWave(f) => {
                        // The wavelet stream carries the negotiated ColorInfo (no VUI): an
                        // HDR (PQ) pyrowave session presents through the HDR10 path exactly
                        // like the H.26x codecs (design/pyrowave-444-hdr.md Phase 3).
                        st.hdr = f.color.is_pq();
                        st.hdr_untonemapped = false;
                        match presenter.present(
                            &window,
                            FrameInput::PyroWave(f),
                            overlay_frame.as_ref(),
                        ) {
                            Ok(p) => {
                                st.pyro_present_warned = false;
                                p
                            }
                            Err(e) => {
                                if device_lost(&e) {
                                    return Err(e)
                                        .context("GPU device lost — the session cannot continue");
                                }
                                if !st.pyro_present_warned {
                                    st.pyro_present_warned = true;
                                    tracing::warn!(
                                        error = %format!("{e:#}"),
                                        "pyrowave present failed — suppressing repeats until it recovers"
                                    );
                                }
                                false
                            }
                        }
                    }
                    DecodedImage::Cpu(c) => {
                        st.hdr = c.color.is_pq();
                        // Since M8 the software lane uploads planes into the SAME planar
                        // CSC pass as the hardware lanes, so a PQ stream is tone-mapped
                        // there exactly like theirs — the badge no longer has to warn
                        // that this lane shows PQ raw, because it does not.
                        st.hdr_untonemapped = false;
                        // Same treatment as the pyrowave arm below, and for the same
                        // reason: since M8 this arm allocates three plane images (plus
                        // memory and views) on every size change and runs a render pass,
                        // so it has failure modes a staging upload never had — and it is
                        // the LAST rung, so a present failure has nothing left to demote
                        // to. Drop the frame and keep the session; only a lost device
                        // ends it.
                        match presenter.present(
                            &window,
                            FrameInput::Cpu(&c),
                            overlay_frame.as_ref(),
                        ) {
                            Ok(p) => {
                                st.cpu_present_warned = false;
                                p
                            }
                            Err(e) => {
                                if device_lost(&e) {
                                    return Err(e)
                                        .context("GPU device lost — the session cannot continue");
                                }
                                if !st.cpu_present_warned {
                                    st.cpu_present_warned = true;
                                    tracing::warn!(
                                        error = %format!("{e:#}"),
                                        "software present failed — suppressing repeats until it recovers"
                                    );
                                }
                                false
                            }
                        }
                    }
                    // The VAAPI rung's output: dmabuf fds plus a plane layout, guard
                    // opaque. (This arm took libavcodec's VAAPI rung too until M10; the
                    // import and its failure-streak demotion were identical for both.)
                    #[cfg(target_os = "linux")]
                    DecodedImage::NativeDmabuf(d)
                        if presenter.supports_dmabuf() && !st.dmabuf_demoted =>
                    {
                        st.hdr = d.color.is_pq();
                        st.hdr_untonemapped = false;
                        match presenter.present(
                            &window,
                            FrameInput::Dmabuf(d),
                            overlay_frame.as_ref(),
                        ) {
                            Ok(p) => {
                                st.hw_fails = 0;
                                p
                            }
                            // Import/CSC failure is survivable (the stream continues on
                            // the next frame) — but a streak means this box can't do the
                            // hw path: demote the decoder to software, same contract as
                            // the GTK presenter's GL-converter failures. A lost DEVICE
                            // is not survivable and must not demote — see [`device_lost`].
                            Err(e) => {
                                if device_lost(&e) {
                                    return Err(e)
                                        .context("GPU device lost — the session cannot continue");
                                }
                                st.hw_fails += 1;
                                tracing::warn!(error = %format!("{e:#}"), fails = st.hw_fails,
                                    "hardware present failed");
                                if st.hw_fails >= 3 && !st.dmabuf_demoted {
                                    st.dmabuf_demoted = true;
                                    tracing::warn!("demoting the decoder to software");
                                    st.force_software.store(true, Ordering::Relaxed);
                                }
                                false
                            }
                        }
                    }
                    #[cfg(target_os = "linux")]
                    DecodedImage::NativeDmabuf(_) => {
                        // No import extensions on this device (or already demoted) — the
                        // pump rebuilds the decoder as software; frames flow again soon.
                        if !st.dmabuf_demoted {
                            st.dmabuf_demoted = true;
                            tracing::warn!(
                                "no dmabuf import support on this device — demoting the \
                                 decoder to software"
                            );
                            st.force_software.store(true, Ordering::Relaxed);
                        }
                        false
                    }
                    // D3D11VA: shared-texture import, same gate + failure-streak
                    // demotion contract as the dmabuf path.
                    #[cfg(windows)]
                    DecodedImage::D3d11(d) if presenter.supports_d3d11() && !st.dmabuf_demoted => {
                        st.hdr = d.color.is_pq();
                        st.hdr_untonemapped = false;
                        match presenter.present(
                            &window,
                            FrameInput::D3d11(d),
                            overlay_frame.as_ref(),
                        ) {
                            Ok(p) => {
                                st.hw_fails = 0;
                                p
                            }
                            Err(e) => {
                                // Lost device ⇒ unrecoverable, never demote ([`device_lost`]).
                                if device_lost(&e) {
                                    return Err(e)
                                        .context("GPU device lost — the session cannot continue");
                                }
                                st.hw_fails += 1;
                                tracing::warn!(error = %format!("{e:#}"), fails = st.hw_fails,
                                    "hardware present failed");
                                if st.hw_fails >= 3 && !st.dmabuf_demoted {
                                    st.dmabuf_demoted = true;
                                    tracing::warn!("demoting the decoder to software");
                                    st.force_software.store(true, Ordering::Relaxed);
                                }
                                false
                            }
                        }
                    }
                    #[cfg(windows)]
                    DecodedImage::D3d11(_) => {
                        // No import extensions on this device (or already demoted) — the
                        // pump rebuilds the decoder as software; frames flow again soon.
                        if !st.dmabuf_demoted {
                            st.dmabuf_demoted = true;
                            tracing::warn!(
                                "no win32 external-memory import on this device — demoting \
                                 the decoder to software"
                            );
                            st.force_software.store(true, Ordering::Relaxed);
                        }
                        false
                    }
                    // Native Vulkan Video (pf-vkdecode): decoded on the presenter's own
                    // device — present is views + CSC, no import step to gate on. Same
                    // failure-streak demotion contract as the dmabuf path. A
                    // drained/demoted frame drops through the arm below — its guard still
                    // returns the decoder's slot.
                    DecodedImage::NativeVk(v) if !st.dmabuf_demoted => {
                        st.hdr = v.color.is_pq();
                        st.hdr_untonemapped = false;
                        match presenter.present(
                            &window,
                            FrameInput::NativeVk(v),
                            overlay_frame.as_ref(),
                        ) {
                            Ok(p) => {
                                st.hw_fails = 0;
                                p
                            }
                            Err(e) => {
                                // Lost device ⇒ unrecoverable, never demote ([`device_lost`]).
                                if device_lost(&e) {
                                    return Err(e)
                                        .context("GPU device lost — the session cannot continue");
                                }
                                st.hw_fails += 1;
                                tracing::warn!(error = %format!("{e:#}"), fails = st.hw_fails,
                                    "native vulkan present failed");
                                if st.hw_fails >= 3 {
                                    st.dmabuf_demoted = true;
                                    tracing::warn!("demoting the decoder to software");
                                    st.force_software.store(true, Ordering::Relaxed);
                                }
                                false
                            }
                        }
                    }
                    DecodedImage::NativeVk(_) => false, // demoted — drain until rebuild
                };
                if did_present {
                    presented_video = true;
                    // Smoothness: this latch slot is served — one present per slot.
                    // (Set only on success: a gated or failed present leaves the slot
                    // open for the retry.)
                    if slot_target != 0 {
                        st.last_target_ns = slot_target;
                    }
                    if opts.json_status && !st.ready_announced {
                        st.ready_announced = true;
                        println!("{{\"ready\":true}}");
                    }
                    if presenter.present_timing_active() {
                        // T0.2: hand the frame's stamps to the present-wait waiter — the
                        // e2e/display samples arrive via `take_presented_samples` with a
                        // TRUE on-glass stamp instead of the submit-time one below.
                        presenter.note_presented(pts_ns, decoded_ns);
                        st.gate.note_present(now_ns);
                        st.win_out_max = st.win_out_max.max(presenter.presents_outstanding());
                    } else {
                        let displayed_ns = session::now_ns();
                        // The `displayed` stamp (same clamp rules as the pump's windows).
                        let clock_offset_ns = st
                            .clock_offset
                            .as_ref()
                            .map_or(0, |o| o.load(Ordering::Relaxed));
                        let e2e = (displayed_ns as i128 + clock_offset_ns as i128 - pts_ns as i128)
                            .max(0) as u64;
                        if e2e > 0 && e2e < 10_000_000_000 {
                            st.win_e2e_us.push(e2e / 1000);
                            // Same hand-off as the glass-stamped branch above. This one is anchored
                            // on the submit instant rather than a true latch, so it UNDERSTATES the
                            // video leg by up to a refresh period — the audio loop's deadband is
                            // wider than that, which is what keeps the approximation harmless.
                            if let Some(c) = st.video_e2e.as_ref() {
                                c.store(e2e, Ordering::Relaxed);
                            }
                        }
                        st.win_disp_us
                            .push(displayed_ns.saturating_sub(decoded_ns) / 1000);
                        // No glass stamps on this stack: the submit instant anchors an
                        // approximate grid on the mode's refresh period, so smoothness
                        // still drains one frame per (approximate) slot.
                        st.clock.note_batch(&[displayed_ns]);
                    }
                }
            }

            // Fold the presenter window into the shared stats line once per second.
            // (The on-glass samples themselves are drained every pass above — they
            // drive the latch clock and glass gate, not just this fold.)
            if st.win_start.elapsed() >= Duration::from_secs(1) {
                let (e2e_p50, e2e_p95) = session::window_percentiles(&mut st.win_e2e_us);
                let (disp_p50, _) = session::window_percentiles(&mut st.win_disp_us);
                let (pace_p50, _) = session::window_percentiles(&mut st.win_pace_us);
                let (latch_p50, _) = session::window_percentiles(&mut st.win_latch_us);
                // Drained ONCE per window and shared by the HUD and the log line below —
                // a second `take_counters` would read zeros.
                let (replaced, q_drop, q_dry) = st.store.take_counters();
                let (gated, forced) = st.gate.take_counters();
                st.presented = PresentedWindow {
                    e2e_p50_ms: e2e_p50 as f32 / 1000.0,
                    e2e_p95_ms: e2e_p95 as f32 / 1000.0,
                    display_ms: disp_p50 as f32 / 1000.0,
                    pace_ms: pace_p50 as f32 / 1000.0,
                    latch_ms: latch_p50 as f32 / 1000.0,
                    mode: presenter.present_mode_name(),
                    vrr: st.cadence.verdict(),
                    smoothing: st.store.is_smoothing(),
                    q_drop,
                    q_dry,
                    gated,
                    forced,
                };
                st.win_e2e_us.clear();
                st.win_disp_us.clear();
                st.win_pace_us.clear();
                st.win_latch_us.clear();
                st.win_start = Instant::now();
                // Adaptive slot margin (the Android presenter's measured recipe):
                // start at 0 — a fixed lead is pure display tax — and widen one step
                // per window whose measured latch misses demand it. One-way per
                // stream; the next stream restarts at 0.
                if st.store.is_smoothing() && st.win_misses > 2 && st.margin_ns < MARGIN_MAX_NS {
                    st.margin_ns = (st.margin_ns + MARGIN_STEP_NS).min(MARGIN_MAX_NS);
                    tracing::info!(
                        margin_us = st.margin_ns / 1000,
                        misses = st.win_misses,
                        "smoothness slot margin widened (measured latch misses)"
                    );
                }
                // The 1 Hz presenter line (the Apple `pf-present` analogue): emitted
                // when anything moved, or always under PUNKTFUNK_PRESENT_DEBUG=1 —
                // the field-triage instrument for the intent engine.
                if pacing_active && (present_debug || q_drop + q_dry + gated + forced > 0) {
                    tracing::info!(
                        smoothing = st.presented.smoothing,
                        mode = st.presented.mode,
                        vrr = st.presented.vrr.label(),
                        replaced,
                        q_drop,
                        q_dry,
                        gated,
                        forced,
                        misses = st.win_misses,
                        out_max = st.win_out_max,
                        pace_ms = st.presented.pace_ms,
                        latch_ms = st.presented.latch_ms,
                        period_us = st.clock.period_ns() / 1000,
                        margin_us = st.margin_ns / 1000,
                        "presenter window"
                    );
                }
                st.win_misses = 0;
                st.win_out_max = 0;
            }
        }

        // Composite the overlay every iteration when no video frame drove a present but
        // something on-screen still animates: browse-idle (library / connecting), OR a
        // mid-stream resize scrim + spinner (the host's virtual-display + encoder rebuild
        // leaves a gap with no frames — without this the spinner would freeze). FIFO
        // vsync-throttles this to the display rate; the 15 ms wait keeps it smooth.
        let resize_scrim = stream.as_ref().is_some_and(|s| s.resize_overlay.active());
        let browse_idle = matches!(mode, ModeCtl::Browse(_))
            && stream.as_ref().is_none_or(|s| s.connector.is_none());
        if !presented_video && (resize_scrim || browse_idle) {
            // The UI owns the screen again: hand the swapchain back to SDR before drawing
            // it. A finished PQ stream leaves HDR10 live, and nothing else would ever turn
            // it off — `present` re-evaluates the mode only from a frame's colour
            // signalling, and these UI presents carry no frame. Guarded inside, so this is
            // free on every ordinary idle iteration. (Deliberately NOT applied to
            // `resize_scrim`: that scrim is a mid-stream gap in a session that is still
            // HDR, and flipping there would rebuild the swapchain twice per resize.)
            if browse_idle {
                presenter.leave_hdr(&window)?;
            }
            presenter.present(&window, FrameInput::Redraw, overlay_frame.as_ref())?;
        }
    };

    // Every exit from the loop above converges here, which is why the gamepad teardown belongs
    // here and not on the individual `break`s. `gamepad.detach()` only queues the detach; the
    // close — flush, host-side GamepadRemove, and the explicit rumble-stop backstop — runs when
    // the pump drains it. Single mode broke out of the loop immediately after detaching and
    // Event::Quit never detached at all, so both left forwarded pads unflushed and, if the game
    // was rumbling at the time, still buzzing.
    pump.shutdown();
    // Join the pump BEFORE the device-wide idle: its decode submissions on the shared
    // device would race vkDeviceWaitIdle otherwise.
    if let Some(st) = stream.take() {
        st.shutdown();
    }
    // Overlay resources live on the presenter's device: quiesce the queue first, drop
    // the overlay (its Drop destroys the Skia surfaces), THEN the presenter tears down.
    presenter.wait_idle();
    drop(overlay);
    Ok(outcome)
}

/// An `SDL_DisplayMode` as the panel's REAL pixels — the `0 = native` stream mode.
///
/// SDL3 reports a display mode in SCREEN COORDINATES, not pixels, and hands you the ratio
/// between the two separately as `pixel_density`. On X11 and Windows that ratio is always
/// 1.0 (SDL never sets it there, and `SDL_video.c` normalizes the unset 0.0 up to 1.0), so
/// this is a no-op — but under a Wayland compositor doing FRACTIONAL scaling it is the
/// whole ballgame: KDE at 150 % advertises a 2560×1600 panel as 1707×1067 points with
/// `pixel_density` ≈ 1.4997, and taking `m.w`/`m.h` raw is what made "Native resolution"
/// negotiate 1706×1066 (1707×1067 even-floored by `render_scale::apply`) and stream a
/// blurry two-thirds-size image. `SDL_VIDEO_WAYLAND_SCALE_TO_DISPLAY=1` is the same fix
/// from the outside — it makes SDL report the native mode itself — which is why setting it
/// was a workaround.
///
/// The density is the exact `pixels / points` ratio SDL derived from the output, so the
/// multiplication recovers the panel size to the pixel rather than approximating it.
fn native_mode(w: i32, h: i32, pixel_density: f32, refresh_rate: f32) -> Mode {
    // A non-finite or non-positive density is SDL telling us nothing useful; 1× at least
    // preserves the pre-fix behaviour instead of collapsing the mode to zero.
    let density = if pixel_density.is_finite() && pixel_density > 0.0 {
        pixel_density
    } else {
        1.0
    };
    let px = |v: i32| (v.max(0) as f32 * density).round().max(0.0) as u32;
    Mode {
        width: px(w),
        height: px(h),
        refresh_hz: refresh_rate.round().max(0.0) as u32,
    }
}

/// Match-window (D1): replace the params' requested w/h with the window's physical pixel
/// size — even-floored (the host's `validate_dimensions` rejects odd) and clamped to a
/// sane minimum — keeping the resolved refresh. Under `--fullscreen` the window IS the
/// display, so this degenerates to the display's native mode.
fn apply_match_window(
    params: &mut SessionParams,
    window: &sdl3::video::Window,
    render_scale: f64,
    max_dim: u32,
) {
    let (pw, ph) = window.size_in_pixels();
    // × the render scale (even + codec-clamped), so match-window supersamples/undersamples exactly
    // like the fixed-mode path; 1.0 leaves the window's native pixels (the prior behaviour).
    let (w, h) = punktfunk_core::render_scale::apply(pw, ph, render_scale, max_dim);
    params.mode.width = w;
    params.mode.height = h;
    tracing::info!(
        w,
        h,
        "match-window: requesting the scaled window pixel size"
    );
}

/// Per-iteration HUD/title refresh: follow the live mode slot (updated by any accepted
/// ack — a follower request, another trigger, or a host-side corrective rollback).
fn hud_mode_tick(st: &mut StreamState, window: &mut sdl3::video::Window, title_base: &str) {
    let Some(c) = &st.connector else {
        return;
    };
    let m = c.mode();
    if st.shown_mode.is_some_and(|prev| prev != m) {
        st.mode_line = format!("{}×{}@{}", m.width, m.height, m.refresh_hz);
        tracing::info!(mode = %st.mode_line, "stream mode switched");
        let _ = window.set_title(&format!("{title_base} · {}", st.mode_line));
    }
    st.shown_mode = Some(m);
}

/// Match-window (D2) per-iteration tick: fire the debounced `Reconfigure` once ~400 ms
/// pass with no further resize events. The shared trigger discipline:
///   * physical pixels, even-floored, clamped ≥ 320×200; the current refresh is kept;
///   * ≥ 1 s between requests (the accept ack round-trips in milliseconds — it precedes
///     the host's rebuild — so the spacing also keeps at most ~one request outstanding);
///   * each distinct size is requested at most ONCE (`resize_requested`): a rejected
///     size isn't re-asked until the window changes, and a host-side rollback (accepted,
///     rebuild failed, corrective ack restored the old mode) can't loop.
fn resize_tick(
    st: &mut StreamState,
    window: &mut sdl3::video::Window,
    persist: &mut dyn FnMut(u32, u32),
    render_scale: f64,
    max_dim: u32,
) {
    let Some(c) = &st.connector else {
        return; // not connected yet — the pending stamp survives until we are
    };
    let m = c.mode();
    // × the render scale (even + codec-clamped) so a resize under Match-window targets the same
    // supersampled space the live mode is in; 1.0 leaves the window's native pixels. resize_decision
    // re-normalizes idempotently.
    let (pw, ph) = window.size_in_pixels();
    let pixel_size = punktfunk_core::render_scale::apply(pw, ph, render_scale, max_dim);
    match resize_decision(
        Instant::now(),
        &mut st.resize_pending,
        st.resize_sent_at,
        st.resize_requested,
        (m.width, m.height),
        pixel_size,
    ) {
        ResizeAction::Wait => {}
        ResizeAction::Settled(target) => {
            // The debounce settled: persist the window's LOGICAL size for the next
            // launch (its window is created in logical units) even when no request goes
            // out (e.g. resized back to the streamed size).
            let (lw, lh) = window.size();
            persist(lw, lh);
            let Some((w, h)) = target else { return };
            tracing::info!(w, h, "window resized — requesting mode switch");
            if c.request_mode(Mode {
                width: w,
                height: h,
                refresh_hz: m.refresh_hz,
            })
            .is_err()
            {
                tracing::warn!("mode-switch request dropped — control channel closed");
            }
            st.resize_requested = Some((w, h));
            st.resize_sent_at = Some(Instant::now());
            // Show the scrim + spinner until a frame at this size lands (or the timeout):
            // the live drag itself stays sharp; only the host's rebuild gap is covered.
            st.resize_overlay.steering(w, h, Instant::now());
        }
    }
}

/// What one [`resize_decision`] tick decided.
#[derive(Debug, PartialEq, Eq)]
enum ResizeAction {
    /// Nothing to do yet (no resize pending, still debouncing, or spacing defers — the
    /// pending stamp is kept so a later tick retries).
    Wait,
    /// The debounce settled (pending cleared, the caller persists the window size), with
    /// the mode to request — `None` when the size needs no switch (equal to the streamed
    /// mode, or this exact size was already requested once).
    Settled(Option<(u32, u32)>),
}

/// The D2 trigger discipline as a pure decision (unit-tested — CI can't open windows):
/// debounce to resize-end, ≥ 1 s between requests, physical pixels even-floored and
/// clamped ≥ 320×200, skip when equal to the streamed mode, and each distinct size
/// requested at most once (covers rejected sizes AND host-side rollbacks).
fn resize_decision(
    now: Instant,
    pending: &mut Option<Instant>,
    sent_at: Option<Instant>,
    requested: Option<(u32, u32)>,
    current: (u32, u32),
    pixel_size: (u32, u32),
) -> ResizeAction {
    const DEBOUNCE: Duration = Duration::from_millis(400);
    const SPACING: Duration = Duration::from_secs(1);
    let Some(since) = *pending else {
        return ResizeAction::Wait;
    };
    if now.duration_since(since) < DEBOUNCE {
        return ResizeAction::Wait;
    }
    if sent_at.is_some_and(|at| now.duration_since(at) < SPACING) {
        return ResizeAction::Wait; // keep the pending stamp — a later tick retries
    }
    *pending = None;
    let target = ((pixel_size.0 & !1).max(320), (pixel_size.1 & !1).max(200));
    if current == target || requested == Some(target) {
        return ResizeAction::Settled(None);
    }
    ResizeAction::Settled(Some(target))
}

/// Resize-in-progress overlay state (design/midstream-resolution-resize.md — client UX),
/// ported from the Apple client's `ResizeIndicator`. A mid-stream Match-window switch takes
/// the host 0.3–2 s to rebuild its virtual display + encoder, and the first new-mode frame
/// is an IDR the decoder re-inits on. Rather than let the stream stretch to the changed
/// window during that gap, the presenter EMBRACES the delay: a deliberate scrim + spinner
/// the instant a switch is requested, cleared the instant the sharp new-resolution frame is
/// on screen — so the wait reads as intentional, not as lag.
///
/// Driven entirely by signals the presenter already has (no new protocol):
///   * START — [`resize_tick`] reports the size it just requested (`steering`).
///   * END — the decode pipeline reports each frame's dimensions; when they reach the
///     target the new picture is here (`decoded`). The accepted-switch ack alone can't
///     end it: the ack round-trips in milliseconds, ahead of the host's rebuild.
///   * TIMEOUT — the safety net for a switch that never delivers the exact target (a
///     gamescope reject, an advertised-mode cap, or a corrective ack landing a different
///     size); `tick` clears it after [`ResizeIndicator::TIMEOUT`].
///
/// Pure + clock-injected so the transition logic is unit-tested without a live session.
#[derive(Default)]
struct ResizeIndicator {
    /// The size the follower is steering toward — cleared once a decoded frame reaches it.
    /// `Some` ⇔ the scrim + spinner should be shown.
    target: Option<(u32, u32)>,
    /// When the current active span began — the timeout is measured from here.
    since: Option<Instant>,
}

impl ResizeIndicator {
    /// How long to keep the overlay up if the target frame never arrives.
    const TIMEOUT: Duration = Duration::from_millis(2500);

    /// Whether the scrim + spinner should be shown.
    fn active(&self) -> bool {
        self.target.is_some()
    }

    /// A switch to `w`×`h` was just requested — show the overlay now. The timeout re-arms
    /// only when the target actually changes, so a drag that walks through several sizes
    /// (each its own request) never trips the timeout mid-gesture.
    fn steering(&mut self, w: u32, h: u32, now: Instant) {
        if self.target != Some((w, h)) {
            self.since = Some(now);
        }
        self.target = Some((w, h));
    }

    /// A decoded frame arrived at `w`×`h`. Clears the overlay once it matches the steered
    /// target — the sharp new-resolution picture is on glass.
    fn decoded(&mut self, w: u32, h: u32) {
        if self.target == Some((w, h)) {
            self.target = None;
            self.since = None;
        }
    }

    /// Timeout safety net: stop showing once [`TIMEOUT`](Self::TIMEOUT) has elapsed with no
    /// matching frame (a rejected or host-capped switch never delivers the exact target).
    fn tick(&mut self, now: Instant) {
        if self
            .since
            .is_some_and(|s| now.duration_since(s) >= Self::TIMEOUT)
        {
            self.target = None;
            self.since = None;
        }
    }
}

/// Apply the capture state to the window: pointer lock (relative mouse + hidden cursor)
/// and a keyboard grab, so system chords (Alt+Tab, the Windows key / Super) reach the
/// host while captured instead of the local shell. SDL implements the grab per platform:
/// a low-level keyboard hook on Windows (the same mechanism the WinUI shell's in-process
/// client used its own WH_KEYBOARD_LL hooks for), `zwp_keyboard_shortcuts_inhibit_manager_v1`
/// on Wayland, `XGrabKeyboard` (plus the `_XWAYLAND_MAY_GRAB_KEYBOARD` message under
/// XWayland) on X11.
///
/// `inhibit` is [`Settings::inhibit_shortcuts`] — off leaves every system chord with the
/// local shell mid-stream, which is what a second-screen/work profile wants. It only ever
/// *removes* a grab: capture state still gates it, so releasing input (focus loss, the
/// Ctrl+Alt+Shift+Q chord, session end) always hands the chords back.
///
/// The `desktop` mouse model never locks: the pointer roams (and leaves the window)
/// freely, the local cursor is hidden over the window — the host's composited cursor,
/// tracking our absolute sends, is the one you see (until the M2 cursor channel flips
/// who draws it) — and system chords stay local (a remote desktop is something you
/// Alt-Tab away from, not into). `desktop` only matters while `on`.
fn apply_capture(
    window: &mut sdl3::video::Window,
    mouse: &sdl3::mouse::MouseUtil,
    on: bool,
    desktop: bool,
    inhibit: bool,
) {
    mouse.set_relative_mouse_mode(window, on && !desktop);
    mouse.show_cursor(!on);
    let grab = on && !desktop && inhibit;
    if !window.set_keyboard_grab(grab) && grab {
        // The one refusal SDL reports is a missing mechanism — a Wayland compositor with no
        // shortcuts-inhibit global. Said once per process: the answer never changes
        // mid-session, and this runs on every engage. Under gamescope that is the expected
        // shape, not a problem — it has no shortcuts of its own and hands the focused window
        // every key already — so it stays at debug there rather than crying wolf once per
        // Deck stream.
        static SAID: AtomicBool = AtomicBool::new(false);
        if !SAID.swap(true, Ordering::Relaxed) {
            let err = sdl3::get_error();
            if std::env::var_os("GAMESCOPE_WAYLAND_DISPLAY").is_some() {
                tracing::debug!(error = %err, "no keyboard grab under gamescope — chords already ours");
            } else {
                tracing::warn!(
                    error = %err,
                    "capture system shortcuts is on, but this compositor offers no way to grab \
                     the keyboard — system chords stay with the local shell"
                );
            }
        }
    }
}

/// One SDL mouse/touch event as the overlay wants it: swapchain PIXELS, which is the
/// space the console renders and hit-tests in. `None` for events the console can't use.
///
/// Two different conversions, and mixing them up puts every click off by the display
/// scale: SDL reports mouse positions in WINDOW coordinates (logical units — 1× on a
/// HiDPI panel at 200 % is half a pixel), while fingers arrive window-NORMALIZED (0..1).
/// Only DIRECT touch devices are offered; an indirect trackpad already drives the mouse,
/// and forwarding both would double every tap.
fn overlay_pointer(event: &Event, window: &sdl3::video::Window) -> Option<PointerInput> {
    let (pw, ph) = window.size_in_pixels();
    let (lw, lh) = window.size();
    // Logical → physical. A zero-sized window (minimized) would divide by zero.
    let sx = pw as f32 / lw.max(1) as f32;
    let sy = ph as f32 / lh.max(1) as f32;
    let button = |b: sdl3::mouse::MouseButton| match b {
        sdl3::mouse::MouseButton::Left => Some(PointerButton::Primary),
        sdl3::mouse::MouseButton::Right => Some(PointerButton::Secondary),
        _ => None,
    };
    Some(match event {
        Event::MouseMotion { x, y, .. } => PointerInput::Move {
            x: x * sx,
            y: y * sy,
        },
        Event::MouseButtonDown {
            mouse_btn, x, y, ..
        } => PointerInput::Down {
            x: x * sx,
            y: y * sy,
            button: button(*mouse_btn)?,
        },
        Event::MouseButtonUp {
            mouse_btn, x, y, ..
        } => PointerInput::Up {
            x: x * sx,
            y: y * sy,
            button: button(*mouse_btn)?,
        },
        Event::MouseWheel {
            y,
            mouse_x,
            mouse_y,
            ..
        } => PointerInput::Wheel {
            x: mouse_x * sx,
            y: mouse_y * sy,
            dy: *y,
        },
        Event::FingerDown { touch_id, x, y, .. } if is_direct_touch(*touch_id) => {
            PointerInput::Down {
                x: x * pw as f32,
                y: y * ph as f32,
                button: PointerButton::Primary,
            }
        }
        Event::FingerMotion { touch_id, x, y, .. } if is_direct_touch(*touch_id) => {
            PointerInput::Move {
                x: x * pw as f32,
                y: y * ph as f32,
            }
        }
        Event::FingerUp { touch_id, x, y, .. } if is_direct_touch(*touch_id) => PointerInput::Up {
            x: x * pw as f32,
            y: y * ph as f32,
            button: PointerButton::Primary,
        },
        // The pointer left the window mid-press: drop the press rather than let a release
        // that never comes leave a widget armed forever.
        Event::Window {
            win_event: WindowEvent::MouseLeave,
            ..
        } => PointerInput::Cancel,
        _ => return None,
    })
}

/// Is this SDL touch device a real touchscreen (DIRECT, window-relative coordinates)?
/// Trackpads report INDIRECT and drive the mouse — their finger events must not be
/// forwarded as touch passthrough. An unknown/invalid id (INVALID) reads as not-direct.
fn is_direct_touch(touch_id: u64) -> bool {
    use sdl3::sys::touch::{SDL_GetTouchDeviceType, SDL_TouchDeviceType, SDL_TouchID};
    // SAFETY: per the Vulkan contract above - the Vulkan handles used here are owned by this type
    // and live for the call, and every builder struct is a local that outlives it.
    unsafe { SDL_GetTouchDeviceType(SDL_TouchID(touch_id)) == SDL_TouchDeviceType::DIRECT }
}

/// Route one SDL touchscreen finger into the active session's [`Capture`] per the touch
/// model. SDL delivers window-normalized `x`/`y` (0..1) and a nanosecond `timestamp`; the
/// dispatcher hands `Capture` physical window pixels (trackpad ballistics + gesture geometry)
/// AND the finger mapped into the letterboxed content rect (pointer moves + raw passthrough).
/// Returns whether a three-finger tap asked to cycle the stats tier. Down/Move before the
/// first decoded frame have nothing to map onto and are dropped; an Up always dispatches so a
/// lift can release a held contact/drag.
fn dispatch_finger(
    phase: FingerPhase,
    window: &sdl3::video::Window,
    stream: &mut Option<StreamState>,
    finger_id: u64,
    x: f32,
    y: f32,
    timestamp: u64,
) -> bool {
    let Some(st) = stream.as_mut() else {
        return false;
    };
    let (pw, ph) = window.size_in_pixels();
    let (wx, wy) = (x * pw as f32, y * ph as f32);
    let abs = match st.last_video {
        Some(video) => {
            let (ax, ay, aw, ah) = finger_to_content((pw, ph), video, x, y);
            Abs {
                x: ax,
                y: ay,
                w: aw,
                h: ah,
            }
        }
        None if phase == FingerPhase::Up => Abs {
            x: 0,
            y: 0,
            w: 0,
            h: 0,
        },
        None => return false,
    };
    let Some(cap) = st.capture.as_mut() else {
        return false;
    };
    cap.dispatch_finger(
        phase,
        finger_id,
        wx,
        wy,
        abs,
        timestamp as f64 / 1_000_000.0,
    )
}

/// Advance the stats-overlay tier and re-render the OSD immediately from the last window
/// (waiting for the next Stats event would lag the trigger by up to 1 s). Shared by the
/// Ctrl+Alt+Shift+S chord and the three-finger touch tap.
fn bump_stats_tier(
    verbosity: &mut StatsVerbosity,
    stream: &mut Option<StreamState>,
    presenter: &Presenter,
) {
    *verbosity = verbosity.next();
    if let Some(st) = stream {
        st.osd_text = match &st.last_stats {
            Some(s) => stats_text(
                *verbosity,
                &st.mode_line,
                s,
                &st.presented,
                st.hdr,
                presenter.hdr_active(),
                st.hdr_untonemapped,
                st.profile.as_deref(),
            ),
            None => String::new(),
        };
    }
}

/// The pure Contain-fit mapping (window pixels in, content pixels out) — split out so the
/// letterbox math is testable without a live SDL window. Mirrors
/// [`vk::letterbox`]; a finger in the letterbox bars clamps to the nearest content edge.
fn finger_to_content(
    surface: (u32, u32),
    video: (u32, u32),
    x: f32,
    y: f32,
) -> (i32, i32, u32, u32) {
    let (pw, ph) = (f64::from(surface.0), f64::from(surface.1));
    let (vw, vh) = video;
    let scale = (pw / f64::from(vw.max(1))).min(ph / f64::from(vh.max(1)));
    let dw = (f64::from(vw) * scale).max(1.0);
    let dh = (f64::from(vh) * scale).max(1.0);
    let ox = (pw - dw) / 2.0;
    let oy = (ph - dh) / 2.0;
    let cx = ((f64::from(x) * pw - ox) / dw).clamp(0.0, 1.0) * dw;
    let cy = ((f64::from(y) * ph - oy) / dh).clamp(0.0, 1.0) * dh;
    (cx.round() as i32, cy.round() as i32, dw as u32, dh as u32)
}

/// The inverse direction of [`finger_to_content`] for the M3 reappear warp: a HOST-frame pixel
/// (`video` space — what `CursorState` carries) → LOGICAL window coordinates (what
/// `warp_mouse_in_window` takes). Maps through the aspect-fit letterbox (physical), then
/// physical → logical via the window's pixel density; out-of-range host coords clamp into the
/// content rect so the warp always lands on the video.
fn content_to_window(
    logical: (u32, u32),
    surface: (u32, u32),
    video: (u32, u32),
    x: i32,
    y: i32,
) -> (f32, f32) {
    let (pw, ph) = (f64::from(surface.0), f64::from(surface.1));
    let (vw, vh) = (f64::from(video.0.max(1)), f64::from(video.1.max(1)));
    let scale = (pw / vw).min(ph / vh);
    let (dw, dh) = ((vw * scale).max(1.0), (vh * scale).max(1.0));
    let ox = (pw - dw) / 2.0;
    let oy = (ph - dh) / 2.0;
    let px = ox + (f64::from(x).clamp(0.0, vw - 1.0)) * scale;
    let py = oy + (f64::from(y).clamp(0.0, vh - 1.0)) * scale;
    // Physical → logical (HiDPI): the ratio of the window's logical size to its pixel size.
    let lx = px * f64::from(logical.0) / pw.max(1.0);
    let ly = py * f64::from(logical.1) / ph.max(1.0);
    (lx as f32, ly as f32)
}

/// The overlay chrome's UI scale (`FrameCtx::scale`): SDL's window display scale — DPI × the
/// display's content scale, `1.0` at 96 dpi / 100 % — times the `PUNKTFUNK_OSD_SCALE` preference.
///
/// Sanitizing is not paranoia: `SDL_GetWindowDisplayScale` returns `0.0` when it cannot resolve the
/// window's display (a headless/offscreen driver, or racing a monitor hotplug), and a 0 multiplier
/// would collapse the OSD to an invisible zero-size panel — worse than the un-scaled chrome it
/// replaces. The 4× ceiling keeps a bogus scale from covering the stream.
fn overlay_scale(display_scale: f32, pref: f32) -> f32 {
    let base = if display_scale.is_finite() && display_scale > 0.0 {
        display_scale
    } else {
        1.0
    };
    let pref = if pref.is_finite() && pref > 0.0 {
        pref
    } else {
        1.0
    };
    (base * pref).clamp(0.5, 4.0)
}

/// The presenter's share of the unified stats window — folded into each printed line.
#[derive(Default)]
struct PresentedWindow {
    e2e_p50_ms: f32,
    e2e_p95_ms: f32,
    display_ms: f32,
    /// The display stage split (design/desktop-presentation-rebuild.md WP4):
    /// `pace` = decoded → present-submit (our own pipeline), `latch` = submit → on-glass
    /// (the presentation engine's queue + the vblank wait). Both `0` without
    /// `VK_KHR_present_wait`, where the two are not separable — the HUD then shows the
    /// unsplit figure rather than inventing a zero latch.
    ///
    /// This split is what makes a high `display` self-diagnosing: latch dominating means
    /// the vsync/queue floor (or a standing queue), pace dominating means us.
    /// `pace` is also the honest cross-platform twin of the Apple client's shaved
    /// number — Apple subtracts its measured OS present floor, and the latch IS our
    /// floor, so `pace` is what remains on both sides of that comparison.
    pace_ms: f32,
    latch_ms: f32,
    /// The live swapchain present mode (`mailbox`/`fifo`/…). Shown because a mode is
    /// chosen from what the surface offers, so "why is my latch a refresh long" is
    /// usually answered by a MAILBOX request having landed on FIFO.
    mode: &'static str,
    /// Whether variable refresh is measurably live (never claimed without evidence).
    vrr: Cadence,
    /// Presenter-engine counters for the window: the smoothing FIFO's overflow drops and
    /// post-preroll underflows, and the FIFO glass gate's holds/stale force-opens.
    smoothing: bool,
    q_drop: u32,
    q_dry: u32,
    gated: u32,
    forced: u32,
}

/// The capture hints (`ui_stream` parity — the words the user reads while released).
const HINT_KEYBOARD: &str = "点击串流画面捕获输入 · Ctrl+Alt+Shift+Q 释放 · \
     Ctrl+Alt+Shift+M 鼠标模式 · Ctrl+Alt+Shift+D 断开连接 · Ctrl+Alt+Shift+S 统计信息";
const HINT_WITH_PAD: &str = "点击串流画面捕获输入 · Ctrl+Alt+Shift+Q 释放 · \
     Ctrl+Alt+Shift+D 断开连接 · 长按 L1 + R1 + Start + Select 退出";

/// The unified stats window (design/stats-unification.md) as OSD text at the given tier
/// (the Android client's vocabulary, each a strict superset of the previous):
/// Compact = one glanceable line, Normal = mode + end-to-end percentiles + loss,
/// Detailed = decoder path, HDR tag and the per-stage equation on top. Off reads empty.
/// Multi-line for the console-UI panel; the stdout `stats:` line joins Detailed with `|`.
///
/// The HDR tag is honest about the display path: `HDR` only when the swapchain actually
/// runs HDR10 (`hdr_display`); a PQ stream tone-mapped onto an SDR surface (no HDR10
/// format offered, HDR off in the compositor) shows `HDR→SDR`; and a lane that shows PQ
/// with no tone-map pass at all (`hdr_untonemapped`) shows `HDR→SDR (raw)`, so a
/// washed-out picture is named for what it is rather than passed off as a tone-map.
/// ⚠ Since M8 no lane sets that flag — the software lane, which used to, now goes through
/// the same planar CSC pass as the hardware ones. The arm is kept for the next one that
/// does not; see `StreamState::hdr_untonemapped`.
///
/// `profile` (the session's settings profile, `None` for the global defaults) closes the
/// first line at every tier — the cheapest possible answer to "which profile am I on?"
/// (design/client-settings-profiles.md §5.2).
#[allow(clippy::too_many_arguments)]
fn stats_text(
    verbosity: StatsVerbosity,
    mode_line: &str,
    s: &Stats,
    p: &PresentedWindow,
    hdr_stream: bool,
    hdr_display: bool,
    hdr_untonemapped: bool,
    profile: Option<&str>,
) -> String {
    let profile_tag = profile.map(|n| format!(" · {n}")).unwrap_or_default();
    match verbosity {
        StatsVerbosity::Off => return String::new(),
        StatsVerbosity::Compact => {
            // fps · e2e ms · Mb/s — the latency term waits for the first presenter
            // window (0 = no capture→displayed samples yet).
            let mut text = format!("{:.0} fps", s.fps);
            if p.e2e_p50_ms > 0.0 {
                text.push_str(&format!(" · {:.1} ms", p.e2e_p50_ms));
            }
            text.push_str(&format!(" · {:.0} Mb/s", s.mbps));
            if s.lost > 0 {
                text.push_str(&format!(" · lost {}", s.lost));
            }
            text.push_str(&profile_tag);
            return text;
        }
        StatsVerbosity::Normal | StatsVerbosity::Detailed => {}
    }
    let detailed = verbosity == StatsVerbosity::Detailed;
    let mut text = if detailed {
        // The encoder target next to the measured rate is the figure whose absence let the
        // settings-drop bug ship four releases: "19 Mb/s" alone can't distinguish "the
        // encoder is capped at 20" from "my 200 Mb/s grant met a cheap scene". `(auto)`
        // marks an Automatic session — the ABR moves the target by design, so a shifting
        // number reads as policy, not a broken setting. Omitted against an old host that
        // never reported a rate.
        let target = match (s.target_kbps, s.auto_rate) {
            (0, _) => String::new(),
            (t, true) => format!(" · target {:.0} Mb/s (auto)", f64::from(t) / 1000.0),
            (t, false) => format!(" · target {:.0} Mb/s", f64::from(t) / 1000.0),
        };
        // The chroma tag mirrors the HDR tag's honesty: `4:4:4→4:2:0` = the session asked
        // for full chroma and the host resolved 4:2:0 (its policy/capturer/encoder gates
        // said no) — otherwise the Settings switch's effect is unobservable.
        let chroma = match (s.asked_444, s.chroma_444) {
            (_, true) => " · 4:4:4",
            (true, false) => " · 4:4:4→4:2:0",
            _ => "",
        };
        format!(
            "{mode_line} · {:.0} fps · {:.1} Mb/s{target} · {}{}{chroma}",
            s.fps,
            s.mbps,
            if s.decoder.is_empty() { "-" } else { s.decoder },
            match (hdr_stream, hdr_display) {
                (true, true) => " · HDR",
                (true, false) if hdr_untonemapped => " · HDR→SDR (raw)",
                (true, false) => " · HDR→SDR",
                _ => "",
            },
        )
    } else {
        format!("{mode_line} · {:.0} fps · {:.1} Mb/s", s.fps, s.mbps)
    };
    text.push_str(&profile_tag);
    text.push_str(&format!(
        "\ne2e {:.1}/{:.1} ms (p50/p95)",
        p.e2e_p50_ms, p.e2e_p95_ms
    ));
    if detailed {
        if s.split {
            text.push_str(&format!(" · host {:.1} · net {:.1}", s.host_ms, s.net_ms));
        } else {
            text.push_str(&format!(" · host+net {:.1}", s.host_net_ms));
        }
        text.push_str(&format!(
            " · decode {:.1} · display {:.1} ms",
            s.decode_ms, p.display_ms
        ));
        // The display split (WP4). Only with true on-glass stamps — without them the
        // two halves are not separable and the unsplit figure stands alone rather than
        // implying a zero latch.
        if p.latch_ms > 0.0 || p.pace_ms > 0.0 {
            text.push_str(&format!(
                " (pace {:.1} + latch {:.1})",
                p.pace_ms, p.latch_ms
            ));
        }
        // Extended 0xCF host-stage split (T0.1): its own line so the per-stage attribution
        // (queue → encode → seal/xfer → pace) reads as the host pipeline in order.
        if s.staged {
            text.push_str(&format!(
                "\nhost: queue {:.1} · encode {:.1} · xfer {:.1} · pace {:.1} ms",
                s.host_queue_ms, s.host_encode_ms, s.host_xfer_ms, s.host_pace_ms
            ));
        }
        // The presenter line: the swapchain mode that is actually live, the chosen
        // intent, and the engine's own counters. Present-mode alone answers most
        // "why is my latch a whole refresh" questions; the counters only render when
        // they are non-zero, so a healthy latency session shows just the mode.
        if !p.mode.is_empty() {
            text.push_str(&format!("\npresent: {}", p.mode));
            // Only once measured — an unproven "vrr no" would be a claim, not a reading.
            if p.vrr != Cadence::Unknown {
                text.push_str(&format!(" · vrr {}", p.vrr.label()));
            }
            if p.smoothing {
                text.push_str(" · smoothing");
            }
            if p.q_drop > 0 {
                text.push_str(&format!(" · qdrop {}", p.q_drop));
            }
            if p.q_dry > 0 {
                text.push_str(&format!(" · qdry {}", p.q_dry));
            }
            if p.gated > 0 {
                text.push_str(&format!(" · gated {}", p.gated));
            }
            if p.forced > 0 {
                text.push_str(&format!(" · forced {}", p.forced));
            }
        }
    }
    if s.lost > 0 {
        text.push_str(&format!("\nlost {} ({:.1}%)", s.lost, s.lost_pct));
    }
    // The mic uplink line renders only while voice is actually going out (a healthy 10 ms-frame
    // uplink reads ~100 f/s) and only in Detailed — drops here are the client shedding backlog.
    // A muted mic reads 0 and drops the line; the mute has its own always-on badge instead, so
    // this stays a throughput readout rather than doubling as a mute indicator.
    if detailed && (s.mic_sent > 0 || s.mic_dropped > 0) {
        text.push_str(&format!("\nmic {} f/s", s.mic_sent));
        if s.mic_dropped > 0 {
            text.push_str(&format!(" · dropped {}", s.mic_dropped));
        }
    }
    // The audio plane's own latency, Detailed-only. `buffer` is how much decoded audio is queued
    // ahead of the speaker; `a/v` is where that PUTS it relative to the picture (+ = audio behind).
    //
    // Both, not just the depth: a deep ring on a jittery link is correct behaviour, and only the
    // offset distinguishes that from a ring that is simply holding audio late. Before this the
    // plane published neither — they lived in a `tracing::debug!` line that, on the Steam Deck,
    // goes to a pipe under Steam's reaper that nobody can read, so the device that reported the
    // latency was the one device where the numbers could not be seen.
    if detailed && s.audio_buffer_ms > 0 {
        text.push_str(&format!("\naudio buffer {} ms", s.audio_buffer_ms));
        if s.audio_av_offset_ms != 0 {
            text.push_str(&format!(" · a/v {:+} ms", s.audio_av_offset_ms));
        }
    }
    // Decode integrity (M4) — the native lane's answer to "was that stream actually
    // clean?". Appended LAST and only when it has something to say, which keeps it
    // additive for the stdout `stats:` line's parsers (a machine interface: every
    // existing segment stays where it was) and keeps a healthy session's OSD exactly
    // as quiet as it is today.
    //
    // "Something to say" deliberately includes a device with no `RESULT_STATUS`
    // support (RADV), even with zero damage: there the counters cover the parser's
    // half only, and a silent integrity line would read as a clean bill of health on
    // the one configuration that cannot give one. Saying "no driver status" once a
    // second is the whole lesson of `nb_queries = 0` — an unmeasured session must
    // never look like a measured one. A lane that cannot report integrity at all (the
    // CPU rung, PyroWave) prints nothing rather than zeros, for the same reason.
    if detailed && s.decode_integrity {
        let mut parts: Vec<String> = Vec::new();
        if s.decode_damaged > 0 {
            parts.push(format!("damaged {}", s.decode_damaged));
        }
        if s.decode_refused > 0 {
            // The decoder could not run at all — a different diagnosis from
            // `damaged`, and the one that means the screen is frozen rather than
            // occasionally glitching. Without it a rung refusing every AU printed
            // no integrity line whatsoever.
            parts.push(format!("refused {}", s.decode_refused));
        }
        if s.decode_failed > 0 {
            parts.push(format!("driver-failed {}", s.decode_failed));
        }
        if s.concealed_run > 0 {
            // The figure that says "and it has not recovered" — a run still climbing
            // at the end of the window is a different problem from the same count of
            // isolated damaged AUs.
            parts.push(format!("run {}", s.concealed_run));
        }
        if s.worst_concealed_run > s.concealed_run {
            // Only when it says something the instantaneous run does not: this is
            // sampled once a second and the worst moment lasts a handful of frames,
            // so a window that reads `damaged 40` with no run at all is either forty
            // isolated glitches or one 40-AU freeze that recovered — and until this
            // figure was surfaced, nothing on the OSD could tell those apart.
            // Session-cumulative, unlike everything before it on this line, which is
            // why it is labelled rather than folded into `run`.
            parts.push(format!("worst run {}", s.worst_concealed_run));
        }
        if !s.decode_status_queries {
            parts.push("no driver status".into());
        }
        if !parts.is_empty() {
            text.push_str(&format!("\nintegrity: {}", parts.join(" · ")));
        }
    }
    // M8's software-HEVC-drop telemetry ("telemetry on frequency", §7 risk register):
    // how many times in THIS process a session's codec ran out of decode rungs and had
    // to reconnect as another codec. Process-cumulative, appended LAST and only when
    // nonzero — additive for the stdout `stats:` line's parsers, and invisible on the
    // overwhelming majority of runs where it never happens.
    //
    // On the line rather than only in the log because the question it answers is a rate
    // across a session history ("did dropping software HEVC cost anyone a stream?"), and
    // a warn nobody greps for cannot answer it.
    let fallbacks = pf_client_core::session::codec_fallbacks();
    if detailed && fallbacks > 0 {
        text.push_str(&format!("\ncodec_fallbacks {fallbacks}"));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The field report this exists for: CachyOS/KDE Plasma 6.7.4 Wayland, a 2560×1600@165
    /// laptop panel at 150 % scaling. KDE advertises the output as 1707×1067 points, SDL
    /// hands that back as the desktop mode with `pixel_density` = 2560/1707, and "Native
    /// resolution" streamed 1706×1066 — the points, even-floored by `render_scale::apply`.
    #[test]
    fn native_is_the_panels_pixels_under_fractional_wayland_scaling() {
        // SDL derives the density as the exact pixels-per-point ratio of the output.
        let density = 2560.0 / 1707.0;
        let m = native_mode(1707, 1067, density, 165.0);
        assert_eq!((m.width, m.height, m.refresh_hz), (2560, 1600, 165));
        // …and it survives the even-floor the host's `validate_dimensions` forces, which is
        // where 1707×1067 lost its odd pixel and became the reported 1706×1066.
        assert_eq!(
            punktfunk_core::render_scale::apply(m.width, m.height, 1.0, 8192),
            (2560, 1600)
        );
        assert_eq!(
            punktfunk_core::render_scale::apply(1707, 1067, 1.0, 8192),
            (1706, 1066),
            "the pre-fix mode, kept here so the regression is legible"
        );
    }

    #[test]
    fn native_is_unchanged_where_the_density_is_one() {
        // X11, Windows, and Wayland at 100 % all report 1.0 — the fix must be inert there.
        let m = native_mode(2560, 1600, 1.0, 165.0);
        assert_eq!((m.width, m.height, m.refresh_hz), (2560, 1600, 165));
        // Integer scaling (a 200 % 4K panel reported as 1920×1080 points) doubles cleanly.
        let m = native_mode(1920, 1080, 2.0, 60.0);
        assert_eq!((m.width, m.height), (3840, 2160));
    }

    #[test]
    fn a_nonsense_density_falls_back_to_one_rather_than_zeroing_the_mode() {
        // SDL normalizes an unset density to 1.0, but this must not be the one place a
        // driver quirk can hand the host a 0×0 mode request.
        for bogus in [0.0, -1.0, f32::NAN, f32::INFINITY] {
            let m = native_mode(2560, 1600, bogus, 60.0);
            assert_eq!((m.width, m.height), (2560, 1600), "density {bogus}");
        }
        // A negative mode size is clamped, not wrapped into a huge u32.
        let m = native_mode(-1, -1, 1.5, 60.0);
        assert_eq!((m.width, m.height), (0, 0));
    }

    #[test]
    fn overlay_scale_follows_dpi_and_survives_a_bogus_display() {
        // 100 % / 96 dpi is the identity — the chrome keeps the size it always had.
        assert_eq!(overlay_scale(1.0, 1.0), 1.0);
        // The common HiDPI settings pass straight through.
        assert_eq!(overlay_scale(1.5, 1.0), 1.5);
        assert_eq!(overlay_scale(2.0, 1.0), 2.0);
        // PUNKTFUNK_OSD_SCALE multiplies the display's own scale, it doesn't replace it.
        assert_eq!(overlay_scale(2.0, 1.25), 2.5);
        // SDL reports 0.0 when it can't resolve the window's display (offscreen driver, or
        // racing a hotplug) — that must NOT collapse the panel to nothing.
        assert_eq!(overlay_scale(0.0, 1.0), 1.0);
        assert_eq!(overlay_scale(f32::NAN, 1.0), 1.0);
        assert_eq!(overlay_scale(-2.0, 1.0), 1.0);
        // A garbage preference degrades to "just the DPI", never to zero.
        assert_eq!(overlay_scale(1.5, 0.0), 1.5);
        assert_eq!(overlay_scale(1.5, f32::NAN), 1.5);
        // Clamped both ways so nothing can hide the OSD or bury the stream under it.
        assert_eq!(overlay_scale(1.0, 100.0), 4.0);
        assert_eq!(overlay_scale(1.0, 0.01), 0.5);
    }

    #[test]
    fn content_to_window_inverts_the_letterbox() {
        // 1920×1080 video letterboxed in a 1600×1200 (4:3) window at 2× HiDPI: pillarless
        // top/bottom bars — scale = 1600/1920, dh = 900, oy = 150 (physical).
        let logical = (800u32, 600u32);
        let surface = (1600u32, 1200u32);
        let video = (1920u32, 1080u32);
        // The host-frame center must land at the logical window center.
        let (wx, wy) = content_to_window(logical, surface, video, 960, 540);
        assert!((wx - 400.0).abs() < 1.0, "wx = {wx}");
        assert!((wy - 300.0).abs() < 1.0, "wy = {wy}");
        // Roundtrip through the forward mapping: normalized window pos → the same host
        // content-rect pixel (finger_to_content returns content-RECT coords, i.e. the
        // host pixel scaled by the letterbox factor).
        let (nx, ny) = (wx / logical.0 as f32, wy / logical.1 as f32);
        let (cx, cy, dw, dh) = finger_to_content(surface, video, nx, ny);
        assert_eq!((dw, dh), (1600, 900));
        assert!((cx - 800).abs() <= 1, "cx = {cx}"); // 960 * (1600/1920)
        assert!((cy - 450).abs() <= 1, "cy = {cy}"); // 540 * ( 900/1080)
                                                     // Out-of-range host coords clamp into the video, never the bars.
        let (_, wy_clamped) = content_to_window(logical, surface, video, 0, 10_000);
        assert!(wy_clamped <= 300.0 + 225.0 + 1.0, "wy = {wy_clamped}"); // ≤ bottom of content
    }

    #[test]
    fn resize_decision_follows_the_d2_discipline() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;

        // No resize pending → nothing to do.
        let mut pending = None;
        assert_eq!(
            resize_decision(t0, &mut pending, None, None, (1280, 720), (1000, 600)),
            ResizeAction::Wait
        );

        // Still debouncing (a drag in progress) → wait, pending kept.
        let mut pending = Some(t0);
        assert_eq!(
            resize_decision(
                t0 + ms(399),
                &mut pending,
                None,
                None,
                (1280, 720),
                (1000, 600)
            ),
            ResizeAction::Wait
        );
        assert!(pending.is_some(), "pending survives the wait");

        // Debounce settled → request the even-floored, clamped pixel size.
        assert_eq!(
            resize_decision(
                t0 + ms(400),
                &mut pending,
                None,
                None,
                (1280, 720),
                (1001, 601)
            ),
            ResizeAction::Settled(Some((1000, 600))),
            "odd pixels floor to even"
        );
        assert!(pending.is_none(), "pending consumed");

        // Spacing: a request went out < 1 s ago → wait WITHOUT dropping the pending
        // stamp, so a later tick retries.
        let mut pending = Some(t0);
        assert_eq!(
            resize_decision(
                t0 + ms(900),
                &mut pending,
                Some(t0),
                Some((1000, 600)),
                (1280, 720),
                (800, 500)
            ),
            ResizeAction::Wait
        );
        assert!(pending.is_some());
        assert_eq!(
            resize_decision(
                t0 + ms(1000),
                &mut pending,
                Some(t0),
                Some((1000, 600)),
                (1280, 720),
                (800, 500)
            ),
            ResizeAction::Settled(Some((800, 500)))
        );

        // Equal to the streamed mode → settle (persist) but no request.
        let mut pending = Some(t0);
        assert_eq!(
            resize_decision(
                t0 + ms(400),
                &mut pending,
                None,
                None,
                (1280, 720),
                (1280, 720)
            ),
            ResizeAction::Settled(None)
        );

        // A size already requested once (rejected, or rolled back host-side) is never
        // re-asked — no request → rollback → request loop.
        let mut pending = Some(t0);
        assert_eq!(
            resize_decision(
                t0 + ms(400),
                &mut pending,
                None,
                Some((1000, 600)),
                (1280, 720),
                (1000, 600)
            ),
            ResizeAction::Settled(None)
        );

        // Tiny windows clamp to the host's floor.
        let mut pending = Some(t0);
        assert_eq!(
            resize_decision(
                t0 + ms(400),
                &mut pending,
                None,
                None,
                (1280, 720),
                (100, 80)
            ),
            ResizeAction::Settled(Some((320, 200)))
        );
    }

    #[test]
    fn resize_indicator_shows_until_the_target_frame_or_timeout() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;

        // Idle at rest.
        let mut ind = ResizeIndicator::default();
        assert!(!ind.active());

        // A requested switch shows the overlay immediately.
        ind.steering(1000, 600, t0);
        assert!(ind.active());

        // A frame at a DIFFERENT size (a stale old-mode frame still draining) doesn't lift it.
        ind.decoded(1280, 720);
        assert!(ind.active(), "an off-target frame keeps the scrim up");

        // The sharp new-resolution frame arrives → cleared.
        ind.decoded(1000, 600);
        assert!(!ind.active(), "the target frame lifts the scrim");
        ind.tick(t0 + ms(10_000)); // a late tick after clearing is inert
        assert!(!ind.active());

        // A switch whose target frame never arrives (rejected / host-capped) times out.
        let mut ind = ResizeIndicator::default();
        ind.steering(1000, 600, t0);
        ind.tick(t0 + ResizeIndicator::TIMEOUT - ms(1));
        assert!(ind.active(), "still within the timeout window");
        ind.tick(t0 + ResizeIndicator::TIMEOUT);
        assert!(!ind.active(), "timeout lifts a switch that never delivered");
    }

    #[test]
    fn resize_indicator_retargets_and_rearms_the_timeout_mid_drag() {
        let t0 = Instant::now();
        let ms = Duration::from_millis;

        // A drag that walks through sizes (each a fresh request) re-arms the timeout, so a
        // slow gesture never trips it: at t0 steer A, then near-timeout steer B, then a B
        // frame lands well after A's timeout would have fired.
        let mut ind = ResizeIndicator::default();
        ind.steering(1000, 600, t0);
        let near = t0 + ResizeIndicator::TIMEOUT - ms(1);
        ind.steering(1200, 700, near); // new target → timeout re-armed from `near`
        ind.tick(t0 + ResizeIndicator::TIMEOUT + ms(1)); // past A's window, within B's
        assert!(
            ind.active(),
            "retarget re-armed the timeout — no mid-drag flicker"
        );

        // Re-steering the SAME size does NOT re-arm (so a repeated identical request can't
        // hold the scrim open forever).
        let mut ind = ResizeIndicator::default();
        ind.steering(1000, 600, t0);
        ind.steering(1000, 600, t0 + ms(500)); // same target, later — `since` unchanged
        ind.tick(t0 + ResizeIndicator::TIMEOUT);
        assert!(
            !ind.active(),
            "an unchanged target keeps the original timeout"
        );
    }

    fn sample() -> (Stats, PresentedWindow) {
        (
            Stats {
                fps: 119.6,
                mbps: 24.3,
                host_net_ms: 2.1,
                host_ms: 1.2,
                net_ms: 0.9,
                split: true,
                host_queue_ms: 0.3,
                host_encode_ms: 0.5,
                host_xfer_ms: 0.1,
                host_pace_ms: 0.3,
                staged: true,
                decode_ms: 1.8,
                lost: 3,
                lost_pct: 0.4,
                mic_sent: 0,
                mic_dropped: 0,
                audio_buffer_ms: 0,
                audio_av_offset_ms: 0,
                // The decode-path tag as the session actually spells it since M10 — the
                // ladder's rung names (`NativeRung::name`), not the deleted libavcodec
                // ones. A fixture carrying a tag no client emits would let this test go on
                // asserting the shape of a string that no longer exists.
                decoder: "native-vulkan",
                // Old-host baseline (no reported target, 4:2:0 never asked): the tier
                // texts stay exactly what they were before the target/chroma elements.
                target_kbps: 0,
                auto_rate: false,
                chroma_444: false,
                asked_444: false,
                // A lane with NO detectors (the CPU rung / PyroWave — and, before M10,
                // any libavcodec rung): it cannot answer integrity questions at all, so
                // every existing tier text below must be unchanged by M4's line.
                decode_integrity: false,
                decode_damaged: 0,
                decode_failed: 0,
                decode_refused: 0,
                concealed_run: 0,
                worst_concealed_run: 0,
                decode_status_queries: false,
            },
            PresentedWindow {
                e2e_p50_ms: 6.4,
                e2e_p95_ms: 9.1,
                display_ms: 1.1,
                ..Default::default()
            },
        )
    }

    /// The tier ladder: Off is empty, Compact is one line, Normal adds the mode + e2e
    /// lines but no stage terms or decoder tag, Detailed carries everything.
    #[test]
    fn stats_text_tiers() {
        let (s, p) = sample();
        let text = |v| stats_text(v, "1920×1080@120", &s, &p, true, false, false, None);

        assert_eq!(text(StatsVerbosity::Off), "");

        let compact = text(StatsVerbosity::Compact);
        assert_eq!(compact, "120 fps · 6.4 ms · 24 Mb/s · lost 3");
        assert_eq!(compact.lines().count(), 1);

        let normal = text(StatsVerbosity::Normal);
        assert!(normal.starts_with("1920×1080@120 · 120 fps · 24.3 Mb/s\n"));
        assert!(normal.contains("e2e 6.4/9.1 ms (p50/p95)"));
        assert!(normal.contains("lost 3 (0.4%)"));
        assert!(
            !normal.contains("native-vulkan"),
            "decoder tag is Detailed-only"
        );
        assert!(!normal.contains("decode"), "stage terms are Detailed-only");

        let detailed = text(StatsVerbosity::Detailed);
        assert!(detailed.contains("vulkan · HDR→SDR"));
        assert!(
            !detailed.contains("(raw)"),
            "the hardware lane tone-maps — no raw tag"
        );
        assert!(detailed.contains("host 1.2 · net 0.9 · decode 1.8 · display 1.1 ms"));
        assert!(detailed.contains("host: queue 0.3 · encode 0.5 · xfer 0.1 · pace 0.3 ms"));
        assert!(detailed.contains("lost 3 (0.4%)"));
        assert!(
            !normal.contains("queue"),
            "host-stage split is Detailed-only"
        );
        assert!(
            !detailed.contains("pace 1.1"),
            "no glass stamps in this sample — the display stage stays unsplit"
        );
    }

    /// WP4: with true on-glass stamps the display stage reads as its two halves, the
    /// live present mode is named, and the engine counters render only when non-zero —
    /// so a healthy latency session shows the mode and nothing else. Without glass
    /// stamps (no `VK_KHR_present_wait`) the split is absent rather than a zero latch.
    #[test]
    fn detailed_splits_display_into_pace_and_latch() {
        let (s, mut p) = sample();
        p.display_ms = 12.4;
        p.pace_ms = 1.1;
        p.latch_ms = 11.3;
        p.mode = "fifo";
        let split = stats_text(
            StatsVerbosity::Detailed,
            "m",
            &s,
            &p,
            false,
            false,
            false,
            None,
        );
        assert!(split.contains("display 12.4 ms (pace 1.1 + latch 11.3)"));
        assert!(split.contains("\npresent: fifo"));
        assert!(
            !split.contains("qdrop") && !split.contains("gated") && !split.contains("smoothing"),
            "quiet counters stay off the HUD: {split}"
        );

        // The smoothing FIFO and the glass gate surface once they actually do something.
        p.smoothing = true;
        p.q_drop = 2;
        p.q_dry = 1;
        p.gated = 7;
        p.forced = 1;
        let busy = stats_text(
            StatsVerbosity::Detailed,
            "m",
            &s,
            &p,
            false,
            false,
            false,
            None,
        );
        assert!(busy.contains("present: fifo · smoothing · qdrop 2 · qdry 1 · gated 7 · forced 1"));

        // A tier below Detailed never carries any of it.
        let normal = stats_text(
            StatsVerbosity::Normal,
            "m",
            &s,
            &p,
            false,
            false,
            false,
            None,
        );
        assert!(!normal.contains("present:") && !normal.contains("pace"));
    }

    /// The decode-integrity line (M4) — the whole point of which is that it can tell
    /// three states apart that all look identical as "no complaints today":
    ///
    /// * a lane that CANNOT see corruption (the CPU rung, PyroWave — and every
    ///   libavcodec rung this program used to have: `nb_queries = 0`, no
    ///   `AV_FRAME_FLAG_CORRUPT`): silent, never zeros, because printing zeros would
    ///   assert a cleanliness nothing checked;
    /// * a lane that looked and saw nothing: also silent, but it earned it;
    /// * a lane that looked with only half its detectors — a device without
    ///   `queryResultStatusSupport` — which says so EVERY window, damage or not.
    ///
    /// Plus the shape a support engineer actually needs when there IS damage: how
    /// much, whose fault (stream vs driver), and whether it ever recovered.
    #[test]
    fn the_integrity_line_distinguishes_clean_from_unmeasurable() {
        let (base, p) = sample();
        let line = |s: &Stats| {
            stats_text(
                StatsVerbosity::Detailed,
                "m",
                s,
                &p,
                false,
                false,
                false,
                None,
            )
            .lines()
            .find(|l| l.starts_with("integrity:"))
            .map(str::to_string)
        };

        // A lane with no detectors cannot answer at all — nothing is printed. (The
        // fixture is one, so this also pins that every other tier text is untouched by M4.)
        assert_eq!(line(&base), None, "a lane with no detectors says nothing");

        // The native rung on a device with full status support, decoding clean:
        // also nothing — a healthy session's OSD stays exactly as quiet as it was.
        let clean = Stats {
            decode_integrity: true,
            decode_status_queries: true,
            ..base
        };
        assert_eq!(line(&clean), None);

        // The same rung on RADV, where a RESULT_STATUS query would hang the VCN ring:
        // clean counters, but only the parser's half was ever measured, and the line
        // says so rather than implying a full bill of health.
        let unmeasured = Stats {
            decode_status_queries: false,
            ..clean
        };
        assert_eq!(
            line(&unmeasured).as_deref(),
            Some("integrity: no driver status")
        );

        // Damage, attributed: concealment is the stream's, `driver-failed` is the
        // hardware's, and `run` answers "did it come back?".
        let damaged = Stats {
            decode_damaged: 4,
            decode_failed: 2,
            concealed_run: 3,
            worst_concealed_run: 3,
            ..clean
        };
        assert_eq!(
            line(&damaged).as_deref(),
            Some("integrity: damaged 4 · driver-failed 2 · run 3")
        );

        // A lossy window the stream recovered from: the run is 0 and simply drops out.
        let recovered = Stats {
            decode_damaged: 4,
            concealed_run: 0,
            ..clean
        };
        assert_eq!(line(&recovered).as_deref(), Some("integrity: damaged 4"));

        // …and the reason that window is not the whole story. `concealed_run` is an
        // INSTANT sampled once a second; the freeze it missed lasted 40 AUs. Forty
        // isolated glitches and one 40-AU freeze that recovered render identically
        // without the session's worst run, and they are completely different bugs.
        let recovered_hard = Stats {
            worst_concealed_run: 40,
            ..recovered
        };
        assert_eq!(
            line(&recovered_hard).as_deref(),
            Some("integrity: damaged 4 · worst run 40")
        );
        // It stays quiet whenever it adds nothing — a run still climbing at the end
        // of the window already IS the worst one.
        let still_broken = Stats {
            concealed_run: 40,
            worst_concealed_run: 40,
            ..recovered
        };
        assert_eq!(
            line(&still_broken).as_deref(),
            Some("integrity: damaged 4 · run 40")
        );

        // A rung that REFUSED every AU — a host renegotiating outside the decode
        // envelope. The screen is frozen, nothing was concealed, no driver verdict
        // exists, and before M4's review this printed no integrity line at all: a
        // decoder that decoded nothing, reported as a clean session.
        let refusing = Stats {
            decode_refused: 60,
            concealed_run: 60,
            worst_concealed_run: 60,
            ..clean
        };
        assert_eq!(
            line(&refusing).as_deref(),
            Some("integrity: refused 60 · run 60")
        );

        // Never below Detailed — the tier ladder is a strict superset chain and this
        // is diagnostic detail, not a glanceable number.
        for tier in [
            StatsVerbosity::Compact,
            StatsVerbosity::Normal,
            StatsVerbosity::Off,
        ] {
            assert!(
                !stats_text(tier, "m", &damaged, &p, false, false, false, None)
                    .contains("integrity:"),
                "{tier:?}"
            );
        }
    }

    /// The honest HDR badges. ⚠ **The `(raw)` arm is currently unreachable in
    /// production**: `hdr_untonemapped` is written `false` on every present arm since M8
    /// took the software lane through the same planar CSC pass (and therefore the same
    /// tone-map) as the hardware lanes — see `StreamState::hdr_untonemapped`. This tests
    /// the FORMATTER, not a state the client can be in, and it is kept for the same
    /// reason the field is: the next lane that bypasses the pass must be able to say so
    /// rather than quietly claim a tone-map, and this is the assertion that will still be
    /// here when it does.
    #[test]
    fn hdr_badge_names_the_untonemapped_cpu_lane() {
        let (s, p) = sample();
        let badge = |hdr_display, raw| {
            stats_text(
                StatsVerbosity::Detailed,
                "m",
                &s,
                &p,
                true,
                hdr_display,
                raw,
                None,
            )
        };
        assert!(badge(false, true).contains(" · HDR→SDR (raw)"));
        assert!(!badge(false, false).contains("(raw)"));
        assert!(badge(false, false).contains(" · HDR→SDR"));
        assert!(badge(true, false).contains(" · HDR"));
        assert!(!badge(true, false).contains("HDR→SDR"));
    }

    /// Detailed shows the negotiated encoder target next to the measured rate — the
    /// figure whose absence let the settings-drop bug ship four releases — tagged
    /// `(auto)` when the ABR owns it, plus the honest chroma tag when 4:4:4 was asked.
    #[test]
    fn detailed_shows_target_and_chroma_resolution() {
        let (mut s, p) = sample();
        let line1 = |s: &Stats, v| {
            stats_text(v, "m", s, &p, false, false, false, None)
                .lines()
                .next()
                .unwrap()
                .to_string()
        };
        // Explicit 200 Mb/s honoured, cheap scene: measured AND target both show — the
        // exact pair a user needs to tell a capped encoder from an idle one.
        s.target_kbps = 200_000;
        assert!(line1(&s, StatsVerbosity::Detailed).contains("24.3 Mb/s · target 200 Mb/s · "));
        // An Automatic session's moving target reads as policy, not a broken setting.
        (s.target_kbps, s.auto_rate) = (20_000, true);
        assert!(line1(&s, StatsVerbosity::Detailed).contains("target 20 Mb/s (auto)"));
        // Normal keeps its old line — the target is a Detailed element.
        assert!(!line1(&s, StatsVerbosity::Normal).contains("target"));
        // An old host that never reported a rate shows no target element at all.
        s.target_kbps = 0;
        assert!(!line1(&s, StatsVerbosity::Detailed).contains("target"));
        // 4:4:4 asked and granted…
        (s.asked_444, s.chroma_444) = (true, true);
        assert!(line1(&s, StatsVerbosity::Detailed).ends_with("· 4:4:4"));
        // …vs asked and declined: the downgrade is said out loud, mirroring `HDR→SDR`.
        s.chroma_444 = false;
        assert!(line1(&s, StatsVerbosity::Detailed).ends_with("· 4:4:4→4:2:0"));
        // Unasked stays untagged (4:2:0 is the default — not noise worth a tag).
        s.asked_444 = false;
        assert!(!line1(&s, StatsVerbosity::Detailed).contains("4:4:4"));
    }

    /// The mic uplink line: Detailed-only, and only while the uplink is live.
    #[test]
    fn stats_text_mic_line() {
        let (mut s, p) = sample();
        let text = |s: &Stats, v| stats_text(v, "m", s, &p, false, false, false, None);
        assert!(
            !text(&s, StatsVerbosity::Detailed).contains("mic"),
            "no mic line while the mic is off"
        );
        s.mic_sent = 100;
        let detailed = text(&s, StatsVerbosity::Detailed);
        assert!(detailed.contains("\nmic 100 f/s"));
        assert!(
            !detailed.contains("dropped"),
            "a healthy uplink shows no drop term"
        );
        assert!(
            !text(&s, StatsVerbosity::Normal).contains("mic"),
            "mic line is Detailed-only"
        );
        s.mic_dropped = 7;
        assert!(text(&s, StatsVerbosity::Detailed).contains("mic 100 f/s · dropped 7"));
    }

    /// Compact omits the latency term until the presenter's first e2e window lands.
    #[test]
    fn compact_waits_for_e2e() {
        let (mut s, _) = sample();
        s.lost = 0;
        let p = PresentedWindow::default();
        assert_eq!(
            stats_text(
                StatsVerbosity::Compact,
                "m",
                &s,
                &p,
                false,
                false,
                false,
                None
            ),
            "120 fps · 24 Mb/s"
        );
    }

    /// The session's settings profile closes the FIRST line at every tier — one line in
    /// Compact, the mode line in Normal/Detailed — and nothing renders without one.
    #[test]
    fn stats_text_names_the_active_profile() {
        let (s, p) = sample();
        assert_eq!(
            stats_text(
                StatsVerbosity::Compact,
                "m",
                &s,
                &p,
                false,
                false,
                false,
                Some("Game")
            ),
            "120 fps · 6.4 ms · 24 Mb/s · lost 3 · Game"
        );
        let normal = stats_text(
            StatsVerbosity::Normal,
            "1920×1080@120",
            &s,
            &p,
            false,
            false,
            false,
            Some("Work"),
        );
        assert_eq!(
            normal.lines().next().unwrap(),
            "1920×1080@120 · 120 fps · 24.3 Mb/s · Work"
        );
        let detailed = stats_text(
            StatsVerbosity::Detailed,
            "1920×1080@120",
            &s,
            &p,
            true,
            true,
            false,
            Some("Work"),
        );
        assert!(detailed.lines().next().unwrap().ends_with("· HDR · Work"));
        // No profile → the line is exactly what it always was.
        assert!(!stats_text(
            StatsVerbosity::Normal,
            "m",
            &s,
            &p,
            false,
            false,
            false,
            None
        )
        .contains(" ·  "));
    }

    #[test]
    fn finger_maps_across_a_perfectly_filled_surface() {
        // Video exactly fills the window (no letterbox): normalized finger → content
        // corners/center map straight through, and the surface size is the video size.
        let video = (1920, 1080);
        assert_eq!(
            finger_to_content((1920, 1080), video, 0.0, 0.0),
            (0, 0, 1920, 1080)
        );
        assert_eq!(
            finger_to_content((1920, 1080), video, 1.0, 1.0),
            (1920, 1080, 1920, 1080)
        );
        assert_eq!(
            finger_to_content((1920, 1080), video, 0.5, 0.5),
            (960, 540, 1920, 1080)
        );
    }

    #[test]
    fn finger_rebases_onto_the_letterboxed_content_rect() {
        // 16:9 video in the Deck's 16:10 glass (1280×800) letterboxes: content is
        // 1280×720, centered with 40px bars top/bottom. A finger at the window's vertical
        // center is the content's vertical center; a finger inside the top bar clamps to
        // the content's top edge (not a negative coordinate).
        let surface = (1280, 800);
        let video = (1920, 1080);
        let (_, cy, w, h) = finger_to_content(surface, video, 0.5, 0.5);
        assert_eq!((w, h), (1280, 720));
        assert_eq!(cy, 360);
        // y=0.01 → window pixel 8, above the 40px bar → clamps to content top (0).
        assert_eq!(
            finger_to_content(surface, video, 0.5, 0.01),
            (640, 0, 1280, 720)
        );
        // Bottom-right corner of the video content.
        assert_eq!(
            finger_to_content(surface, video, 1.0, 1.0),
            (1280, 720, 1280, 720)
        );
    }
}
