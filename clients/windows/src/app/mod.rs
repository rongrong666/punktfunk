//! The WinUI 3 (windows-reactor) application shell.
//!
//! Declarative React-like model: this root component routes on a `Screen` value held in
//! `use_async_state` so background threads (discovery, the spawned session's stdout reader) can
//! drive navigation. Each screen lives in its own submodule:
//!
//! * [`hosts`] — saved/manual host list, plus per-host forget + speed test
//! * [`connect`] — the trust gate and session lifecycle glue (connect / request-access flows)
//! * [`speed`] — the per-host network speed test (probe burst over the real data plane)
//! * [`settings`] — persisted preferences · [`licenses`] — the license notices screen ·
//!   [`help`] — the in-stream keyboard-shortcuts reference (reached from the host list)
//! * [`stream`] — the stream status card (the stream itself runs in the spawned session window)
//! * [`style`] — the shared look (cards, pills, monograms), following the windows-reactor
//!   gallery: Mica backdrop, a centred max-width column, theme brushes (`ThemeRef`)
//!
//! **Re-render discipline** — MEASURED rules, not folklore: each is pinned by a
//! characterization test in `tests/reactor_semantics.rs` against the exact windows-reactor
//! rev in Cargo.toml. Re-run that suite on every bump; a red test means this note is stale.
//!
//! * A child's *sync* `use_state` re-renders it — including under element-equal
//!   non-component wrappers (`border`, `scroll_viewer`), and including writes from
//!   handlers fired through the harness backend
//!   (`sync_state_child_under_element_equal_border_rerenders`,
//!   `sync_state_from_backend_fired_event_rerenders`).
//! * **BUT the real WinUI backend does not honour that last rule.** Measured 2026-07-29:
//!   settings was componentized with its scope as local sync state, and a live UIA pick in
//!   the scope ComboBox changed nothing on screen — `on_selection_changed` wired in the
//!   real backend never pumped the pass the harness pumps (the de-hoist is reverted in this
//!   branch's history; repro = tests/reactor_semantics.rs case 3 passing while the same
//!   flow fails live). So per-screen EVENT-driven UI state ALSO stays in root as
//!   `AsyncSetState` props — hoisting here is on real-backend evidence, not engine rules.
//! * An `AsyncSetState` written from a background thread does NOT re-render its owning
//!   component: the value lands and the dirty flag is set, but the rerender request is
//!   keyed by the component's own HostId, which is never registered — only the root's is —
//!   so it is silently dropped and surfaces on the next unrelated pass
//!   (`async_state_child_under_element_equal_border_rerenders` asserts the drop). So
//!   everything THREAD-driven (discovery, HUD stats, speed-test results, spawn events)
//!   is held as *root* state and passed down as props.
//! * Corollary: state a root tween is KEYED on (`screen`, the settings section, `show_add`)
//!   must stay in root regardless — the tween workers are root effects writing root async
//!   state, and root can only start a tween off a trigger it owns.

mod connect;
mod help;
mod hosts;
mod launcher_icons;
mod licenses;
mod os_icons;
mod settings;
mod speed;
mod stream;
mod style;

use crate::trust::{KnownHosts, Settings};
use hosts::HostsProps;
use pf_client_core::gamepad::GamepadService;
use punktfunk_core::client::NativeClient;
use speed::{SpeedProps, SpeedState};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use windows_reactor::*;

#[derive(Clone, PartialEq)]
pub(crate) enum Screen {
    Hosts,
    Connecting,
    /// The no-PIN "request access" wait: an identified connect is in flight, parked by the host
    /// until the operator approves this device in its console. Cancelable.
    RequestAccess,
    /// Wake-on-LAN "wait until up": a magic packet was sent to an offline saved host and we're
    /// probing for it to come back (re-sending periodically) before dialing. Cancelable.
    Waking,
    Stream,
    Settings,
    /// Open-source / third-party license notices (reached from Settings).
    Licenses,
    /// In-stream keyboard-shortcuts reference + capture help (reached from the host list's
    /// Shortcuts button).
    Help,
    /// Per-host network speed test (probe burst + recommended bitrate).
    SpeedTest,
}

/// The host we're about to connect to / pair with / speed-test (carried into those screens
/// via `Shared::target`).
#[derive(Clone, Default)]
pub(crate) struct Target {
    pub(crate) name: String,
    pub(crate) addr: String,
    pub(crate) port: u16,
    pub(crate) fp_hex: Option<String>,
    pub(crate) pair_optional: bool,
    /// Wake-on-LAN MAC(s) for this host (from the saved store or the live advert) — used to send a
    /// magic packet before connecting to an offline host. Empty when none is known.
    pub(crate) mac: Vec<String>,
    /// This host's management-API port (saved store). `None` = unknown, use
    /// [`pf_client_core::library::DEFAULT_MGMT_PORT`]. Carried on the target for the same
    /// reason as `mac`; unused by this no-library build but kept in the shared shape.
    #[allow(dead_code)]
    pub(crate) mgmt_port: Option<u16>,
    /// A ONE-OFF settings profile for this connect ("Connect with"): `Some(id)` overrides the
    /// host's binding for this launch, `Some("")` forces the global defaults on a bound host,
    /// `None` honors the binding. It never rebinds anything — the default changes only through
    /// the picker in the host editor (design/client-settings-profiles.md §5.2).
    pub(crate) profile: Option<String>,
    /// A library title id (`steam:570`, …) to launch on connect — carried on the target so it
    /// survives a detour through the trust flow.
    pub(crate) launch: Option<String>,
    /// WireGuard-mode target: the session dials through the in-process WG relay using the
    /// keys stored on this host's known-hosts record; no fingerprint pin is required up
    /// front (learned from the session's Welcome on first connect).
    pub(crate) wg: bool,
}

/// Stable app services handed to the page components as props. Each routed screen that uses
/// hooks (`hosts_page`/`pair_page`/`speed_page`/`library_page`) is mounted as its own
/// `component(...)`, so its hooks live in an isolated slot list — calling them on the shared
/// parent `cx` would change the hook order whenever the screen changes (reactor's
/// Rules-of-Hooks guard aborts).
///
/// `Svc` compares equal by `ctx` identity (it never meaningfully changes across renders), so a
/// page whose props are just `Svc` re-renders only via its own state hooks, never spuriously
/// from the parent.
#[derive(Clone)]
pub(crate) struct Svc {
    pub(crate) ctx: Arc<AppCtx>,
    pub(crate) set_screen: AsyncSetState<Screen>,
    pub(crate) set_status: AsyncSetState<String>,
    /// Speed-test lifecycle lives in root state (thread-driven — see the module docs); the hosts
    /// page resets it to `Running` before navigating, the probe worker completes it.
    pub(crate) set_speed: AsyncSetState<SpeedState>,
}

impl PartialEq for Svc {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.ctx, &other.ctx)
    }
}

/// Cross-thread shell state driven off the UI thread: the current target, the live spawned
/// session child (Disconnect/Cancel kill it) and its latest stats line, plus the connect-flow
/// cancel flag and the speed-test generation guard.
#[derive(Default)]
pub(crate) struct Shared {
    pub(crate) target: Mutex<Target>,
    /// The live session child (spawn mode) — the status page's Disconnect and the
    /// request-access Cancel kill it. A FRESH handle is installed per spawn.
    pub(crate) session: Mutex<crate::spawn::SessionChild>,
    /// Latest `stats:` line from the session child (spawn mode), already formatted;
    /// mirrored into the HUD sample for the session status page.
    pub(crate) stats_line: Mutex<String>,
    /// Cancel flag for the in-flight "request access" connect. A FRESH flag is installed per
    /// request: the waiting screen's Cancel button reads it back from here and sets it, and that
    /// request's event loop (which captured the same `Arc` at spawn) then tears down silently when
    /// the parked connect finally resolves. `None` outside a request-access flow.
    pub(crate) cancel: Mutex<Option<Arc<AtomicBool>>>,
    /// Speed-test run generation, bumped by the hosts page when it starts a run. A probe worker
    /// only publishes its outcome while its generation is still current, so a test abandoned
    /// mid-run can't overwrite a newer run's result when it finally resolves.
    pub(crate) speed_gen: std::sync::atomic::AtomicU64,
    /// Whether the live session child is a `--browse` console-UI run (vs a stream) — the
    /// session status page words itself accordingly. Set by each spawn.
    pub(crate) browse: std::sync::atomic::AtomicBool,
}

pub struct AppCtx {
    pub(crate) identity: (String, String),
    /// The settings snapshot the UI renders from. Loaded once at startup, and RE-BASED on
    /// the file when the settings page is (re)entered (`settings::refresh_snapshot`) and
    /// inside every `commit` — this process is not the file's only writer (session resize,
    /// console UI, Decky), so a plain process-lifetime snapshot goes stale on screen.
    pub(crate) settings: Mutex<Settings>,
    pub(crate) gamepad: GamepadService,
    pub(crate) shared: Arc<Shared>,
}

pub fn run(identity: (String, String), gamepad: GamepadService) -> windows_reactor::Result<()> {
    // The host tiles' OS marks and the library's launcher marks load as file:/// URIs — put the
    // embedded PNGs on disk first.
    os_icons::install();
    launcher_icons::install();
    let ctx = Arc::new(AppCtx {
        identity,
        settings: Mutex::new(Settings::load()),
        gamepad,
        shared: Arc::new(Shared::default()),
    });
    // Re-apply the persisted forwarded-controller pin (stable key; the service matches it
    // whenever such a pad connects) — GTK-shell parity.
    {
        let forward = ctx.settings.lock().unwrap().forward_pad.clone();
        if !forward.is_empty() {
            ctx.gamepad.set_pinned(Some(forward));
        }
    }
    apply_window_icon_when_ready();
    App::new()
        .title("Punktfunk")
        .inner_size(1000.0, 720.0)
        // A floor under every layout: below this the header/cards would clip rather than
        // reflow (the pages adapt down to it — see the hosts page's responsive grid).
        .inner_constraints(InnerConstraints {
            min_width: Some(420.0),
            min_height: Some(360.0),
            ..Default::default()
        })
        .backdrop(Backdrop::Mica)
        .render(move |cx| root(cx, &ctx))
}

/// Stamp the embedded app icon (build.rs, resource ordinal 1) onto the top-level window once it
/// exists: `WM_SETICON` drives the title bar and Alt-Tab (plus the taskbar for unpackaged runs;
/// the MSIX taskbar/Start icons come from the package assets). windows-reactor creates its
/// window icon-less and exposes no handle before `App::render` blocks, so a short background
/// poll finds our own window by its (unique) title.
fn apply_window_icon_when_ready() {
    use windows::Win32::libloaderapi::GetModuleHandleW;
    use windows::Win32::minwindef::{LPARAM, WPARAM};
    use windows::Win32::winuser::{
        FindWindowW, GetSystemMetrics, LoadImageW, SendMessageW, ICON_BIG, ICON_SMALL, IMAGE_ICON,
        LR_DEFAULTCOLOR, SM_CXICON, SM_CXSMICON, WM_SETICON,
    };
    let _ = std::thread::Builder::new()
        .name("pf-window-icon".into())
        // SAFETY: every call in this thread is a Win32 window/icon API taking either a static wide
        // literal, a handle it just obtained and checked, or the module handle of this process; none
        // of them dereference caller memory, and the loop gives up after 100 tries.
        .spawn(|| unsafe {
            for _ in 0..100 {
                let hwnd = FindWindowW(None, windows::core::w!("Punktfunk"));
                if !hwnd.0.is_null() {
                    let module = GetModuleHandleW(None);
                    if module.0.is_null() {
                        return;
                    }
                    // Small (title bar) and big (Alt-Tab) at their native metrics, both from
                    // the multi-size .ico so nothing is scaled at draw time.
                    // MAKEINTRESOURCE(1): the "pointer" IS the resource ordinal — not a
                    // dangling pointer, and `ptr::dangling()` (an alignment-based address)
                    // would name a different resource.
                    #[allow(clippy::manual_dangling_ptr)]
                    let ordinal_1 = windows::core::PCWSTR(1 as *const u16);
                    for (which, metric) in [(ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)] {
                        let px = GetSystemMetrics(metric);
                        let icon = LoadImageW(
                            Some(module),
                            ordinal_1,
                            IMAGE_ICON as u32,
                            px,
                            px,
                            LR_DEFAULTCOLOR as u32,
                        );
                        if !icon.0.is_null() {
                            SendMessageW(
                                hwnd,
                                WM_SETICON as u32,
                                WPARAM(which as usize),
                                LPARAM(icon.0 as isize),
                            );
                        }
                    }
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
}

fn root(cx: &mut RenderCx, ctx: &Arc<AppCtx>) -> Element {
    let (screen, set_screen) = cx.use_async_state(Screen::Hosts);
    let (status, set_status) = cx.use_async_state(String::new());
    let (hud, set_hud) = cx.use_async_state(stream::HudSample::default());
    let (speed, set_speed) = cx.use_async_state(SpeedState::Running);
    // Per-host action state for the hosts page. Root, not page-local: the "…" overflow is a WinUI
    // MenuFlyout whose item clicks are wired straight in the reactor backend, bypassing the normal
    // event-dispatch flush — a sync page-local setter marks state dirty but never re-renders. See
    // `hosts::HostsProps`.
    let (forget, set_forget) = cx.use_async_state(Option::<(String, String)>::None);
    let (rename, set_rename) = cx.use_async_state(Option::<(String, String)>::None);
    let (show_add, set_show_add) = cx.use_async_state(false);
    // Hovered host tile (its stable id), driving the WinUI-style card hover fill. Root state for
    // the same reason as `forget`/`rename`: pointer enter/exit handlers are wired straight in the
    // reactor backend, so only a root `AsyncSetState` reliably re-renders the page.
    let (hover, set_hover) = cx.use_async_state(Option::<String>::None);
    // Which Settings section the NavigationView shows (persists across visits this run).
    // Opens on General — the first sidebar item, matching the Apple client's landing category.
    let (settings_nav, set_settings_nav) = cx.use_async_state("general".to_string());
    // Which LAYER the settings screen edits: "" = the global defaults, else a profile id
    // (design/client-settings-profiles.md §5.1). Root state for the same reason as the section
    // above — the ComboBox's change handler is wired in the reactor backend.
    let (settings_scope, set_settings_scope) = cx.use_async_state(String::new());
    // The profile a Delete… click is asking about; `Some` renders the confirmation. Root state
    // because this page stays hook-free (its handlers are wired in the reactor backend).
    let (settings_delete, set_settings_delete) = cx.use_async_state(Option::<String>::None);
    // Whether the Edit-profile modal is up. Root state for the reactor-backend-handler reason
    // above; guarded in the page so it only renders while a profile is actually in scope.
    let (settings_edit, set_settings_edit) = cx.use_async_state(false);
    // Bumped when a settings edit changes what the page should SHOW without changing any state
    // it already reads — ANY edit through `settings::commit` (creating an override must surface
    // its marker as immediately as resetting one clears it), a reset, a profile colour change.
    // Root state comparison makes same-value calls free, so a counter is what forces the pass.
    let (settings_rev, set_settings_rev) = cx.use_async_state(0u64);
    // The hosts page's mirror of the same idea: pin/unpin from a tile's menu rewrites the
    // known-hosts store behind the tiles, and the bump is what makes the pinned tile appear
    // in the same gesture instead of on the next discovery tick.
    let (hosts_rev, set_hosts_rev) = cx.use_async_state(0u64);
    // `punktfunk://` links: the receiver thread queues them (from this launch's argv, or from a
    // later instance over WM_COPYDATA) and this poll pulls them onto the UI thread. Thread-fed
    // state must be root state, like the pad count below.
    let (deep_link, set_deep_link) = cx.use_async_state(Option::<String>::None);
    cx.use_effect((), {
        let set_deep_link = set_deep_link.clone();
        move || {
            std::thread::Builder::new()
                .name("pf-deeplink-poll".into())
                .spawn(move || loop {
                    for url in crate::deeplink::drain() {
                        set_deep_link.call(Some(url));
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                })
                .ok();
        }
    });
    // Saved-host reachability, keyed by `fp_hex`, refreshed by the probe sweep below. Root state
    // (thread-driven → must be root to re-render — see the module docs), passed to the hosts page.
    let (probed, set_probed) = cx.use_async_state(HashMap::<String, bool>::new());

    // Route an arriving link. Parsing, host and profile resolution and every refusal rule live
    // in the shared brain (`plan_from_link`); this is only the WinUI end — turn the outcome into
    // the same call a tile click makes, so a link gets the identical wake, trust and error
    // surfaces rather than a second connect path of its own.
    cx.use_effect(deep_link.clone(), {
        let (ctx, set_screen, set_status, set_deep_link) = (
            ctx.clone(),
            set_screen.clone(),
            set_status.clone(),
            set_deep_link.clone(),
        );
        let screen_now = screen.clone();
        move || {
            let Some(url) = deep_link.clone() else {
                return;
            };
            set_deep_link.call(None);
            let refuse = |msg: String| {
                tracing::info!(%msg, "deep link refused");
                set_status.call(msg);
                set_screen.call(Screen::Hosts);
            };
            let link = match pf_client_core::deeplink::parse(&url) {
                Ok(l) => l,
                Err(e) => return refuse(e.message()),
            };
            // Rule 2 of §3: never preempt a live session. Only this layer knows one is running,
            // which is why the brain leaves the check here.
            if matches!(screen_now, Screen::Stream | Screen::Connecting) {
                return refuse("已有会话正在运行 \u{2014} 请先结束它。".into());
            }
            let known = KnownHosts::load();
            let plan = pf_client_core::orchestrate::plan_from_link(
                &link,
                &known,
                &pf_client_core::profiles::ProfilesFile::load(),
                &ctx.settings.lock().unwrap().clone(),
            );
            use pf_client_core::orchestrate::PlanOutcome;
            match plan {
                Ok(PlanOutcome::Connect(p)) => {
                    let target = Target {
                        name: p.host.name.clone(),
                        addr: p.host.addr.clone(),
                        port: p.host.port,
                        fp_hex: p.host.fp_hex.clone(),
                        pair_optional: false,
                        mac: p.host.mac.clone(),
                        mgmt_port: p.host.mgmt_port,
                        profile: p.profile_override.clone(),
                        launch: None, // routed explicitly below (initiate_launch*)
                        wg: p.host.wg.is_some(),
                    };
                    // With a MAC it takes the dial first wake path, so a sleeping host wakes
                    // instead of erroring — exactly what clicking its tile would do. The
                    // link's `launch=` id must reach the session (`--launch`) — this arm used
                    // to drop it, so a game link opened a plain desktop session.
                    match (p.launch.clone(), p.wake && !target.mac.is_empty()) {
                        (Some(id), true) => {
                            connect::initiate_launch_waking(
                                &ctx,
                                target,
                                id,
                                &set_screen,
                                &set_status,
                            );
                        }
                        (Some(id), false) => {
                            connect::initiate_launch(&ctx, target, id, &set_screen, &set_status);
                        }
                        (None, true) => {
                            connect::initiate_waking(&ctx, target, &set_screen, &set_status)
                        }
                        (None, false) => connect::initiate(&ctx, target, &set_screen, &set_status),
                    }
                }
                // Known but never pinned, or not known at all: this build has no PIN ceremony,
                // so an untrusted link target is a dead end — point the user at WG mode.
                Ok(PlanOutcome::ConfirmUnknown(u)) => {
                    let name = u.name.clone().unwrap_or_else(|| u.addr.clone());
                    refuse(format!(
                        "{name} 尚未与本设备配对 —— 此版本已移除 PIN 配对流程，请用 WireGuard 模式手动添加。"
                    ));
                }
                Ok(PlanOutcome::Unsupported(route)) => refuse(format!(
                    "Punktfunk 暂时无法打开 \u{201c}{}\u{201d} 链接。",
                    route.as_str()
                )),
                Err(e) => refuse(e.message()),
            }
        }
    });

    // HUD sample: the spawned session child's latest `stats:` line, mirrored into root state so
    // the stream status page gets it as a *prop* (thread-driven state must be root state — see the
    // module docs). The compare in `AsyncSetState::call` makes the idle case free.
    cx.use_effect((), {
        let shared = ctx.shared.clone();
        let set_hud = set_hud.clone();
        move || {
            std::thread::Builder::new()
                .name("pf-hud".into())
                .spawn(move || loop {
                    std::thread::sleep(std::time::Duration::from_millis(400));
                    set_hud.call(stream::HudSample {
                        stats_line: shared.stats_line.lock().unwrap().clone(),
                    });
                })
                .ok();
        }
    });

    // Periodic reachability sweep (spawned once): a saved host reached only over a routed network
    // (Tailscale/VPN) never advertises on mDNS, so presence can't come from the discovery stream
    // alone. This probes every saved host (bounded, trust-agnostic QUIC handshake — one thread each
    // so a slow/unreachable host doesn't delay the rest) and mirrors the results into root state so
    // the tiles get them as a prop; the pip then reads `advertising OR probed-reachable` — the
    // display-side companion to the dial-first connect fix. The compare in `call` makes idle free.
    cx.use_effect((), {
        let set_probed = set_probed.clone();
        let shared = ctx.shared.clone();
        move || {
            std::thread::Builder::new()
                .name("pf-probe".into())
                .spawn(move || {
                    loop {
                        // A spawned session/browse child is running: the shell is hidden
                        // (nobody sees the pips) and one of these hosts is mid-stream —
                        // probing it is pure noise. Sleep through and sweep after it ends.
                        if shared.session.lock().unwrap().is_running() {
                            std::thread::sleep(Duration::from_secs(12));
                            continue;
                        }
                        let handles: Vec<_> = KnownHosts::load()
                            .hosts
                            .into_iter()
                            .filter(|h| !h.addr.is_empty())
                            .map(|h| {
                                std::thread::spawn(move || {
                                    (
                                        h.fp_hex,
                                        NativeClient::probe(
                                            &h.addr,
                                            h.port,
                                            Duration::from_millis(2500),
                                        ),
                                    )
                                })
                            })
                            .collect();
                        let map: HashMap<String, bool> =
                            handles.into_iter().filter_map(|h| h.join().ok()).collect();
                        set_probed.call(map);
                        std::thread::sleep(Duration::from_secs(12));
                    }
                })
                .ok();
        }
    });

    // Screen-entrance animation: each navigation slides the new screen up a few px while fading it
    // in (the Windows-Settings drill-in). It's a manual tween, not a composition animation, because
    // reactor's DSL exposes no static transform/translation setter and its one-shot animations run
    // from the visual's CURRENT value (a shown element is already at opacity 1, so nothing to fade
    // from). So a worker thread steps a 0 → 1 `progress` after each navigation; the wrapper maps it
    // to opacity (= progress) and a top margin (= (1-progress)·offset). The page components are
    // memoised on unchanged props, so each step is just a cheap root re-render updating two props.
    // A generation guard (bumped per navigation) stops a superseded tween so rapid nav can't fight.
    let anim_gen = cx.use_ref(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let (anim, set_anim) = cx.use_async_state((Option::<Screen>::None, 1.0f64));
    cx.use_effect(screen.clone(), {
        let (s, set_anim, generation) =
            (screen.clone(), set_anim.clone(), anim_gen.borrow().clone());
        move || {
            use std::sync::atomic::Ordering::SeqCst;
            let mine = generation.fetch_add(1, SeqCst) + 1;
            std::thread::spawn(move || {
                const STEPS: u32 = 14;
                for i in 0..=STEPS {
                    if generation.load(SeqCst) != mine {
                        return; // a newer navigation superseded this tween
                    }
                    let p = f64::from(i) / f64::from(STEPS);
                    let eased = 1.0 - (1.0 - p).powi(3); // ease-out cubic
                    set_anim.call((Some(s.clone()), eased));
                    std::thread::sleep(std::time::Duration::from_millis(16));
                }
            });
        }
    });
    // Progress for THIS screen: 0 until the tween for it starts (fresh navigation starts hidden +
    // offset, no flash), 1 once settled. A stale value for another screen reads as 0.
    let progress = if anim.0.as_ref() == Some(&screen) {
        anim.1
    } else {
        0.0
    };

    // Settings-section entrance: the same tween again, keyed on the selected section, so
    // switching panes slides the CONTENT column up (the sidebar stays put — this must not wrap
    // the NavigationView, so it can't ride the screen-level tween above). Entering Settings
    // fresh leaves it settled at 1 (only the screen tween plays; no double animation).
    let nav_gen = cx.use_ref(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let (nav_anim, set_nav_anim) = cx.use_async_state((String::new(), 1.0f64));
    cx.use_effect(settings_nav.clone(), {
        let (s, set_nav_anim, generation) = (
            settings_nav.clone(),
            set_nav_anim.clone(),
            nav_gen.borrow().clone(),
        );
        move || {
            use std::sync::atomic::Ordering::SeqCst;
            let mine = generation.fetch_add(1, SeqCst) + 1;
            std::thread::spawn(move || {
                const STEPS: u32 = 14;
                for i in 0..=STEPS {
                    if generation.load(SeqCst) != mine {
                        return; // a newer section switch superseded this tween
                    }
                    let p = f64::from(i) / f64::from(STEPS);
                    let eased = 1.0 - (1.0 - p).powi(3);
                    set_nav_anim.call((s.clone(), eased));
                    std::thread::sleep(std::time::Duration::from_millis(16));
                }
            });
        }
    });
    let nav_progress = if nav_anim.0 == settings_nav {
        nav_anim.1
    } else {
        0.0
    };

    // "Add host" modal entrance: the same manual tween as the screen navigation (see above for
    // why it can't be a composition animation), stepping 0 → 1 when the modal opens. The hosts
    // page maps it to the modal's opacity + a downward start offset (the slide-up) and the
    // scrim's fade. Closing resets to 0 instantly — the modal unmounts, nothing to animate.
    let add_gen = cx.use_ref(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)));
    let (add_anim, set_add_anim) = cx.use_async_state(0.0f64);
    cx.use_effect(show_add, {
        let (set_add_anim, generation) = (set_add_anim.clone(), add_gen.borrow().clone());
        move || {
            use std::sync::atomic::Ordering::SeqCst;
            let mine = generation.fetch_add(1, SeqCst) + 1;
            if !show_add {
                set_add_anim.call(0.0);
                return;
            }
            std::thread::spawn(move || {
                const STEPS: u32 = 12;
                for i in 0..=STEPS {
                    if generation.load(SeqCst) != mine {
                        return; // reopened/closed mid-tween — a newer run owns the value
                    }
                    let p = f64::from(i) / f64::from(STEPS);
                    set_add_anim.call(1.0 - (1.0 - p).powi(3)); // ease-out cubic
                    std::thread::sleep(std::time::Duration::from_millis(16));
                }
            });
        }
    });

    // Each hook-using screen is mounted as its own component so its hooks are isolated from
    // root's (root's own hooks above stay a stable prefix regardless of which screen renders).
    let svc = Svc {
        ctx: ctx.clone(),
        set_screen: set_screen.clone(),
        set_status: set_status.clone(),
        set_speed: set_speed.clone(),
    };
    let body = match &screen {
        Screen::Hosts => component(
            hosts::hosts_page,
            HostsProps {
                svc,
                probed,
                status,
                forget,
                rename,
                show_add,
                add_anim,
                hover,
                hosts_rev,
                set_forget,
                set_rename,
                set_show_add,
                set_hover,
                set_hosts_rev: set_hosts_rev.clone(),
            },
        ),
        // connecting_page / request_access_page / waking_page / settings_page / licenses_page /
        // help_page use no hooks (they never touch `cx`), so calling them inline is sound.
        Screen::Connecting => connect::connecting_page(ctx, &status),
        Screen::RequestAccess => connect::request_access_page(ctx, &set_screen),
        Screen::Waking => connect::waking_page(ctx, &set_screen),
        Screen::Settings => settings::settings_page(
            ctx,
            &set_screen,
            &settings_nav,
            &set_settings_nav,
            &settings_scope,
            &set_settings_scope,
            &settings_delete,
            &set_settings_delete,
            settings_edit,
            &set_settings_edit,
            settings_rev,
            &set_settings_rev,
            nav_progress,
        ),
        Screen::Licenses => licenses::licenses_page(ctx, &set_screen),
        Screen::Help => help::help_page(&set_screen),
        Screen::SpeedTest => component(speed::speed_page, SpeedProps { svc, state: speed }),
        // The stream runs in the punktfunk-session child's own window; this screen is a
        // status page (no hooks — inline is sound).
        Screen::Stream => stream::session_page(ctx, &hud),
    };

    // The Stream screen is a plain status card (the session child owns the real stream window);
    // it's shown without the navigation entrance tween. Everything else slides + fades in.
    if matches!(screen, Screen::Stream) {
        return body;
    }
    let offset = (1.0 - progress) * 22.0;
    border(body)
        .opacity(progress)
        .margin(Thickness {
            left: 0.0,
            top: offset,
            right: 0.0,
            bottom: 0.0,
        })
        .into()
}
