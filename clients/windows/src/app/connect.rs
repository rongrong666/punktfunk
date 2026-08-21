//! The trust gate and session lifecycle glue: `initiate` routes a connect through the trust
//! rules (pinned → silent, WireGuard-mode → tunnel-authenticated, `pair=optional` → TOFU),
//! `connect_with` starts the session worker and drives navigation from its events, and the
//! "request access" (delegated-approval) flow parks an identified connect until the operator
//! approves it. This build has NO PIN pairing ceremony and no mDNS discovery.

use super::style::*;
use super::{AppCtx, Screen, Svc, Target};
use crate::trust::{self, KnownHost, KnownHosts};
use pf_client_core::orchestrate::{WakeOutcome, WakeWait};
use punktfunk_core::client::NativeClient;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use windows_reactor::*;

/// The no-pairing refusal: this build removed the PIN ceremony, so a host with no stored
/// fingerprint and no WireGuard config cannot be connected — say so and stay put.
fn refuse_unpaired(target: &Target, set_status: &AsyncSetState<String>) {
    set_status.call(format!(
        "{} 尚未与本设备配对 —— 此版本已移除 PIN 配对流程，请改用 WireGuard 模式添加。",
        if target.name.is_empty() {
            &target.addr
        } else {
            &target.name
        }
    ));
}

/// The trust gate (mirrors the GTK client's `initiate_connect`): pinned fingerprint → silent
/// connect; known address → stored pin; advertised `pair=optional` → TOFU; otherwise → PIN
/// pairing.
pub(crate) fn initiate(
    ctx: &Arc<AppCtx>,
    target: Target,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    initiate_opts(ctx, target, set_screen, set_status, false)
}

/// Dial-first for a saved host that isn't advertising but has a known MAC: fire the magic packet
/// now (fire-and-forget — harmless if it's awake, and a genuinely-asleep box is already booting
/// while the dial times out) and dial IMMEDIATELY. mDNS absence does NOT mean unreachable — a
/// host reached over a routed network (Tailscale/VPN/another subnet) is mDNS-blind forever, and
/// gating the dial on presence bricked exactly those reconnects. Only a failed dial falls into
/// the visible [`wake_and_connect`] wait.
pub(crate) fn initiate_waking(
    ctx: &Arc<AppCtx>,
    target: Target,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    if ctx.settings.lock().unwrap().auto_wake {
        crate::wol::wake(&target.mac, target.addr.parse().ok());
    }
    initiate_opts(ctx, target, set_screen, set_status, true)
}

fn initiate_opts(
    ctx: &Arc<AppCtx>,
    target: Target,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
    wake_on_fail: bool,
) {
    // Every route reads the target back for its screen copy ("Connecting to X",
    // "Streaming to X") — stash it up front, not just on the pairing route.
    *ctx.shared.target.lock().unwrap() = target.clone();
    let known = KnownHosts::load();
    let pin = target
        .fp_hex
        .as_ref()
        .and_then(|fp| known.find_by_fp(fp).map(|_| fp.clone()))
        .or_else(|| {
            known
                .find_by_addr(&target.addr, target.port)
                .map(|k| k.fp_hex.clone())
        })
        .and_then(|fp| trust::parse_hex32(&fp));

    let opts = ConnectOpts {
        wake_on_fail,
        ..ConnectOpts::default()
    };
    // WireGuard mode authenticates both ends in the tunnel handshake — no pin needed, and the
    // host's TLS fingerprint is learned from the session's own Welcome on first connect.
    let wg = target.wg
        || known
            .find_by_addr(&target.addr, target.port)
            .is_some_and(|k| k.wg.is_some());
    if wg {
        connect_with(ctx, &target, pin, set_screen, set_status, opts);
    } else if let Some(pin) = pin {
        connect_with(ctx, &target, Some(pin), set_screen, set_status, opts);
    } else if target.pair_optional {
        connect_with(ctx, &target, None, set_screen, set_status, opts); // TOFU
    } else {
        refuse_unpaired(&target, set_status);
    }
}

/// Start a stream that launches a library title on connect (`--launch id`) — the library
/// page's tap-to-play, and a deep link's `launch=` (which this used to drop: the link
/// opened a plain desktop session). The library only opens for paired hosts, so the pin
/// resolves like a normal initiate; a host forgotten mid-visit routes to the PIN ceremony
/// instead.
pub(crate) fn initiate_launch(
    ctx: &Arc<AppCtx>,
    target: Target,
    launch: String,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    initiate_launch_opts(ctx, target, launch, set_screen, set_status, false)
}

/// [`initiate_launch`] with the dial-first wake of [`initiate_waking`] — a deep link's
/// `launch=` toward a saved host that isn't advertising but has a known MAC.
pub(crate) fn initiate_launch_waking(
    ctx: &Arc<AppCtx>,
    target: Target,
    launch: String,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    if ctx.settings.lock().unwrap().auto_wake {
        crate::wol::wake(&target.mac, target.addr.parse().ok());
    }
    initiate_launch_opts(ctx, target, launch, set_screen, set_status, true)
}

fn initiate_launch_opts(
    ctx: &Arc<AppCtx>,
    target: Target,
    launch: String,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
    wake_on_fail: bool,
) {
    *ctx.shared.target.lock().unwrap() = target.clone();
    let known = KnownHosts::load();
    let pin = target
        .fp_hex
        .as_deref()
        .and_then(trust::parse_hex32)
        .or_else(|| {
            known
                .find_by_addr(&target.addr, target.port)
                .and_then(|k| trust::parse_hex32(&k.fp_hex))
        });
    let Some(pin) = pin else {
        // WG targets need no pin (tunnel-authenticated); anything else has no pairing
        // ceremony left to detour through in this build.
        let wg = target.wg
            || known
                .find_by_addr(&target.addr, target.port)
                .is_some_and(|k| k.wg.is_some());
        if !wg {
            refuse_unpaired(&target, set_status);
            return;
        }
        connect_with(
            ctx,
            &target,
            None,
            set_screen,
            set_status,
            ConnectOpts {
                launch: Some(launch),
                wake_on_fail,
                ..ConnectOpts::default()
            },
        );
        return;
    };
    connect_with(
        ctx,
        &target,
        Some(pin),
        set_screen,
        set_status,
        ConnectOpts {
            launch: Some(launch),
            wake_on_fail,
            ..ConnectOpts::default()
        },
    );
}

/// Tunables that differ between the normal connect and the no-PIN "request access" flow.
/// `Default` is the normal connect: short handshake budget, persist *unpaired* on TOFU, and the
/// plain "Connecting" screen.
pub(crate) struct ConnectOpts {
    /// Handshake budget. Request-access uses a long one because the host PARKS the connection
    /// until the operator clicks Approve in its console (see the host's `PENDING_APPROVAL_WAIT`).
    connect_timeout: Duration,
    /// Persist the host as *paired* on a successful connect. Set for request-access, where the
    /// operator's approval IS the pairing, so future connects are silent (rule 1). Normal TOFU
    /// persists the host *unpaired* (pinned, but not PIN/approval-verified).
    persist_paired: bool,
    /// Show the cancelable "waiting for approval" screen instead of "Connecting" (request-access).
    awaiting_approval: bool,
    /// Set by the waiting screen's Cancel button. `NativeClient::connect` is blocking with no
    /// abort, so Cancel returns the UI immediately and leaves the parked connect to resolve/time
    /// out; this request's event loop (which captured the same `Arc` at spawn) then tears down
    /// silently when the parked connect finally resolves — without touching a screen a new
    /// session may already own.
    cancel: Option<Arc<AtomicBool>>,
    /// Fall into the Wake-on-LAN wait ([`wake_and_connect`]) when THIS dial fails with a plain
    /// connect failure (not a trust rejection). Set by the dial-first path for a saved host that
    /// isn't advertising but has a known MAC — the dial is attempted unconditionally (mDNS
    /// absence ≠ unreachable: routed/Tailscale hosts never advertise here), and only a real
    /// failure escalates to the visible "Waking…" wait. The wait's own redial clears the flag,
    /// so it can't loop.
    wake_on_fail: bool,
    /// A library title id (`steam:570`, …) the host launches during the connect handshake —
    /// the library page's tap-to-play, passed to the spawned session child as `--launch`.
    launch: Option<String>,
}

impl Default for ConnectOpts {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(15),
            persist_paired: false,
            awaiting_approval: false,
            cancel: None,
            wake_on_fail: false,
            launch: None,
        }
    }
}

#[allow(dead_code)] // the plain-connect helper of the removed pairing screens
pub(crate) fn connect(
    ctx: &Arc<AppCtx>,
    target: &Target,
    pin: Option<[u8; 32]>,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    connect_with(
        ctx,
        target,
        pin,
        set_screen,
        set_status,
        ConnectOpts::default(),
    );
}

fn connect_with(
    ctx: &Arc<AppCtx>,
    target: &Target,
    pin: Option<[u8; 32]>,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
    opts: ConnectOpts,
) {
    // Session-always: every stream runs in the spawned punktfunk-session Vulkan binary.
    connect_spawn(ctx, target, pin, set_screen, set_status, opts)
}

/// Spawn-mode connect: run the stream in the punktfunk-session binary and translate its
/// stdout contract into the app's connect-flow navigation. The child
/// NEVER connects unpinned — a stored/ceremony pin, else the host's advertised
/// fingerprint (TOFU: persisted once the child reports ready, which proves the host
/// really holds that identity, mirroring the GTK shell); no fingerprint at all routes to
/// the PIN ceremony.
fn connect_spawn(
    ctx: &Arc<AppCtx>,
    target: &Target,
    pin: Option<[u8; 32]>,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
    opts: ConnectOpts,
) {
    let tofu = pin.is_none();
    let fp_hex = pin.map(|p| trust::hex(&p)).or_else(|| {
        target
            .fp_hex
            .clone()
            .filter(|f| trust::parse_hex32(f).is_some())
    });
    let fp_hex = match fp_hex {
        Some(fp) => fp,
        // WG mode connects with NO pinned fingerprint — the tunnel handshake is the
        // authentication, and the session child learns the host's TLS fingerprint from the
        // Welcome (learn_fp_by_addr). Empty fp_arg → spawn_session passes no --fp.
        None if target.wg
            || KnownHosts::load()
                .find_by_addr(&target.addr, target.port)
                .is_some_and(|k| k.wg.is_some()) =>
        {
            String::new()
        }
        None => {
            refuse_unpaired(target, set_status);
            return;
        }
    };

    // A fresh child slot per spawn, installed where Disconnect/Cancel can reach it.
    let child = crate::spawn::SessionChild::default();
    *ctx.shared.session.lock().unwrap() = child.clone();
    ctx.shared.stats_line.lock().unwrap().clear();
    ctx.shared.browse.store(false, Ordering::SeqCst);
    set_status.call(String::new());
    set_screen.call(if opts.awaiting_approval {
        Screen::RequestAccess
    } else {
        Screen::Connecting
    });

    let persist_paired = opts.persist_paired;
    let cancel = opts.cancel;
    let wake_on_fail = opts.wake_on_fail;
    let ctx2 = ctx.clone();
    let shared = ctx.shared.clone();
    let (ss, st) = (set_screen.clone(), set_status.clone());
    let target = target.clone();
    // The closure owns `target`/`fp_hex`; the call itself borrows copies.
    let (addr, port, fp_arg) = (target.addr.clone(), target.port, fp_hex.clone());
    let profile_arg = target.profile.clone();
    // The launch id: an explicit opts pick (the library's tap-to-play), else one riding
    // the target — a deep link's `launch=` that detoured through the PIN ceremony.
    let launch_arg = opts.launch.clone().or_else(|| target.launch.clone());
    let spawned = crate::spawn::spawn_session(
        &addr,
        port,
        &fp_arg,
        opts.connect_timeout.as_secs(),
        launch_arg.as_deref(),
        profile_arg.as_deref(),
        child,
        move |event| {
            use crate::spawn::SpawnEvent;
            // The child is gone — bring the shell back BEFORE the cancel gate below, so a
            // Ready that raced a Cancel (and hid the shell) can never strand it hidden.
            if matches!(event, SpawnEvent::Exited { .. }) {
                crate::shell_window::restore();
            }
            // A cancelled request-access connect that resolved late: tear down silently —
            // Cancel already killed the child and returned the UI to the host list.
            if cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst)) {
                return;
            }
            match event {
                SpawnEvent::Ready => {
                    if (persist_paired || tofu) && !fp_hex.is_empty() {
                        // Request-access: the operator approved this device — record the
                        // host PAIRED so future connects are silent. Plain TOFU persists
                        // it *unpaired* (pinned): the child connected pinned to the
                        // advertised fingerprint, so ready proves the host holds it.
                        // Either way an authorised decision, so `upsert_trusted`: a dead
                        // record for this address is retired instead of shadowing this one.
                        let mut k = KnownHosts::load();
                        k.upsert_trusted(KnownHost {
                            name: target.name.clone(),
                            addr: target.addr.clone(),
                            port: target.port,
                            fp_hex: fp_hex.clone(),
                            paired: persist_paired,
                            mac: target.mac.clone(),
                            ..Default::default()
                        });
                        let _ = k.save();
                    }
                    // The child presented its first frame — its window is up, so the
                    // shell yields: one visible Punktfunk window at a time. Every exit
                    // path restores it (the `Exited` handling above).
                    crate::shell_window::hide();
                    ss.call(Screen::Stream);
                }
                SpawnEvent::Stats(line) => *shared.stats_line.lock().unwrap() = line,
                SpawnEvent::Exited { error, ended, code } => {
                    match error {
                        Some((msg, true)) => {
                            // Pinned-fingerprint mismatch → show the reason and return to the
                            // host list (no PIN re-pair screen in this build). The host
                            // ANSWERED, so never the wake fallback.
                            st.call(msg);
                            ss.call(Screen::Hosts);
                        }
                        Some((_, false))
                            if wake_on_fail && ctx2.settings.lock().unwrap().auto_wake =>
                        {
                            // The dial-first attempt to a non-advertising host failed — it
                            // may genuinely be asleep. NOW wake and wait. Skipped entirely
                            // when auto-wake is off: the wait is only worth showing if we
                            // are actually sending magic packets to end it.
                            wake_and_connect(&ctx2, target.clone(), &ss, &st);
                        }
                        Some((msg, false)) => {
                            st.call(msg);
                            ss.call(Screen::Hosts);
                        }
                        // `ended` = the host ended the session (banner); a clean exit
                        // (user closed the stream window / Disconnect) returns silently.
                        // A child that said nothing AND failed gets the exit code, so the
                        // return to the host list is never unexplained.
                        None => {
                            st.call(
                                ended
                                    .or_else(|| crate::spawn::silent_exit_banner(code))
                                    .unwrap_or_default(),
                            );
                            ss.call(Screen::Hosts);
                        }
                    }
                }
            }
        },
    );
    if let Err(e) = spawned {
        set_status.call(e);
        set_screen.call(Screen::Hosts);
    }
}

/// "Open console UI": run the gamepad library (`punktfunk-session --browse`) for a
/// PAIRED host in the session window. The shell yields exactly like a stream — hidden on
/// the library window's `ready`, restored when the child exits (launched titles stream
/// in that same window, so the whole couch round-trip happens without the shell).
/// `target = None` opens the console's own host view (discovery, pairing, settings) — the
/// couch entry point that isn't tied to one host; `Some` opens straight into that host's
/// library.
///
/// Unused in this build (the game-library UI was removed); kept so `--browse` spawning
/// stays available for a future couch entry point.
#[allow(dead_code)]
pub(crate) fn open_console(
    ctx: &Arc<AppCtx>,
    target: Option<Target>,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    let child = crate::spawn::SessionChild::default();
    *ctx.shared.session.lock().unwrap() = child.clone();
    ctx.shared.stats_line.lock().unwrap().clear();
    ctx.shared.browse.store(true, Ordering::SeqCst);
    if let Some(t) = target.clone() {
        *ctx.shared.target.lock().unwrap() = t;
    }
    let fullscreen = ctx.settings.lock().unwrap().fullscreen_on_stream;
    set_status.call(String::new());
    set_screen.call(Screen::Connecting);

    let shared = ctx.shared.clone();
    let (ss, st) = (set_screen.clone(), set_status.clone());
    let addr_port = target.as_ref().map(|t| (t.addr.clone(), t.port));
    let spawned = crate::spawn::spawn_browse(
        addr_port.as_ref().map(|(a, p)| (a.as_str(), *p)),
        fullscreen,
        child,
        move |event| {
            use crate::spawn::SpawnEvent;
            match event {
                SpawnEvent::Ready => {
                    // The library window presented — the shell yields (same one-visible-
                    // window rule as a stream).
                    crate::shell_window::hide();
                    ss.call(Screen::Stream);
                }
                SpawnEvent::Stats(line) => *shared.stats_line.lock().unwrap() = line,
                SpawnEvent::Exited { error, ended, code } => {
                    crate::shell_window::restore();
                    // Quit from the library (B / closing the window) returns silently;
                    // a failed start surfaces its error line, or the exit code when it
                    // died without producing one.
                    st.call(
                        error
                            .map(|(msg, _)| msg)
                            .or(ended)
                            .or_else(|| crate::spawn::silent_exit_banner(code))
                            .unwrap_or_default(),
                    );
                    ss.call(Screen::Hosts);
                }
            }
        },
    );
    if let Err(e) = spawned {
        set_status.call(e);
        set_screen.call(Screen::Hosts);
    }
}

/// The no-PIN "request access" flow: open an identified connect that the host PARKS until the
/// operator approves this device in its console (or web UI), showing a cancelable "waiting"
/// screen meanwhile. On approval the SAME connection is admitted (no reconnect) and the host is
/// saved as paired, so later connects are silent.
#[allow(dead_code)] // entry points went with the removed pairing/discovery screens
pub(crate) fn request_access(props: &Svc, target: &Target) {
    let ctx = &props.ctx;
    // Pin the advertised certificate for a discovered host (defence against a host impostor while
    // we wait); a manually-typed host has no advertised fingerprint, so trust-on-first-use.
    let pin = target.fp_hex.as_deref().and_then(trust::parse_hex32);
    // A fresh cancel flag per request, installed where the waiting screen's Cancel button can read
    // it back; this request's event loop captures the same `Arc` (via ConnectOpts) below.
    let cancel = Arc::new(AtomicBool::new(false));
    *ctx.shared.cancel.lock().unwrap() = Some(cancel.clone());
    connect_with(
        ctx,
        target,
        pin,
        &props.set_screen,
        &props.set_status,
        ConnectOpts {
            // Must exceed the host's approval window (PENDING_APPROVAL_WAIT) so a slow operator
            // approval still lands on this connection rather than timing the client out first.
            connect_timeout: Duration::from_secs(185),
            persist_paired: true,
            awaiting_approval: true,
            cancel: Some(cancel),
            ..ConnectOpts::default()
        },
    );
}

/// The Wake-on-LAN "wait until up" flow (mirrors the Apple `HostWaker`): the FALLBACK after a
/// failed dial-first attempt ([`initiate_waking`]) to an offline saved host with a MAC.
/// Send a magic packet, show a cancelable "Waking…" screen, and PROBE the host's QUIC port
/// until it answers — re-sending the packet periodically — on a bounded deadline (a cold box
/// takes far longer to POST/boot than a connect attempt will sit). This build has no mDNS
/// discovery, so the probe (not an advert) is the online signal; when the host answers we
/// dial it as saved. On timeout or Cancel we return to the host list.
///
/// The cadence is [`WakeWait`], shared with the GTK shell and ported from Apple's `HostWaker`
/// (design/client-architecture-split.md §3).
fn wake_and_connect(
    ctx: &Arc<AppCtx>,
    target: Target,
    set_screen: &AsyncSetState<Screen>,
    set_status: &AsyncSetState<String>,
) {
    // The packets are the wait's business: `WakeWait` asks for one on its first tick and every
    // 6 s after (a single one can be missed, and some NICs only wake on a fresh packet after
    // dropping into a deeper sleep state).
    // A fresh cancel flag per wake, installed where the "Waking…" screen's Cancel button reads it
    // back (the same shared channel as the request-access flow); the poll loop checks the same `Arc`.
    let cancel = Arc::new(AtomicBool::new(false));
    *ctx.shared.cancel.lock().unwrap() = Some(cancel.clone());
    // The busy page reads the host name from the shared target.
    *ctx.shared.target.lock().unwrap() = target.clone();
    set_status.call(String::new());
    set_screen.call(Screen::Waking);

    let (ctx, ss, st) = (ctx.clone(), set_screen.clone(), set_status.clone());
    std::thread::spawn(move || {
        let mut wait = WakeWait::new();
        loop {
            // Cancel already returned the UI to the host list — stop re-sending and tear down.
            if cancel.load(Ordering::SeqCst) {
                return;
            }
            // No discovery in this build: a bounded, trust-agnostic QUIC handshake probe is
            // the online signal (the same probe the hosts page's reachability sweep uses).
            let online = NativeClient::probe(&target.addr, target.port, Duration::from_millis(2500));

            let tick = wait.tick(online);
            if tick.send_packet {
                crate::wol::wake(&target.mac, target.addr.parse().ok());
            }
            match tick.outcome {
                Some(WakeOutcome::Online) => {
                    initiate(&ctx, target.clone(), &ss, &st);
                    return;
                }
                Some(WakeOutcome::TimedOut) => {
                    st.call("主机未能上线。".to_string());
                    ss.call(Screen::Hosts);
                    return;
                }
                None => {}
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}

/// The plain "Connecting…" screen shown while the session worker handshakes. No hooks.
pub(crate) fn connecting_page(ctx: &Arc<AppCtx>, status: &str) -> Element {
    let target_name = ctx.shared.target.lock().unwrap().name.clone();
    let headline = if target_name.is_empty() {
        "正在连接\u{2026}".to_string()
    } else {
        format!("正在连接到 {target_name}\u{2026}")
    };
    let detail = if status.is_empty() {
        "正在协商会话并创建虚拟显示器\u{2026}"
    } else {
        status
    };
    busy_page(&headline, detail, Vec::new())
}

/// The cancelable "waiting for approval" screen (request-access flow): a spinner + guidance while
/// the identified connect sits parked on the host, plus a Cancel that returns to the host list and
/// trips the shared cancel flag so the parked connect tears down silently if it resolves after the
/// user has walked away. No hooks.
pub(crate) fn request_access_page(
    ctx: &Arc<AppCtx>,
    set_screen: &AsyncSetState<Screen>,
) -> Element {
    let target_name = ctx.shared.target.lock().unwrap().name.clone();
    let headline = if target_name.is_empty() {
        "等待批准\u{2026}".to_string()
    } else {
        format!("等待 {target_name} 批准\u{2026}")
    };
    let cancel_btn = {
        let (ctx, ss) = (ctx.clone(), set_screen.clone());
        button("取消")
            .icon(Symbol::Cancel)
            .on_click(move || {
                // Return the UI immediately; trip the flag this request's event loop
                // captured so it tears down silently when the connect resolves (see
                // ConnectOpts::cancel). Killing the parked session child IS the abort.
                if let Some(c) = ctx.shared.cancel.lock().unwrap().as_ref() {
                    c.store(true, Ordering::SeqCst);
                }
                ctx.shared.session.lock().unwrap().kill();
                ss.call(Screen::Hosts);
            })
            .horizontal_alignment(HorizontalAlignment::Center)
    };
    busy_page(
        &headline,
        "请在主机的控制台或 Web 界面中批准本设备\u{2014}\u{2014}批准后会自动连接，\
         无需 PIN 码。",
        vec![cancel_btn.into()],
    )
}

/// The cancelable "Waking…" screen (Wake-on-LAN wait-until-up flow): a spinner + guidance while the
/// poll loop waits for the woken host to reappear on mDNS, plus a Cancel that returns to the host
/// list and trips the shared cancel flag so the poll loop stops re-sending and tears down. No hooks.
pub(crate) fn waking_page(ctx: &Arc<AppCtx>, set_screen: &AsyncSetState<Screen>) -> Element {
    let target_name = ctx.shared.target.lock().unwrap().name.clone();
    let headline = if target_name.is_empty() {
        "正在唤醒主机\u{2026}".to_string()
    } else {
        format!("正在唤醒 {target_name}\u{2026}")
    };
    let cancel_btn = {
        let (ctx, ss) = (ctx.clone(), set_screen.clone());
        button("取消")
            .icon(Symbol::Cancel)
            .on_click(move || {
                // Return the UI immediately and trip the flag the poll loop is watching so it stops
                // re-sending and exits without touching a screen a later action may already own.
                if let Some(c) = ctx.shared.cancel.lock().unwrap().as_ref() {
                    c.store(true, Ordering::SeqCst);
                }
                ss.call(Screen::Hosts);
            })
            .horizontal_alignment(HorizontalAlignment::Center)
    };
    busy_page(
        &headline,
        "已发送唤醒信号，正在等待主机上线\u{2014}\u{2014}对于睡眠或关机的机器，\
         最长可能需要一分钟。",
        vec![cancel_btn.into()],
    )
}
