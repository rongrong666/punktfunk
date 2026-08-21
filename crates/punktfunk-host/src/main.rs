//! `punktfunk-host` — the Linux streaming host (plan §2, §6, §7).
//!
//! Creates a client-sized virtual display, captures it via PipeWire, encodes with
//! VAAPI/NVENC, and hands encoded access units to `punktfunk_core` for FEC + packetization +
//! pacing + send. Input flows back via libei/uinput. The platform backends are
//! `#[cfg(target_os = "linux")]`; the crate compiles everywhere so the workspace builds
//! on non-Linux dev machines — it just can't run the pipeline there.
//!
//! Subcommands: `serve` runs the native punktfunk/1 host + management REST API by default, and —
//! with `--gamestream` — the GameStream/Moonlight-compat planes too (opt-in, trusted-LAN only);
//! `punktfunk1-host` runs the native punktfunk/1 host standalone; `spike` is a capture→encode→file
//! pipeline dev tool that also round-trips the encoded AUs through a `punktfunk_core` loopback.

// Scaffold: trait methods and config paths are defined ahead of their backends.
#![allow(dead_code)]
// Unsafe-proof program (both lints now enforced by the workspace `[workspace.lints]` tables):
// every `unsafe {}` / `unsafe impl` carries a `// SAFETY:` proof, and `unsafe fn` bodies need
// explicit blocks. Keep the `unsafe fn` marker only where a caller can actually violate
// something — a raw pointer or a borrowed `HANDLE` parameter, as in `service::spawn_host`.

mod audio;
mod bringup;
mod capture;
mod detect;
mod devtest;
/// Host health verdicts as one structured channel (design/web-console-diagnostics.md).
#[forbid(unsafe_code)]
mod diagnostics;
// Network-facing on the secure default host (see the forbid block at `mod mgmt` below).
#[forbid(unsafe_code)]
mod discovery;
#[forbid(unsafe_code)]
mod wol;
// Goal-1 stage 6: top-level platform-only modules live under `src/linux/` and `src/windows/`; `#[path]`
// keeps the `crate::*` module names flat (every existing path is unchanged).
#[cfg(target_os = "windows")]
#[path = "windows/crash.rs"]
mod crash;
#[cfg(target_os = "linux")]
#[path = "linux/drm_sync.rs"]
mod drm_sync;
// The video encode backends live in the `pf-encode` leaf crate (plan §W6); this shim keeps every
// existing `crate::encode::*` path valid (the host is the sole consumer, via the negotiator + the
// GameStream/native/mgmt planes). Feature flags (nvenc/amf-qsv/vulkan-encode/pyrowave) forward to
// pf-encode from this crate's `[features]`.
mod encode {
    pub(crate) use pf_encode::*;
}
mod events;
// The lifetime of a launched game: whether it is running, when it exits (which can end the session),
// and how to end it (which a session ending can ask for) — design/session-game-lifetime.md.
mod gamelease;
// The Win32 half of ending a game: WM_CLOSE onto the interactive desktop, then TerminateProcess.
#[cfg(target_os = "windows")]
#[path = "windows/game_term.rs"]
mod game_term;
mod gamestream;
#[cfg(target_os = "linux")]
#[path = "linux/gpuclocks.rs"]
mod gpuclocks;
mod hooks;
// Network-facing on the secure default host (see the forbid block at `mod mgmt` below). Test
// builds carve out like `native`: the identity tests scope `PUNKTFUNK_CONFIG_DIR` by mutating
// the process env, which edition 2024 makes an unsafe call; shipped code keeps the forbid.
#[cfg_attr(not(test), forbid(unsafe_code))]
mod identity;
// The input-injection backends live in the `pf-inject` subsystem crate (plan §W6); this shim keeps
// every existing `crate::inject::*` path valid (the native/gamestream input planes + devtest consume
// the trait, factory, and per-device backends through it).
mod inject {
    pub(crate) use pf_inject::*;
}
#[cfg(target_os = "windows")]
#[path = "windows/install.rs"]
mod install;
#[cfg(target_os = "windows")]
#[path = "windows/interactive.rs"]
mod interactive;
// What this host launched, for whom, and when — so a client that re-dials and re-sends its
// `Hello::launch` verbatim neither gets a second copy of its game nor loses sight of the one it has
// (design/session-game-lifetime.md).
mod client_logs;
mod launchreg;
mod library;
mod log_capture;
// The native punktfunk/1 plane and the management API — everything a SECURE-DEFAULT host
// exposes — are safe Rust by compiler-enforced invariant (rust-safety programme): `forbid`
// here means a future edit cannot quietly introduce unsafe into a network-facing module.
// (`native` carves out its `#[cfg(test)]` C-ABI roundtrip tests, which exercise the CLIENT
// side of punktfunk-core against this host in-process and are unsafe by nature; `mgmt` and
// `identity` carve out test builds too — their tests scope `PUNKTFUNK_CONFIG_DIR` by mutating
// the process env, an unsafe call since edition 2024.)
#[cfg_attr(not(test), forbid(unsafe_code))]
mod mgmt;
#[forbid(unsafe_code)]
mod mgmt_token;
#[cfg_attr(not(test), forbid(unsafe_code))]
mod native;
#[forbid(unsafe_code)]
mod native_pairing;
mod osinfo;
mod pipeline;
mod plugins;
// Finding a launched game's processes from its store's detect signals — the read side of the
// session⇄game lifetime binding (design/session-game-lifetime.md §4). Per-OS matchers inside; on a
// platform with neither (macOS, which has no launch path either) the module is an empty shell.
mod procscan;
mod send_pacing;
#[cfg(target_os = "windows")]
#[path = "windows/service.rs"]
mod service;
mod session_plan;
// Operator policy for the session⇄game lifetime binding (`session-settings.json`).
mod session_settings;
mod session_status;
mod sleep_inhibit;
mod spike;
mod stats_recorder;
// Start/stop/status for the per-user tray — the recovery path it has never had of its own.
#[cfg(target_os = "windows")]
#[path = "windows/tray.rs"]
mod tray;
// The plugin store: signed catalogs, tiered trust, and install/uninstall jobs that run through the
// same runner CLI the `plugins` subcommand uses (design/plugin-store.md).
mod store;
mod stream_marker;
mod update;
// The two startup crash-recovery legs (below), both in the `pf-win-display` leaf crate (plan §W6):
// `monitor_devnode::startup_recover()` re-enables PnP monitor devnodes disabled by a prior run, and
// `isolate_journal::startup_recover()` re-lights displays a prior run deactivated for an EXCLUSIVE
// session and never restored.
#[cfg(target_os = "windows")]
use pf_win_display::monitor_devnode;
#[cfg(target_os = "windows")]
use pf_win_display::win_display::isolate_journal;
// Virtual-display orchestration lives in the `pf-vdisplay` subsystem crate (plan §W6); this shim
// keeps every existing `crate::vdisplay::*` path valid (serve/mgmt/native/capture consume the trait,
// registry, and manager through it). The DDC panel control + the KWin zkde protocol moved with it.
mod vdisplay {
    pub(crate) use pf_vdisplay::*;
}
// The zero-copy GPU plumbing lives in the `pf-zerocopy` leaf crate (plan §W6); this shim keeps
// every existing `crate::zerocopy::*` path valid for the host's remaining callers (session_plan).
#[cfg(target_os = "linux")]
mod zerocopy {
    pub(crate) use pf_zerocopy::*;
}

use anyhow::{bail, Context, Result};
use encode::Codec;
use spike::{Options, Source};
use std::path::PathBuf;

fn main() {
    // Before anything can reach an HTTPS call (the cover-art warmer, webhooks, the plugin-store
    // catalog, the update downloader all build default `ureq` agents).
    punktfunk_core::tls::install_default_provider();
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    // `service run` is launched by the SCM with no console — log to a file instead of stderr.
    #[cfg(target_os = "windows")]
    let service_run = {
        let a: Vec<String> = std::env::args().skip(1).take(2).collect();
        a.first().map(String::as_str) == Some("service")
            && a.get(1).map(String::as_str) == Some("run")
    };
    #[cfg(not(target_os = "windows"))]
    let service_run = false;

    if service_run {
        #[cfg(target_os = "windows")]
        service::init_file_logging(filter);
    } else {
        // Logs go to stderr so stdout stays machine-readable (`punktfunk-host openapi > spec.json`).
        // A second layer tees DEBUG-and-up into the in-memory ring served by GET /api/v1/logs —
        // deliberately not gated by RUST_LOG, so console-side debugging never needs a restart.
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::Layer;
        log_capture::install_global(
            tracing_subscriber::registry()
                .with(
                    log_capture::RingLayer
                        .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
                )
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_filter(filter),
                ),
        );
    }

    // Tee every panic into the log ring BEFORE the default hook: a panicking thread otherwise
    // prints only to stderr — absent from the web console's Logs tab (the ring) and gone entirely
    // when stderr is detached — so a field report reads "host died, zero errors in the logs".
    // The default hook still runs afterwards for the usual stderr message/abort behavior.
    //
    // 🛑 **The tee goes straight to the ring, NOT through `tracing`.** A panic hook that emits a
    // tracing event is a trap: `tracing_subscriber`'s registry is `sharded-slab`-backed and reads a
    // `thread_local!` with `LocalKey::with`, so emitting from a thread whose TLS is being torn down
    // panics — *inside the hook*. Rust treats a panic raised while the hook is running as
    // `MustAbort::PanicInHook` and then deliberately does not format the message ("perhaps that is
    // causing the panic"), so the log gets `panicked at <loc>:` followed by a BLANK line and
    // `thread panicked while processing panic. aborting.` — the cause erased at exactly the moment
    // it mattered. That is precisely what hid the 2026-08-18 teardown abort on .173 (four aborts,
    // zero diagnosis) until it was reproduced standalone.
    //
    // Everything below is TLS-free and cannot panic: `LogRing` is a `OnceLock` + `Mutex`, and
    // `thread::current().name()` / `Backtrace::force_capture()` were both verified safe during TLS
    // destruction. This does not make a TLS-destructor panic survivable — Rust aborts on those
    // regardless — but it does mean the message that names the cause always lands.
    let default_panic = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Manual payload downcast (`payload_as_str` needs Rust 1.91; workspace MSRV is 1.82).
        let payload = info
            .payload()
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| info.payload().downcast_ref::<String>().map(String::as_str))
            .unwrap_or("<non-string panic payload>");
        let location = info
            .location()
            .map(ToString::to_string)
            .unwrap_or_else(|| "<unknown>".into());
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        let backtrace = std::backtrace::Backtrace::force_capture();
        let ts_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        log_capture::ring().push_remote(
            "ERROR",
            "punktfunk_host::panic",
            &format!("PANIC: {payload} (thread={thread}, at {location})\n{backtrace}"),
            ts_ms,
        );
        default_panic(info);
    }));
    // Native crashes (an access violation inside a GPU runtime/driver DLL) are logged by a
    // last-resort SEH filter for the same reason — they otherwise kill the host with no trace.
    #[cfg(target_os = "windows")]
    crash::install();

    if let Err(e) = real_main() {
        tracing::error!("{e:#}");
        std::process::exit(1);
    }
}

/// A lightweight management/CLI subcommand — package/service/driver ops, spec/library dumps — as
/// opposed to a streaming/capture command. These never touch DXGI or run the host, so they skip the
/// startup banner and (on Windows) the GPU-preference hook, whose DPI-awareness probe otherwise
/// prints an alarming `SetProcessDpiAwarenessContext … "access denied"` WARN on a plain
/// `plugins add`. `service run` is the SCM-launched host itself, so it is explicitly NOT lightweight
/// (it must keep the hook — the hybrid-GPU ACCESS_LOST fix depends on it).
/// Resolve the effective monitor pin (env, else the stored policy) and aim absolute input at that
/// head — then report it. Called at startup (an operator sets the pin in a `host.env` and then has
/// no session to watch, so this is where a typo has to surface) and again whenever the console
/// writes the policy, so a picker change re-aims input without a host restart.
///
/// The anchor lives HERE rather than in the mirror backend for two reasons: pf-vdisplay must not
/// depend on pf-inject (its crate doc), and the anchor is a host-level pin anyway — the injector is
/// host-lifetime and shared by every concurrent session, so there is nothing per-session to track
/// (`design/per-monitor-portal-capture.md` §7.2).
#[cfg(target_os = "linux")]
pub(crate) fn refresh_capture_monitor_anchor(context: &str) {
    let Some(want) = pf_vdisplay::capture_monitor() else {
        // No pin (or the console just cleared one): stop aiming input at a monitor we are no
        // longer mirroring, or a later virtual-display session inherits a stale anchor.
        // Setting a pin says so in the log; clearing one is the same size of change to what the
        // host streams, so say that too — but only when there WAS one, or every unpinned host
        // logs this line at startup for no reason.
        if pf_inject::absolute_anchor().is_some() {
            tracing::info!(
                context,
                "capture monitor: cleared — sessions create a virtual display again and absolute \
                 input is no longer anchored"
            );
        }
        pf_inject::set_absolute_anchor(None);
        return;
    };
    match pf_vdisplay::detect().and_then(pf_vdisplay::monitors::list) {
        Ok(ms) => match pf_vdisplay::monitors::resolve(&ms, &want) {
            Ok(m) => {
                // Match the libei region by the head's ORIGIN: two monitors can share a size — and
                // a mirrored head's region is not the client's size at all — so size matching would
                // put the pointer on the wrong screen.
                pf_inject::set_absolute_anchor(Some(pf_inject::AbsoluteAnchor {
                    origin: Some((m.x, m.y)),
                    mapping_id: None,
                }));
                tracing::info!(
                    context,
                    connector = %m.connector,
                    description = %m.description,
                    mode = %m.mode_label(),
                    at = %format!("+{}+{}", m.x, m.y),
                    "capture monitor: sessions will mirror this monitor (no virtual display) and \
                     absolute input is anchored to it"
                );
            }
            // Left unanchored on purpose: a pin that resolves to nothing must not aim input at a
            // guess. The session's own `create` fails with the same reason.
            Err(e) => {
                pf_inject::set_absolute_anchor(None);
                tracing::warn!(
                    context,
                    error = %e,
                    "capture monitor: the pinned monitor is not on this host — sessions will fail \
                     to start until it is corrected or cleared"
                );
            }
        },
        Err(e) => {
            pf_inject::set_absolute_anchor(None);
            tracing::warn!(
                context,
                error = %format!("{e:#}"),
                monitor = %want,
                "capture monitor: a monitor is pinned but the monitors could not be enumerated"
            );
        }
    }
}

fn is_management_cli(args: &[String]) -> bool {
    match args.first().map(String::as_str) {
        Some("plugins")
        | Some("driver")
        | Some("web")
        | Some("tray")
        | Some("openapi")
        | Some("library")
        | Some("detect-conflicts")
        // Reads the compositor's output list and exits — none of the host-startup work applies,
        // and it must not re-run the pin's own startup report while printing that same list.
        | Some("list-monitors")
        | Some("-h")
        | Some("--help")
        | Some("help")
        | None => true,
        Some("service") => args.get(1).map(String::as_str) != Some("run"),
        _ => false,
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();

    // `--version` prints the build-stamped version (build.rs) to stdout and exits — no logging.
    if matches!(
        args.first().map(String::as_str),
        Some("--version") | Some("-V") | Some("version")
    ) {
        println!("punktfunk-host {}", env!("PUNKTFUNK_VERSION"));
        return Ok(());
    }

    // Lightweight CLI commands (e.g. `plugins add`) get none of the host-startup noise below.
    let management_cli = is_management_cli(&args);

    if !management_cli {
        tracing::info!(
            "punktfunk-host {} (punktfunk_core ABI v{})",
            env!("PUNKTFUNK_VERSION"),
            punktfunk_core::ABI_VERSION
        );
    }

    #[cfg(target_os = "linux")]
    if !management_cli {
        refresh_capture_monitor_anchor("startup");
    }

    // Wire pf-vdisplay's display-lifecycle events into the SSE event bus (the subsystem crate emits a
    // neutral DisplayEvent; the orchestrator owns the bus type — plan §W6). Set once, ignore re-set.
    let _ = pf_vdisplay::DISPLAY_EVENT_SINK.set(Box::new(|ev| match ev {
        pf_vdisplay::DisplayEvent::Created {
            backend,
            width,
            height,
            refresh_hz,
        } => events::emit(events::EventKind::DisplayCreated {
            backend,
            mode: events::mode_str(width, height, refresh_hz),
        }),
        pf_vdisplay::DisplayEvent::Released { count } => {
            events::emit(events::EventKind::DisplayReleased { count })
        }
    }));

    // Install the win32u GPU-preference hook (same technique as Apollo, reimplemented — no GPL source
    // copied) BEFORE anything touches DXGI (the virtual-display
    // render-adapter selection creates a DXGI factory during virtual-display setup, well before
    // capture). On a hybrid-GPU box this stops DXGI from reparenting the virtual output off the
    // capture GPU — the ACCESS_LOST churn fix. Idempotent (Once); harmless on non-hybrid boxes.
    // Skipped for lightweight CLI commands (`plugins`, `openapi`, …): they never touch DXGI, and the
    // hook's DPI-awareness probe prints a misleading "access denied" WARN that looks like a failure.
    #[cfg(target_os = "windows")]
    if !management_cli {
        crate::capture::dxgi::install_gpu_pref_hook();
    }

    // NVIDIA clock hygiene (Linux, host subcommands only): install the P2-cap driver profile. The
    // vendor clock *pin* (PUNKTFUNK_PIN_CLOCKS) is no longer held for the host lifetime — it is
    // armed per live client via `gpuclocks::session_pin()` on both streaming planes, so idle clocks
    // are left alone while nobody is connected. No-op off NVIDIA / on the tool subcommands.
    #[cfg(target_os = "linux")]
    if matches!(
        args.first().map(String::as_str),
        Some("serve") | Some("punktfunk1-host")
    ) {
        gpuclocks::on_host_start();
    }

    match args.first().map(String::as_str) {
        // The host: the native punktfunk/1 plane + management API by default (secure), and — with
        // --gamestream — the GameStream/Moonlight-compat planes too (opt-in; #5/#9 trusted-LAN caveat).
        Some("serve") => {
            let (mgmt_opts, native, gamestream) = parse_serve(&args[1..])?;
            // Claim the pf-vdisplay single-instance guard EAGERLY, before any client connects: the
            // claim is first-comer-wins, and a lazily-claiming service could lose its own machine's
            // driver to a stray second host started while the service sat idle.
            #[cfg(target_os = "windows")]
            vdisplay::manager::claim_instance_eagerly();
            // Crash recovery for the experimental `pnp_disable_monitors` axis: re-enable any
            // monitor devnodes a previous host disabled for an Exclusive session and never
            // restored (crash/kill/power loss) — before any new session touches the topology.
            #[cfg(target_os = "windows")]
            monitor_devnode::startup_recover();
            // The same recovery for the experimental `edid_lock` axis: unpin AMD connector
            // emulation a previous host locked and never unlocked — pinned emulation outlives
            // the process (and can outlive a reboot), so this is the only thing standing between
            // a crash and a permanently-emulated connector.
            #[cfg(target_os = "windows")]
            pf_win_display::adl_emul::startup_recover();
            // The same recovery for the DEFAULT Exclusive path: a previous host that died holding a
            // CCD isolate left the operator's panels deactivated with nothing to put them back (the
            // restore snapshot was process memory). Runs AFTER the devnode leg so re-enabled
            // monitors are present again and the EXTEND preset can actually light them.
            #[cfg(target_os = "windows")]
            isolate_journal::startup_recover();
            gamestream::serve(mgmt_opts, native, gamestream)
        }
        // Report other Moonlight-compatible hosts (Sunshine/Apollo/…) installed or running on this
        // machine — side-by-side use is unsupported. Exit 1 if any are found (so the installers and
        // support scripts can gate on it), 0 if clean. The host also runs this at `serve` startup.
        Some("detect-conflicts") => {
            let found = detect::scan();
            if found.is_empty() {
                println!("No conflicting game-streaming host detected.");
                return Ok(());
            }
            print!("{}", detect::render_report(&found));
            // Exit 1 ONLY for a host that runs or will start on its own. The installers and support
            // scripts gate on this code, and a dormant leftover used to abort them — a `winget
            // install` failed in the field on a box whose Sunshine was merely present (see the
            // module docs + `punktfunk-host.iss`). Dormant findings print, then exit 0.
            if detect::any_active(&found) {
                std::process::exit(1);
            }
            Ok(())
        }
        // Install and run host plugins: `plugins add playnite`, `plugins enable`, … Package ops are
        // forwarded to the bun runner; enable/disable/status drive the systemd unit (Linux) or the
        // PunktfunkScripting scheduled task (Windows). See plugins.rs.
        Some("plugins") => plugins::main(&args[1..]),
        // Print the management API's OpenAPI document (for client codegen).
        Some("openapi") => {
            print!("{}", mgmt::openapi_json());
            Ok(())
        }
        // Dump the resolved game library (installed stores + custom entries) as JSON — the same
        // payload `GET /api/v1/library` serves. A diagnostic for "does the host see my games?".
        Some("library") => {
            println!("{}", serde_json::to_string_pretty(&library::all_games())?);
            Ok(())
        }
        // Standalone input-injection smoke test (no client needed): open the session's input
        // backend and inject a scripted mouse/keyboard pattern. Watch a focused app / `wev`.
        Some("input-test") => devtest::input_test(),
        // Standalone stylus smoke test (no client needed): create the "Punktfunk Pen" virtual
        // tablet and draw a pressure-ramped stroke through the real tracker→uinput chain.
        // Watch in Krita/GIMP (pressure brush) or `libinput debug-events`.
        #[cfg(target_os = "linux")]
        Some("pen-test") => devtest::pen_test(),
        // Zero-copy FFI/GPU probe: init the EGL importer + CUDA context (no capture needed).
        #[cfg(target_os = "linux")]
        Some("zerocopy-probe") => zerocopy::probe(),
        // Hidden: the isolated GPU-import worker the capture path spawns from a pinned fd to its
        // own executable image (design/zerocopy-worker-isolation.md) — never run by hand; --fd
        // names the inherited socketpair end.
        #[cfg(target_os = "linux")]
        Some("zerocopy-worker") => zerocopy::worker::run_from_args(&args[1..]),
        // Hidden: the splash client every bare gamescope spawn backgrounds beside its nested app,
        // so a fresh headless gamescope composites (and its PipeWire node delivers frames) from
        // the first second — never run by hand; it needs a gamescope session's DISPLAY.
        #[cfg(target_os = "linux")]
        Some("gamescope-splash") => vdisplay::gamescope_splash_client(),
        // NV12 colour self-test (no display/capture needed): convert a known RGBA pattern to NV12
        // on the GPU and compare against a BT.709 limited-range reference. Validates the Tier 2A
        // `PUNKTFUNK_NV12` convert is colour-correct. Prints PASS/FAIL + max Y/U/V error.
        #[cfg(target_os = "linux")]
        Some("nv12-selftest") => zerocopy::nv12_selftest(),
        // HDR P010 colour self-test (Windows; no display/capture needed): upload a known scRGB FP16
        // pattern, run the `HdrP010Converter` shader → P010 on the GPU, read the Y/UV planes back, and
        // compare against an f64 BT.2020-PQ limited-range reference. Validates the
        // `PUNKTFUNK_HDR_SHADER_P010` colour math without green-screening a live HDR stream. Prints
        // PASS/FAIL + max Y/Cb/Cr error.
        #[cfg(target_os = "windows")]
        Some("hdr-p010-selftest") => {
            // Optional args: a `WxH` size (default 64x64 — pass the real capture size: heights
            // like 1080 are NOT 16-aligned and exercise a different driver path) and a GPU
            // vendor (`intel`|`nvidia`|`amd` — dual-GPU boxes otherwise test the default
            // adapter, which may not be the one that encodes).
            let mut size = (64u32, 64u32);
            let mut vendor = None;
            // `args` starts AT the subcommand (main builds it with `env::args().skip(1)`), so the
            // optional arguments begin at index 1 — cf. `args.get(1)` in the `service` arm. This
            // read `skip(2)` and so silently swallowed the first optional argument: the documented
            // `hdr-p010-selftest 1920x1080 nvidia` picked up the vendor but ran at the 64x64
            // DEFAULT, and a size-only invocation parsed nothing at all and still printed PASS.
            // The size is the whole point of the flag — 1080 is not 16-aligned and takes a
            // different driver path — so the self-test was passing on the one geometry that
            // exercises the least.
            for a in args.iter().skip(1) {
                match a.as_str() {
                    "intel" => vendor = Some(0x8086),
                    "nvidia" => vendor = Some(0x10de),
                    "amd" => vendor = Some(0x1002),
                    s => {
                        let parsed = s
                            .split_once('x')
                            .and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)));
                        match parsed {
                            Some(wh) => size = wh,
                            None => anyhow::bail!(
                                "hdr-p010-selftest: unrecognized arg {s:?} (want WxH or intel|nvidia|amd)"
                            ),
                        }
                    }
                }
            }
            crate::capture::dxgi::hdr_p010_selftest_at(size.0, size.1, vendor)
        }
        // Linux HDR readiness probe: prints, for BOTH Linux HDR sources, whether they can deliver
        // 10-bit PQ right now — the monitor mirror (is a monitor in BT.2100 colour mode?) and the
        // gamescope virtual output (is the resolved gamescope our `pipewire-hdr` build, and is the
        // knob on?) — plus whether the NVENC/VAAPI backend probes Main10 for HEVC/AV1 and the
        // GameStream capability they combine into. The "why isn't my stream HDR?" diagnostic (no
        // display/session needed for the encoder half).
        #[cfg(target_os = "linux")]
        Some("hdr-probe") => {
            let monitor_hdr = pf_capture::gnome_hdr_monitor_active();
            let hevc10 = encode::can_encode_10bit(encode::Codec::H265);
            let av110 = encode::can_encode_10bit(encode::Codec::Av1);
            let gs_binary_hdr = pf_vdisplay::gamescope_hdr_available();
            let gs_knob = pf_host_config::config().gamescope_hdr;
            let compositor = vdisplay::detect().ok();
            println!("monitor in BT.2100 (HDR) colour mode: {monitor_hdr}");
            println!("gamescope offers 10-bit PQ capture:   {gs_binary_hdr}");
            println!("PUNKTFUNK_GAMESCOPE_HDR:              {gs_knob}");
            // The other half of what the patched gamescope buys, and the one with no on-glass
            // symptom of its own: when it is true the compositor paints the pointer into the
            // capture node and the host stops blending — which is what lets the session take the
            // zero-CSC encode source. When it is false the pointer is still streamed, just at the
            // cost of a full-frame pass. Printed because "cursor composited by" is otherwise
            // invisible until you compare two streams side by side.
            println!(
                "gamescope paints the cursor in-node:  {}",
                pf_vdisplay::gamescope_composites_cursor()
            );
            println!("encoder Main10 (HEVC): {hevc10}");
            println!("encoder 10-bit (AV1):  {av110}");
            println!(
                "native-plane HDR on the resolved compositor ({}): {}",
                compositor.map_or("none".to_string(), |c| format!("{c:?}")),
                crate::capture::capturer_supports_hdr_for(compositor)
            );
            println!(
                "GameStream HDR capable (PUNKTFUNK_10BIT + a capable source + encoder): {}",
                gamestream::host_hdr_capable()
            );
            Ok(())
        }
        // Compositor readiness probe: exit 0 iff the (detected or PUNKTFUNK_COMPOSITOR-forced)
        // compositor is up and able to create a virtual output *now*. A session-bringup
        // script polls this to gate on real readiness instead of a blind `sleep`.
        Some("probe-compositor") => {
            let compositor = vdisplay::detect()?;
            vdisplay::probe(compositor).with_context(|| format!("{compositor:?} not ready"))?;
            println!("{compositor:?} ready");
            Ok(())
        }
        // List the host's physical monitors — the connector names `PUNKTFUNK_CAPTURE_MONITOR`
        // takes. An operator configuring an unattended host has to learn those names from
        // somewhere, and "curl the management API before the host is configured" is not it.
        #[cfg(target_os = "linux")]
        Some("list-monitors") => {
            let compositor = vdisplay::detect()?;
            let monitors = vdisplay::monitors::list(compositor)
                .with_context(|| format!("enumerate monitors on {compositor:?}"))?;
            if monitors.is_empty() {
                println!("{compositor:?}: no monitors");
                return Ok(());
            }
            let pinned = vdisplay::capture_monitor();
            println!("{compositor:?}:");
            for m in &monitors {
                let mut tags = Vec::new();
                if m.primary {
                    tags.push("primary");
                }
                if !m.enabled {
                    tags.push("disabled");
                }
                if m.managed {
                    tags.push("punktfunk virtual display");
                }
                if pinned
                    .as_deref()
                    .is_some_and(|p| p.eq_ignore_ascii_case(&m.connector))
                {
                    tags.push("PINNED");
                }
                println!(
                    "  {:<12} {:>13} at +{},+{}  scale {}  {}{}",
                    m.connector,
                    m.mode_label(),
                    m.x,
                    m.y,
                    m.scale,
                    m.description,
                    if tags.is_empty() {
                        String::new()
                    } else {
                        format!("  [{}]", tags.join(", "))
                    }
                );
            }
            Ok(())
        }
        // Mirror a pinned physical monitor and pull frames from it — the per-monitor capture
        // on-glass gate, with no client involved.
        #[cfg(target_os = "linux")]
        Some("mirror-test") => devtest::mirror_test(&args),
        // Aim absolute input at a named monitor and report which libei region it landed in — the
        // on-glass gate for the input-region ladder, with no client involved.
        #[cfg(target_os = "linux")]
        Some("anchor-test") => devtest::anchor_test(&args),
        // Create a virtual DualSense via UHID and exercise it (validation, no streaming session).
        #[cfg(target_os = "linux")]
        Some("dualsense-test") => devtest::dualsense_test(&args),
        // Mint one pad-audio PipeWire sink and capture from it — the Linux 0xD1 source gate.
        #[cfg(target_os = "linux")]
        Some("pad-sink-test") => devtest::pad_sink_test(&args),
        // Attach the usbip DualSense (real USB device + its own UAC sound card) and capture off its
        // isochronous endpoint — the gate for the ContainerId / real-ALSA-card path.
        #[cfg(target_os = "linux")]
        Some("pad-usbip-test") => devtest::pad_usbip_test(&args),
        // Create a virtual Switch Pro Controller via UHID and exercise it (validation, no session).
        #[cfg(target_os = "linux")]
        Some("switchpro-test") => devtest::switchpro_test(&args),
        // Windows N4 SPIKE: hold a software-devnode HID Steam Deck and watch Steam Input promote it.
        #[cfg(target_os = "windows")]
        Some("deck-windows-spike") => devtest::deck_windows_spike(&args),
        // Windows: hold the pf-mouse virtual HID pointer and sweep the real cursor via HID reports
        // (validates the resident-mouse cursor-presence fix on-glass). `--seconds N`.
        #[cfg(target_os = "windows")]
        Some("vmouse-spike") => devtest::vmouse_spike(&args),
        // Windows: ask a throwaway pf_mouse devnode for its channel proof and report which HID
        // transport hidclass forwarded — the pad channel's v3 delivery gate, verified on glass.
        #[cfg(target_os = "windows")]
        Some("channel-proof-probe") => devtest::channel_proof_probe(&args),
        // Windows: create a virtual DualSense (or --ds4/--edge/--deck/--xbox) via the UMDF driver and
        // hold it, driving the real *WindowsManager end to end. `--index N`, `--seconds N`.
        #[cfg(target_os = "windows")]
        Some("dualsense-windows-test") => devtest::dualsense_windows_test(&args),
        // Windows: pad-audio endpoint provisioning (`ensure`/`status`) + the pnputil removal
        // escape hatch (`remove`). `--index N` selects the pad slot (default 0).
        #[cfg(target_os = "windows")]
        Some("pad-endpoint") => devtest::pad_endpoint(&args),
        // Windows: audio-substrate spikes (design/windows-audio-endpoints-and-vbcable.md §3) —
        // mint Steam-driver instances and measure render→capture / loopback end to end.
        #[cfg(target_os = "windows")]
        Some("audio-probe") => devtest::audio_probe(&args),
        // Capture→encode→file pipeline spike (dev tool).
        Some("spike") => spike::run(parse_spike(&args[1..])?),
        // Native punktfunk/1 host (QUIC control plane + UDP data plane).
        Some("punktfunk1-host") => {
            let get = |flag: &str| {
                args.iter()
                    .skip_while(|a| *a != flag)
                    .nth(1)
                    .map(String::as_str)
            };
            let source = match get("--source") {
                Some("virtual") => native::Punktfunk1Source::Virtual,
                _ => native::Punktfunk1Source::Synthetic,
            };
            // Fixed pairing PIN for test harnesses/CI (deterministic ceremony instead of scraping
            // the logged random PIN). An empty value would arm SPAKE2 with an empty password —
            // refuse it loudly, mirroring the --mgmt-token guard.
            let pairing_pin = match get("--pairing-pin") {
                Some(p) if p.trim().is_empty() => bail!("--pairing-pin must not be empty"),
                p => p.map(str::to_string),
            };
            // WireGuard gate mode: `--wg-key` + `--wg-peers` together. The gate owns the only
            // public UDP port; QUIC + the data plane go loopback-only and ride the tunnel, so
            // pairing (the tunnel authenticates peers) and mDNS (nothing to discover publicly)
            // are forced off and the data plane pins the fixed inner port.
            let wg = match (get("--wg-key"), get("--wg-peers")) {
                (None, None) => None,
                (Some(k), Some(p)) => Some(native::WgGate {
                    key_path: std::path::PathBuf::from(k),
                    peers_path: std::path::PathBuf::from(p),
                    listen: get("--wg-listen").map(|s| {
                        s.parse()
                            .unwrap_or_else(|_| panic!("bad --wg-listen address: {s}"))
                    }),
                }),
                _ => bail!("--wg-key and --wg-peers must be given together"),
            };
            native::run(native::Punktfunk1Options {
                port: get("--port").and_then(|s| s.parse().ok()).unwrap_or(9777),
                source,
                seconds: get("--seconds").and_then(|s| s.parse().ok()).unwrap_or(30),
                frames: get("--frames").and_then(|s| s.parse().ok()).unwrap_or(300),
                max_sessions: get("--max-sessions")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                max_concurrent: get("--max-concurrent")
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(native::DEFAULT_MAX_CONCURRENT),
                // Secure by default: REQUIRE PIN pairing (reject unpaired clients) unless
                // --allow-tofu opts into trust-on-first-use — the host then accepts unpaired
                // clients and advertises pair=optional. Pairing is always armed so a PIN is
                // available (logged at startup); `--require-pairing`/`--allow-pairing` are now
                // the default and accepted as no-ops for back-compat. WireGuard gate mode
                // instead authenticates at the tunnel, so both are forced off there.
                require_pairing: wg.is_none() && !args.iter().any(|a| a == "--allow-tofu"),
                allow_pairing: wg.is_none(),
                pairing_pin,
                paired_store: None,
                // Fixed data-plane port: bind it and stream direct (no hole-punch), removing the
                // ~2.5 s punch-timeout on a firewalled host. Default (absent) = a random port +
                // hole-punch. Also honors PUNKTFUNK_DATA_PORT. WireGuard gate mode pins the fixed
                // INNER port on loopback instead (hole-punch semantics kept — see handshake.rs).
                data_port: if wg.is_some() {
                    Some(native::WG_DATA_PORT)
                } else {
                    get("--data-port")
                        .map(str::to_string)
                        .or_else(|| std::env::var("PUNKTFUNK_DATA_PORT").ok())
                        .and_then(|s| s.parse().ok())
                },
                // Disconnect-detection latency (QUIC control-connection idle timeout): --idle-timeout-ms
                // overrides PUNKTFUNK_IDLE_TIMEOUT_MS; absent = the core default (8s).
                idle_timeout: get("--idle-timeout-ms")
                    .and_then(|s| s.trim().parse::<u64>().ok())
                    .filter(|&ms| ms > 0)
                    .map(std::time::Duration::from_millis)
                    .or_else(native::idle_timeout_from_env),
                mdns: wg.is_none()
                    && !args.iter().any(|a| a == "--no-mdns")
                    && discovery::mdns_enabled(),
                wg,
            })
        }
        // Windows service control: install/uninstall/start/stop/status + the SCM `run` entry point.
        // Replaces the ad-hoc launch chain — `service install` registers an auto-start SYSTEM service
        // that launches the host into the active interactive session.
        #[cfg(target_os = "windows")]
        Some("service") => service::main(&args[1..]),
        // Install-time work the Windows installer delegates to the exe instead of locale-parsed
        // PowerShell *files* (the ANSI-codepage parse-break root fix; see windows/install.rs).
        #[cfg(target_os = "windows")]
        Some("driver") => install::driver_main(&args[1..]),
        #[cfg(target_os = "windows")]
        Some("web") => install::web_main(&args[1..]),
        // The tray's only recovery path: it is a per-user GUI process whose HKLM Run value fires
        // solely at sign-in, so anything that kills one (an upgrade, a crash) otherwise left the
        // operator iconless until the next logon.
        #[cfg(target_os = "windows")]
        Some("tray") => tray::main(&args[1..]),
        Some("-h") | Some("--help") | Some("help") | None => {
            print_usage();
            Ok(())
        }
        // Unknown subcommand → usage. (No implicit default; a bare `punktfunk-host` with no
        // args hits the None arm above and prints help.)
        Some(other) => bail!("unknown command '{other}' (try --help)"),
    }
}

/// `serve` options. The **native punktfunk/1 plane + management API are the secure default and always
/// run**; `--gamestream` additionally enables the GameStream/Moonlight-compat planes (opt-in — they
/// carry the inherent on-path #5/#9 weaknesses, so only on a trusted LAN). Returns the mgmt options,
/// the native host config, and whether GameStream is enabled. Native pairing is **required by default**
/// (an open host any LAN device can stream from is insecure); `--open` turns it off.
fn parse_serve(args: &[String]) -> Result<(mgmt::Options, native::NativeServe, bool)> {
    let mut opts = mgmt::Options::default();
    let mut native_port: u16 = 9777; // the native plane always runs now

    // Fixed data-plane UDP port: `Some(p)` binds p and streams direct (no hole-punch, no ~2.5 s
    // punch-timeout on a firewalled host); `None` (default) = a random port + hole-punch. Env
    // default, `--data-port` overrides.
    let mut data_port: Option<u16> = std::env::var("PUNKTFUNK_DATA_PORT")
        .ok()
        .and_then(|s| s.parse().ok());
    let mut open = false;
    let mut gamestream = false;
    let mut no_mdns = false;
    // WireGuard gate mode (`--wg-key` + `--wg-peers` together; `--wg-listen` optional).
    let mut wg_key: Option<String> = None;
    let mut wg_peers: Option<String> = None;
    let mut wg_listen: Option<std::net::SocketAddr> = None;
    // Did the operator pin the mgmt bind themselves? If not, we LAN-expose the read surface below so
    // paired clients can browse the game library out of the box (the bearer admin surface stays
    // loopback-gated in `mgmt::require_auth` regardless of the bind).
    let mut mgmt_bind_explicit = false;
    // Same question for the native port: an explicit `--native-port` out-ranks
    // `PUNKTFUNK_NATIVE_PORT` from host.env, resolved after the loop.
    let mut native_port_explicit = false;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut next = || {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))
        };
        match arg {
            "--mgmt-bind" => {
                opts.bind = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --mgmt-bind (want IP:PORT)"))?;
                mgmt_bind_explicit = true;
            }
            "--mgmt-token" => {
                let token = next()?;
                // An empty token would satisfy the non-loopback "token required" guard
                // while authenticating nobody (or, worse, everybody) — refuse it loudly
                // rather than letting `--mgmt-token "$UNSET_VAR"` ship a dead credential.
                if token.trim().is_empty() {
                    bail!("--mgmt-token must not be empty");
                }
                opts.token = Some(token);
            }
            // The native plane is now the DEFAULT (always runs in `serve`); `--native` is kept as an
            // accepted no-op for back-compat / explicitness.
            "--native" => {}
            "--native-port" => {
                native_port = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --native-port (want a port number)"))?;
                native_port_explicit = true;
            }
            "--data-port" => {
                data_port = Some(
                    next()?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("bad --data-port (want a port number)"))?,
                )
            }
            // Opt into the GameStream/Moonlight-compat planes (off by default — they carry the
            // inherent on-path #5/#9 weaknesses; only for a trusted LAN).
            "--gamestream" | "--moonlight" => gamestream = true,
            // Disable mandatory native pairing — any device can connect (trusted single-user
            // setups only). The default REQUIRES pairing.
            "--open" => open = true,
            // Skip the mDNS adverts (native + GameStream) — multicast-dead environments
            // (bridged Docker, CI netns); clients connect via a manually-added host.
            "--no-mdns" => no_mdns = true,
            // WireGuard gate mode: the gate owns the ONLY public UDP port; QUIC + the data
            // plane go loopback-only and ride the tunnel (pairing/mDNS forced off downstream,
            // the tunnel authenticates peers).
            "--wg-key" => wg_key = Some(next()?),
            "--wg-peers" => wg_peers = Some(next()?),
            "--wg-listen" => {
                wg_listen = Some(
                    next()?
                        .parse()
                        .map_err(|_| anyhow::anyhow!("bad --wg-listen (want IP:PORT)"))?,
                )
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument '{other}' (try --help)"),
        }
        i += 1;
    }
    // WireGuard gate mode (`--wg-key` + `--wg-peers` together): one public UDP port total —
    // the gate owns it and relays authenticated tunnel traffic to the loopback QUIC endpoint +
    // data plane. Incompatible with --gamestream (those planes need their own public ports, so
    // combining them would silently break the one-public-port promise).
    let wg = match (wg_key, wg_peers) {
        (None, None) => None,
        (Some(k), Some(p)) => Some(native::WgGate {
            key_path: std::path::PathBuf::from(k),
            peers_path: std::path::PathBuf::from(p),
            listen: wg_listen,
        }),
        _ => bail!("--wg-key and --wg-peers must be given together"),
    };
    if wg.is_some() && (gamestream || pf_host_config::config().gamestream) {
        bail!(
            "--gamestream cannot be combined with --wg-key: WireGuard gate mode exposes a \
             single public UDP port, but the GameStream/Moonlight planes need several public \
             TCP/UDP ports"
        );
    }
    // The mgmt API is HTTPS + token-authenticated ALWAYS (even on loopback). Resolve the token:
    // the --mgmt-token flag (above) wins, else PUNKTFUNK_MGMT_TOKEN env, else the persisted
    // ~/.config/punktfunk/mgmt-token, else a freshly generated + persisted one — so a bare `serve`
    // Just Works with auth on, no operator step, and the bundled web console reads the same file.
    if opts.token.is_none() {
        opts.token = Some(crate::mgmt_token::load_or_generate()?);
    }
    // The scripting runner's scoped credential: minted + persisted (plugin-token) alongside the
    // admin token so a plugin's zero-config `connect()` picks it up — it authorizes the plugin
    // surface but not hook registration or pairing administration (mgmt::auth::plugin_may_access).
    //
    // Only when a runner is actually installed. It used to be minted unconditionally on every
    // `serve`, so a host with no plugins — the common case — still persisted a second
    // admin-adjacent credential to disk and kept a second authentication lane live for a
    // subsystem it does not run (2026-08-05 review L-21). Installing the runner later mints it on
    // the next start, and an existing plugin-token file is picked up unchanged, so nothing about
    // the plugin flow changes for a host that has one.
    if crate::plugins::runtime_status().installed {
        opts.plugin_token = Some(crate::mgmt_token::load_or_generate_plugin()?);
    }
    // Default the mgmt listener to ALL interfaces (not just loopback) so a paired native client can
    // fetch the game library over mTLS with no operator step — the whole point of "browse works by
    // default". This only LAN-exposes the read-only cert allowlist; the bearer-token admin surface
    // is confined to loopback peers in `mgmt::require_auth`, so binding wide adds no admin exposure.
    // An operator who pinned `--mgmt-bind` (e.g. `127.0.0.1:47990` to restore loopback-only) keeps it.
    //
    // Same two-source shape as `--gamestream` / `PUNKTFUNK_GAMESTREAM` below, and for the same
    // reason: the packaged units ship a fixed ExecStart, so `host.env` is the only route a package
    // user has to move this that an upgrade won't overwrite. CLI wins — it is the more explicit of
    // the two and the one a support instruction reaches for.
    if !mgmt_bind_explicit {
        opts.bind = match pf_host_config::config().mgmt_bind.as_deref() {
            Some(s) => s
                .parse()
                .map_err(|_| anyhow::anyhow!("bad PUNKTFUNK_MGMT_BIND '{s}' (want IP:PORT)"))?,
            // WG gate mode exposes exactly one public port; keep the mgmt console on loopback
            // (reachable over RDP / a port-forward) instead of LAN-exposing it.
            None if wg.is_some() => std::net::SocketAddr::from(([127, 0, 0, 1], mgmt::DEFAULT_PORT)),
            None => std::net::SocketAddr::from(([0, 0, 0, 0], mgmt::DEFAULT_PORT)),
        };
    }
    // Same two-source resolution as the mgmt bind above. A bad value is FATAL rather than ignored:
    // silently serving on 9777 while host.env says otherwise is the failure that reads as "I moved
    // the port and the client still can't reach me".
    if !native_port_explicit {
        if let Some(s) = pf_host_config::config().native_port.as_deref() {
            native_port = s
                .parse()
                .map_err(|_| anyhow::anyhow!("bad PUNKTFUNK_NATIVE_PORT '{s}' (want a port)"))?;
        }
    }
    // Publish the resolved port for the console, right here rather than inside `serve`: the
    // console's unit gates on `mgmt-token` (persisted a few lines above), so writing the endpoint
    // in the same function keeps the two files effectively simultaneous. A console that still wins
    // that race falls back to 47990 and its `Restart=always` retry picks the file up.
    mgmt::publish_endpoint(opts.bind);
    let native = native::NativeServe {
        port: native_port,
        require_pairing: !open,
        // Advertise the mgmt port over mDNS so clients learn where to browse the library (rather than
        // assuming the default). `opts.bind.port()` is the real port even if the operator moved it.
        mgmt_port: opts.bind.port(),
        data_port,
        mdns: !no_mdns && discovery::mdns_enabled(),
        wg,
    };
    // The Moonlight-compat planes are opt-in from EITHER source: the `--gamestream` CLI flag or
    // `PUNKTFUNK_GAMESTREAM` in host.env — the packaged systemd units ship a fixed native-only
    // ExecStart, so the env knob is how a package user opts in without editing the unit.
    let gamestream = gamestream || pf_host_config::config().gamestream;
    Ok((opts, native, gamestream))
}

fn parse_spike(args: &[String]) -> Result<Options> {
    let mut source = Source::Portal;
    let mut width = 1920u32;
    let mut height = 1080u32;
    let mut fps = 60u32;
    let mut seconds = 5u32;
    let mut codec = Codec::H265;
    let mut bitrate_mbps = 20u64;
    let mut out: Option<PathBuf> = None;
    let mut loopback = true;
    let mut wire_chunk: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        let mut next = || {
            i += 1;
            args.get(i)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("missing value for {arg}"))
        };
        match arg {
            "--source" => {
                source = match next()?.as_str() {
                    "synthetic" => Source::Synthetic,
                    "synthetic-nv12" => Source::SyntheticNv12,
                    "portal" => Source::Portal,
                    "kwin-virtual" => Source::KwinVirtual,
                    other => {
                        bail!(
                            "unknown --source '{other}' \
                             (synthetic|synthetic-nv12|portal|kwin-virtual)"
                        )
                    }
                }
            }
            "--width" => {
                width = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --width"))?
            }
            "--height" => {
                height = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --height"))?
            }
            "--fps" => fps = next()?.parse().map_err(|_| anyhow::anyhow!("bad --fps"))?,
            "--seconds" => {
                seconds = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --seconds"))?
            }
            "--codec" => {
                codec = match next()?.as_str() {
                    "h264" => Codec::H264,
                    "h265" | "hevc" => Codec::H265,
                    "av1" => Codec::Av1,
                    // The spike is the only way to drive a PyroWave capture→encode pass without
                    // a client, which is what the Linux-host PyroWave work measures against.
                    // Needs the `pyrowave` feature (default-on) and pairs with
                    // `PUNKTFUNK_ENCODER=pyrowave`, which is what puts the CAPTURE side on the
                    // raw-dmabuf passthrough.
                    "pyrowave" => Codec::PyroWave,
                    other => bail!("unknown --codec '{other}' (h264|h265|av1|pyrowave)"),
                }
            }
            "--bitrate" => {
                bitrate_mbps = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --bitrate (Mbps)"))?
            }
            "--out" => out = Some(PathBuf::from(next()?)),
            "--no-loopback" => loopback = false,
            "--wire-chunk" => {
                let v: usize = next()?
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad --wire-chunk (bytes)"))?;
                wire_chunk = (v > 0).then_some(v);
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => bail!("unknown argument '{other}' (try --help)"),
        }
        i += 1;
    }

    if fps == 0 || width == 0 || height == 0 || seconds == 0 {
        bail!("--fps/--width/--height/--seconds must be > 0");
    }

    let out = out.unwrap_or_else(|| {
        let ext = match codec {
            Codec::H264 => "h264",
            Codec::H265 => "h265",
            Codec::Av1 => "obu",
            // Raw concatenated PyroWave packets — a lab dump, not an FFmpeg-playable stream.
            Codec::PyroWave => "pyrowave",
        };
        PathBuf::from(format!("/tmp/punktfunk-spike.{ext}"))
    });

    Ok(Options {
        source,
        width,
        height,
        fps,
        seconds,
        codec,
        bitrate_bps: bitrate_mbps.saturating_mul(1_000_000),
        out,
        loopback,
        wire_chunk,
    })
}

fn print_usage() {
    eprintln!(
        "punktfunk-host — Linux streaming host

USAGE:
    punktfunk-host serve [OPTIONS]            native punktfunk/1 host + management REST API
                                              (secure default; add --gamestream for Moonlight compat)
    punktfunk-host plugins <CMD>              install/run host plugins (add, remove, list, enable,
                                              disable, status) — `plugins --help` for details
    punktfunk-host tray <CMD>                 status-tray lifecycle (start, stop, status) — Windows;
                                              `start` is how you get the icon back without a re-logon
    punktfunk-host openapi                    print the management API's OpenAPI document (codegen)
    punktfunk-host punktfunk1-host [OPTIONS]  native punktfunk/1 host (QUIC control + UDP data plane)
    punktfunk-host probe-compositor           exit 0 iff the compositor is up + ready (bringup gate)
    punktfunk-host list-monitors              list the host's physical monitors (Linux) — the
                                              connector names PUNKTFUNK_CAPTURE_MONITOR takes
    punktfunk-host spike [OPTIONS]            capture→encode→file pipeline spike (dev tool)

SERVE OPTIONS:
    --mgmt-bind <IP:PORT>        management API address (or PUNKTFUNK_MGMT_BIND in host.env, which
                                 this flag overrides). Default: 0.0.0.0:47990 — paired clients
                                 reach the read-only surface, incl. the game library, over mTLS;
                                 the bearer admin API stays loopback-only. Pin 127.0.0.1:47990 to
                                 bind loopback only. Move the PORT (e.g. 0.0.0.0:47991) to share a
                                 machine with Sunshine/Apollo/Vibeshine, whose web UI owns 47990 —
                                 clients follow via mDNS and the console via mgmt-endpoint
    --mgmt-token <TOKEN>         bearer token for the management API (or PUNKTFUNK_MGMT_TOKEN); the
                                 admin endpoints it guards are honored only from a loopback peer
                                 (the co-located web console), never over the LAN
    --gamestream  (--moonlight)  ALSO run the GameStream/Moonlight-compat planes (nvhttp pairing,
                                 RTSP, ENet control, _nvstream mDNS). OFF by default — they carry
                                 inherent on-path weaknesses (plain-HTTP pairing + legacy GCM nonce
                                 reuse, security-review #5/#9); enable only on a TRUSTED LAN.
                                 Also PUNKTFUNK_GAMESTREAM=1 in host.env (how a packaged install
                                 opts in — the shipped units run native-only)
    --native                     no-op (the native punktfunk/1 plane always runs in `serve` now)
    --native-port <PORT>         native QUIC port (or PUNKTFUNK_NATIVE_PORT in host.env, which
                                 this flag overrides). Default 9777. Clients follow via mDNS, and
                                 a manually-added host keeps whatever port it was added with
    --data-port <PORT>           pin the per-session video data plane to this fixed UDP port and
                                 stream direct (no hole-punch) — open exactly this port in a host
                                 firewall to avoid the ~2.5 s punch-timeout. Default (unset) or
                                 PUNKTFUNK_DATA_PORT: a random port + hole-punch (crosses NAT)
    --open                       disable mandatory native pairing (default: pairing REQUIRED —
                                 an open host any LAN device can stream from is insecure)
    --wg-key <FILE>              WireGuard gate mode: expose ONE public UDP port (the native port,
                                 default 9777); QUIC + the data plane bind loopback and ride the
                                 tunnel. Pairing and mDNS are forced OFF (the tunnel authenticates
                                 peers), --gamestream is refused, and the mgmt console binds
                                 loopback unless --mgmt-bind says otherwise. Requires --wg-peers.
                                 Generate keys with `pf-wgtunnel genkey`
    --wg-peers <FILE>            allowed client public keys, one base64 key per line
    --wg-listen <IP:PORT>        gate public listen address (default 0.0.0.0:<native-port>) — set
                                 when a router/NAT maps a different external port
    --no-mdns                    skip the mDNS adverts (native + GameStream) — for multicast-dead
                                 environments (bridged Docker, CI); clients connect via a manually
                                 added host. Also PUNKTFUNK_MDNS=0

PUNKTFUNK1-HOST OPTIONS:
    --port <N>                   QUIC listen port (default: 9777)
    --source <synthetic|virtual> test frames, or virtual display + NVENC (default: synthetic)
    --seconds <N>                per-session stream duration, virtual source (default: 30)
    --frames <N>                 per-session frame count, synthetic source (default: 300)
    --max-sessions <N>           exit after N sessions; 0 = serve forever (default: 0)
    --max-concurrent <N>         stream at most N sessions at once (NVENC bound); overflow waits
                                 in the accept queue; 0 = unlimited (default: 4)
    --data-port <PORT>           pin the video data plane to this fixed UDP port and stream direct
                                 (no hole-punch; open exactly this port to skip the ~2.5 s punch-
                                 timeout). Default or PUNKTFUNK_DATA_PORT: random port + hole-punch.
                                 A fixed port fits one session; concurrent ones fall back to random
    --allow-tofu                 also accept UNPAIRED clients (trust-on-first-use) and advertise
                                 pair=optional. Default: pairing REQUIRED — the host rejects
                                 unpaired clients and logs a 4-digit pairing PIN at startup;
                                 TOFU without pairing is insecure on a LAN
    --pairing-pin <PIN>          fixed pairing PIN instead of the random per-ceremony one — for
                                 test harnesses/CI (deterministic `probe --pair`); do not use on
                                 a real LAN (a guessable PIN defeats the ceremony's rate limit)
    --no-mdns                    skip the _punktfunk._udp mDNS advert (multicast-dead environments;
                                 clients use --connect HOST:PORT). Also PUNKTFUNK_MDNS=0
    --wg-key <FILE>              WireGuard gate mode: host x25519 private key (base64, from
                                 `pf-wgtunnel genkey`). Requires --wg-peers. The gate owns the ONLY
                                 public UDP port (--port); QUIC + the data plane bind loopback and
                                 ride inside the tunnel. Pairing and mDNS are forced off; the data
                                 plane pins inner port 9778
    --wg-peers <FILE>            allowed client public keys, one base64 key per line (# comments
                                 ok). Generate on each client with `pf-wgtunnel genkey`

SPIKE OPTIONS:
    --source <synthetic|portal|kwin-virtual>
                                 frame source (default: portal). 'kwin-virtual' creates a
                                 KWin virtual output at --width x --height and captures it
    --seconds <N>                capture duration in seconds (default: 5)
    --fps <N>                    target frame rate (default: 60)
    --codec <h264|h265|av1|pyrowave>
                                 encode codec (default: h265). 'pyrowave' also wants
                                 PUNKTFUNK_ENCODER=pyrowave so capture takes the passthrough
    --bitrate <MBPS>             target bitrate in Mbps (default: 20)
    --width <W> --height <H>     synthetic source size (default: 1920x1080)
    --out <PATH>                 raw Annex-B output (default: /tmp/punktfunk-spike.<ext>)
    --no-loopback                skip the punktfunk_core round-trip verification
    --wire-chunk <BYTES>         PyroWave datagram-aligned packetization at this shard payload
                                 (a real session passes its negotiated shard_payload, e.g. 1408).
                                 With PUNKTFUNK_PYROWAVE_STREAMED_AU=1 also armed, the AU is
                                 drained through poll_chunk and sealed as a STREAMED wire frame
                                 (VIDEO_CAP_STREAMED_AU), then byte-verified by the loopback
    -h, --help                   this help

NOTES:
    'portal' needs headless Sway + xdg-desktop-portal-wlr running in this session
    (see design/linux-setup.md). 'synthetic' needs no capture session and always runs.
    Encoded AUs are written to a playable file AND (unless --no-loopback) fed through a
    punktfunk_core host→client loopback that reassembles and byte-verifies each one.
    Both 'serve' and 'punktfunk1-host' advertise the native service over mDNS
    (_punktfunk._udp) for client auto-discovery — 'punktfunk-probe --discover' lists them."
    );
    #[cfg(target_os = "windows")]
    eprintln!(
        "\nWINDOWS SERVICE (end-user deployment — replaces a manual launch):\n\
        \x20   punktfunk-host service install    register an auto-start SYSTEM service + firewall rules\n\
        \x20   punktfunk-host service uninstall  remove the service + firewall rules\n\
        \x20   punktfunk-host service start|stop|restart|status\n\
        \x20   config: %ProgramData%\\punktfunk\\host.env\n\
        \nWINDOWS DIAGNOSTICS:\n\
        \x20   punktfunk-host hdr-p010-selftest  GPU colour check for the PUNKTFUNK_HDR_SHADER_P010 path\n\
        \x20                                     (scRGB FP16 -> P010 BT.2020 PQ shader vs an f64 reference)"
    );
}
