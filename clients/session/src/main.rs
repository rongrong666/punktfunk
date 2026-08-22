//! `punktfunk-session` — the Vulkan session binary (punktfunk-planning
//! `linux-client-rearchitecture.md`, Phase 1: the software-path presenter MVP, which IS
//! the power-user CLI build).
//!
//! One stream session per invocation: `--connect host[:port]` (+ `--fp HEX`,
//! `--launch id`, `--fullscreen`), exits when the session ends. Reads the same identity
//! / known-hosts / settings stores as the desktop shell on each OS — the GTK client
//! (`punktfunk-client`) on Linux, the WinUI client on Windows — so pairing on either side
//! makes the other connect silently. `--pair <PIN> --connect host` runs the ceremony here,
//! with no window and no toolkit, for machines that have only a shell.
//!
//! Stdout is the machine interface (the shell↔session contract): `{"ready":true}` after
//! the first presented frame, `stats:` lines per 1 s window, one `{"error": …}` /
//! `{"ended": …}` JSON line on the way out. Logs go to stderr. Exit codes: 0 clean end,
//! 2 connect failed, 3 trust rejected / pairing required, 4 presenter init failed.
// `deny`, not `forbid`: edition 2024 makes the std process-environment mutators unsafe
// (WP20 — the env-mutation class made visible; named-API mentions here would count against
// the unsafe-hygiene gate C baseline, which tracks this file's real call sites), and this
// bin's three single-threaded-startup env writes carry documented SAFETY comments under
// localized `#[allow(unsafe_code)]` (the pf-update idiom). A `forbid` cannot be overridden
// at those sites and refuses the file.
#![deny(unsafe_code)]

#[cfg(all(any(target_os = "linux", windows), feature = "ui"))]
mod console;
mod ring_layer;

/// Loopback ports the in-process WireGuard relay listens on in WG mode (the session then
/// dials these instead of the real host). The spawner picks a free pair per session (so a
/// client can hold SEVERAL WG streams at once — the screen-wall case) and hands them over
/// with `--wg-relay-listen QUIC:DATA`; these constants are just the default first pair.
/// The TARGET ports written into tunnel packets stay 9777/9778 regardless: those are the
/// host-side service ports the gate dispatches on, not anything local.
const WG_LOCAL_QUIC_PORT: u16 = 9777;
const WG_LOCAL_DATA_PORT: u16 = 9778;

/// The session control socket: a line-per-connection unix socket other same-user
/// processes use to poke the RUNNING stream — today two verbs, `guide` and `qam`, which
/// press the HOST's system buttons (the Decky panel's "Steam menu / Quick access on the
/// host" buttons; see `GamepadService::tap_guide`). Plain text, no JSON: `<verb>\n` in,
/// `ok\n` / `err\n` back.
///
/// The path is `$XDG_RUNTIME_DIR/punktfunk-session-ctl.sock` — inside the flatpak app
/// runtime dir (`…/app/$FLATPAK_ID/`) when sandboxed, the ONE runtime path a flatpak and
/// the host see identically, which is what lets the Decky backend (outside the sandbox)
/// reach a flatpak-run session.
#[cfg(all(unix, any(target_os = "linux", windows)))]
mod ctl_socket {
    use pf_client_core::gamepad::GamepadService;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn path() -> Option<PathBuf> {
        let mut p = PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?);
        if let Ok(id) = std::env::var("FLATPAK_ID") {
            p.push("app");
            p.push(id);
        }
        Some(p.join("punktfunk-session-ctl.sock"))
    }

    /// Bind + serve on a background thread, once per process (later calls no-op). Any
    /// failure just logs at debug — the socket is a convenience surface, never worth
    /// failing a stream over.
    pub(crate) fn spawn(gamepad: GamepadService) {
        static ONCE: std::sync::Once = std::sync::Once::new();
        ONCE.call_once(move || {
            let Some(path) = path() else { return };
            // A previous session's socket file refuses the bind — it's ours to replace.
            let _ = std::fs::remove_file(&path);
            let listener = match UnixListener::bind(&path) {
                Ok(l) => l,
                Err(e) => {
                    tracing::debug!(error = %e, path = %path.display(), "session ctl socket unavailable");
                    return;
                }
            };
            let spawned = std::thread::Builder::new()
                .name("pf-session-ctl".into())
                .spawn(move || {
                    for stream in listener.incoming() {
                        let Ok(mut s) = stream else { continue };
                        let mut line = String::new();
                        if BufReader::new(&s).read_line(&mut line).is_err() {
                            continue;
                        }
                        let ok = match line.trim() {
                            "guide" => {
                                gamepad.tap_guide();
                                true
                            }
                            "qam" => {
                                gamepad.tap_qam();
                                true
                            }
                            _ => false,
                        };
                        let _ = s.write_all(if ok { b"ok\n" } else { b"err\n" });
                    }
                });
            if let Err(e) = spawned {
                tracing::debug!(error = %e, "session ctl thread failed to start");
            }
        });
    }
}

#[cfg(any(target_os = "linux", windows))]
mod session_main {
    use crate::{WG_LOCAL_DATA_PORT, WG_LOCAL_QUIC_PORT};
    use pf_client_core::gamepad::GamepadService;
    use pf_client_core::session::SessionParams;
    use pf_client_core::trust;
    use punktfunk_core::config::{CompositorPref, GamepadPref, Mode};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::Duration;

    pub const EXIT_CONNECT_FAILED: u8 = 2;
    pub const EXIT_TRUST_REJECTED: u8 = 3;
    pub const EXIT_PRESENTER_FAILED: u8 = 4;

    /// The value following `flag` in argv, if present (`--flag value`).
    pub(crate) fn arg_value(flag: &str) -> Option<String> {
        std::env::args()
            .skip_while(|a| a != flag)
            .nth(1)
            .filter(|v| !v.starts_with("--"))
    }

    pub(crate) fn arg_flag(flag: &str) -> bool {
        std::env::args().any(|a| a == flag)
    }

    /// The stats-overlay tier a session starts on: the resolved setting, except that
    /// `--stats` (tooling/debug runs) forces the overlay VISIBLE without demoting an
    /// explicitly chosen richer tier.
    ///
    /// One helper because three callers need the identical rule — both run modes' presenter
    /// options and the per-launch [`session_params`] — and a fourth reading of it would be
    /// the bug this is here to prevent.
    pub(crate) fn stats_tier(settings: &trust::Settings) -> trust::StatsVerbosity {
        stats_tier_with(settings.stats_verbosity(), arg_flag("--stats"))
    }

    /// [`stats_tier`]'s rule, with argv lifted out so it is testable.
    pub(crate) fn stats_tier_with(
        chosen: trust::StatsVerbosity,
        stats_flag: bool,
    ) -> trust::StatsVerbosity {
        match chosen {
            trust::StatsVerbosity::Off if stats_flag => trust::StatsVerbosity::Normal,
            v => v,
        }
    }

    /// Running under Gaming Mode (a Deck, or any gamescope session): the environment
    /// where the local Steam UI owns the physical Steam/QAM buttons — the system-button
    /// "auto" policy keys off this.
    pub(crate) fn gaming_mode() -> bool {
        std::env::var_os("SteamDeck").is_some()
            || std::env::var_os("GAMESCOPE_WAYLAND_DISPLAY").is_some()
    }

    /// Run fullscreen: `--fullscreen`, or the Deck/gamescope env as a fallback so a
    /// manual launch under Gaming Mode does the right thing too. (Browse-mode only —
    /// gated with `mod browse`, its one caller.)
    #[cfg(feature = "ui")]
    pub(crate) fn fullscreen_mode() -> bool {
        arg_flag("--fullscreen") || gaming_mode()
    }

    /// `--window-pos X,Y` → the window's top-left in desktop coordinates (a spawning
    /// shell passes its own position so the session opens on the same monitor); absent or
    /// unparsable = centered on the primary display.
    pub(crate) fn window_pos() -> Option<(i32, i32)> {
        let v = arg_value("--window-pos")?;
        let (x, y) = v.split_once(',')?;
        Some((x.trim().parse().ok()?, y.trim().parse().ok()?))
    }

    /// `--pair <PIN> --connect host[:port]` — the SPAKE2 PIN ceremony with no window, no GTK
    /// and no console UI, so a machine that has only SSH can be enrolled: an embedded/kiosk
    /// client, a headless box, an image being provisioned. Writes the verified host into the
    /// same known-hosts store `--connect` reads, so pairing here is exactly what makes the
    /// later stream connect silently.
    ///
    /// Deliberately identical in shape and output to `punktfunk-client --pair` (which stays
    /// the desktop route) — the difference is only that this binary carries no toolkit, so it
    /// is the one a minimal image installs. Present in the `--no-default-features` build too:
    /// enrolment must not be the reason an embedded image has to pull in Skia.
    fn headless_pair(pin: &str) -> u8 {
        let Some(target) = arg_value("--connect") else {
            eprintln!("--pair requires --connect host[:port]");
            return EXIT_CONNECT_FAILED;
        };
        let (addr, port) = parse_host_port(&target);
        // The label the HOST files this client under. A headless box has nobody to ask, so
        // the hostname is the only name that will mean anything in the paired-devices list.
        let name = arg_value("--name").unwrap_or_else(trust::device_name);

        let identity = match trust::load_or_create_identity() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("client identity: {e:#}");
                return EXIT_CONNECT_FAILED;
            }
        };
        match trust::pair_with_host(&addr, port, &identity, pin, &name) {
            Ok(fp) => {
                let fp_hex = trust::hex(&fp);
                trust::persist_host(
                    &arg_value("--host-label").unwrap_or_else(|| addr.clone()),
                    &addr,
                    port,
                    &fp_hex,
                    true,
                );
                trust::forget_placeholder(&addr, port);
                println!("paired {addr}:{port} fp={fp_hex}");
                0
            }
            Err(e) => {
                eprintln!("pairing failed: {} ({e:?})", trust::pair_error_message(&e));
                EXIT_TRUST_REJECTED
            }
        }
    }

    /// `host[:port]`, port defaulting to the native 9777.
    pub(crate) fn parse_host_port(target: &str) -> (String, u16) {
        match target.rsplit_once(':') {
            Some((a, p)) => match p.parse() {
                Ok(port) => (a.to_string(), port),
                Err(_) => {
                    eprintln!("unparsable port in '{target}', using default 9777");
                    (a.to_string(), 9777)
                }
            },
            None => (target.to_string(), 9777),
        }
    }

    /// `--profile <id|name>` — the settings profile this one session runs with, overriding the
    /// host's own binding for this launch only (never rebinding it): the shells' "Connect
    /// with ▸ X" and a `punktfunk://…&profile=` link both land here. Absent = honor the host's
    /// binding; `--profile ""` (or a bare `--profile`) forces the global defaults, which is
    /// how "Connect with ▸ Default settings" reaches a bound host.
    fn profile_arg() -> Option<String> {
        arg_flag("--profile").then(|| arg_value("--profile").unwrap_or_default())
    }

    /// The connect budget: 15 s normally; `--connect-timeout SECS` overrides — the
    /// shell's request-access flow passes ~185 s because the host PARKS the connection
    /// until the operator clicks Approve.
    pub(crate) fn connect_timeout() -> Duration {
        Duration::from_secs(
            arg_value("--connect-timeout")
                .and_then(|v| v.parse().ok())
                .unwrap_or(15),
        )
    }

    /// One session's pump parameters from the EFFECTIVE settings — shared by `--connect`
    /// and every `--browse` launch. Explicit settings, `0` fields resolved to the
    /// window's display (the GTK client reads the monitor under its window — same
    /// contract).
    ///
    /// `settings` is what [`trust::effective_settings`] returned, never a raw
    /// `Settings::load()`: both callers resolve the host's profile first, so the two
    /// construction sites cannot drift (they historically did — touching one and not the
    /// other is a Windows-only build break). `profile` is that profile's name, for the
    /// stats overlay's first line.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn session_params(
        settings: &trust::Settings,
        profile: Option<String>,
        clipboard_override: Option<bool>,
        addr: String,
        port: u16,
        pin: Option<[u8; 32]>,
        // WG mode dials the loopback relay but must still look host records up by the REAL
        // address (clipboard opt-in below). `None` = addr/port are the real target.
        lookup: Option<(String, u16)>,
        identity: (String, String),
        launch: Option<String>,
        gamepad: &GamepadService,
        native: Mode,
        force_software: Arc<AtomicBool>,
        vulkan: Option<pf_client_core::video::VulkanDecodeDevice>,
    ) -> SessionParams {
        // Per-host clipboard opt-in (design/clipboard-and-file-transfer.md §5.3). In spec
        // mode the spawner already resolved it; otherwise this looks it up itself, which is
        // the last store read the compat path still owes. `addr` is moved into the struct
        // below, so read it first.
        let clipboard = clipboard_override.unwrap_or_else(|| {
            // The record this address RESOLVES to, not "any record mentioning it": a retired
            // duplicate must never be the one that hands a host the clipboard.
            let (laddr, lport) = lookup.unwrap_or_else(|| (addr.clone(), port));
            trust::KnownHosts::load()
                .find_by_addr(&laddr, lport)
                .is_some_and(|h| h.clipboard_sync)
        });
        // Re-apply the shell-persisted forwarded-controller pin (stable `vid:pid:name`
        // key) to OUR gamepad service — the shells' in-process services can't reach this
        // process. Applied per params-build (idempotent; browse re-launches included) so
        // it lands before the session attaches. Empty = automatic (most recent).
        if !settings.forward_pad.is_empty() {
            gamepad.set_pinned(Some(settings.forward_pad.clone()));
        }
        // Whether to forward controllers AT ALL (off = the pad reaches the host by some other
        // route — VirtualHere and friends). Set unconditionally, not only when off: browse mode
        // reuses one service across launches, so a stream that follows one with it off must put
        // it back. It goes on before the attach below, so a non-forwarding session never opens
        // — never grabs — the device.
        gamepad.set_forwarding(settings.gamepad_forwarding);
        // System-button routing: whether raw guide/QAM presses ride the wire, and whether
        // hold-Select arms as the alternate guide route. Auto keys off Gaming Mode — the
        // local Steam UI reacts to the same physical buttons there no matter what, so
        // forwarding raw opens BOTH overlays, the local one on top of the stream. Set
        // unconditionally for the same browse-mode-reuse reason as the line above.
        let game_mode = gaming_mode();
        gamepad.set_system_buttons(
            settings.system_buttons_forward(game_mode),
            settings.guide_gesture_enabled(game_mode),
        );
        // The control socket (guide/QAM injection — the Decky panel's host buttons).
        // Spawned at first params-build so it exists for --connect AND console launches.
        #[cfg(unix)]
        crate::ctl_socket::spawn(gamepad.clone());
        // Pad-audio prefs to OUR gamepad service (same reasoning as the pin above): tier-A
        // slots declare their render caps at open time, which happens on attach — after this.
        gamepad.set_pad_audio_prefs(
            settings.pad_haptics,
            pf_client_core::pad_audio::speaker_active(&settings.pad_speaker),
        );
        let mode = Mode {
            width: if settings.width == 0 {
                native.width
            } else {
                settings.width
            },
            height: if settings.height == 0 {
                native.height
            } else {
                settings.height
            },
            refresh_hz: if settings.refresh_hz == 0 {
                native.refresh_hz.max(30)
            } else {
                settings.refresh_hz
            },
        };
        // Render scale: multiply the resolved mode (even + codec-clamped) so the host renders
        // larger/smaller and the presenter resamples to the window. 1.0 = Native. Applied after the
        // Native/explicit resolution so it composes uniformly with both.
        let (sw, sh) = punktfunk_core::render_scale::apply(
            mode.width,
            mode.height,
            settings.render_scale,
            punktfunk_core::render_scale::max_dimension(&settings.codec),
        );
        let mode = Mode {
            width: sw,
            height: sh,
            ..mode
        };
        // Before the struct literal — `vulkan` moves into it below.
        let phase_lock = vulkan.as_ref().is_some_and(|v| v.present_timing);
        // …and the 4:4:4 promise, for the same reason: asked while the device bundle is
        // still borrowable. `&&` short-circuits, so a box that never enabled Full chroma
        // pays no capability queries for a feature it does not want.
        let want_444 = settings.enable_444
            && pf_client_core::video::hevc_444_hardware_decodable(vulkan.as_ref());
        if settings.enable_444 && !want_444 {
            // Loud, because the user turned a switch on and is not getting it. The
            // alternative is what this replaces: the host grants 4:4:4, the decode ladder
            // has no rung that can take it, and the session drops HEVC entirely.
            tracing::warn!(
                "Full chroma (4:4:4) requested but this device has no 4:4:4 HEVC decode — \
                 asking for 4:2:0 instead. Advertising it would cost the whole codec: 4:4:4 \
                 is granted on HEVC only, and there is no software HEVC decoder to fall back \
                 to (PyroWave carries 4:4:4 on any GPU, if the link can take it)."
            );
        }
        SessionParams {
            host: addr,
            port,
            mode,
            compositor: CompositorPref::from_name(&settings.compositor)
                .unwrap_or(CompositorPref::Auto),
            gamepad: {
                // The setting AS CHOSEN goes to the pad service too, not just the Hello: the host
                // builds each virtual pad from that pad's arrival and only falls back to this
                // session default for a pad that never declares one, so an explicit choice that
                // stopped here would be undone the moment a controller connected.
                let chosen = GamepadPref::from_name(&settings.gamepad).unwrap_or(GamepadPref::Auto);
                gamepad.set_kind_override(chosen);
                match chosen {
                    GamepadPref::Auto => gamepad.auto_pref(),
                    explicit => explicit,
                }
            },
            bitrate_kbps: settings.bitrate_kbps,
            audio_channels: settings.audio_channels,
            // The lossless-audio opt-in, AS STORED — the pump is what filters it, because only it
            // knows whether this box's output device will open the rate and what the host
            // answered. `PUNKTFUNK_AUDIO_HIRES` still overrides it there (a headless box or a
            // Gaming-Mode kiosk has no settings UI), which is why nothing is resolved here.
            audio_format: settings.audio_format.clone(),
            preferred_codec: settings.preferred_codec(),
            // Nothing excluded on a fresh dial. Only the run loop's codec-fallback retry
            // sets this, and it does so on a CLONE of these params — a Settings-level
            // "never use HEVC" would be `preferred_codec`, not this.
            exclude_codecs: 0,
            // HDR off = don't advertise 10-bit/HDR at all; the host then never upgrades.
            // MULTI_SLICE is decoder truth for THIS embedder: every desktop decode stack
            // (Vulkan Video, D3D11VA, VAAPI, openh264/rav1d) handles AUs carrying several
            // slice NALs, so the host may keep its multi-slice low-latency default (§7 LN1).
            // The mobile/TV embedders must NOT copy this blindly — Amlogic MediaCodec wedges
            // on multi-slice AUs (see `VIDEO_CAP_MULTI_SLICE`), so they advertise per-decoder.
            // 4:4:4 is opt-in and off by default (Settings "Full chroma"): the bit says
            // "upgrade me if you can" — the host still gates on its own policy, its capturer,
            // HEVC, and a real GPU 4:4:4 encode probe, and answers the resolved chroma in the
            // Welcome BEFORE we build a decoder. It is now ALSO gated on this device being
            // able to decode 4:4:4 (`want_444`, computed above); the rule and its reasoning
            // live in `video::video_caps_for`, which is where they get tested.
            // The cost stays VISIBLE, not silent: the Detailed stats overlay prints the
            // resolved chroma ("4:4:4→4:2:0" when the host declined) and the decode path
            // frames actually took.
            video_caps: pf_client_core::video::video_caps_for(settings.hdr_enabled, want_444),
            // This panel's HDR colour volume → the host's virtual-display EDID, so host
            // apps tone-map to the real glass. Windows reads it from DXGI (the
            // `--window-pos` monitor; advanced-color outputs only) — gated on the HDR
            // setting, since with 10-bit/HDR unadvertised above the volume is noise. No
            // portable Wayland/X11 query exists yet, so Linux keeps the host's EDID
            // defaults; `PUNKTFUNK_CLIENT_PEAK_NITS` (read in the session pump) pins one
            // manually on either OS and wins over both.
            #[cfg(windows)]
            display_hdr: settings
                .hdr_enabled
                .then(|| pf_client_core::video_d3d11::display_hdr_volume(window_pos()))
                .flatten(),
            #[cfg(not(windows))]
            display_hdr: None,
            // The presenter renders the host cursor locally in desktop mouse mode (M2 cursor
            // channel); capture-mode sessions keep the composited cursor, so only advertise
            // when the session STARTS in desktop mode. The host gates further (Linux portal
            // compositors only).
            cursor_forward: settings.mouse_mode() == trust::MouseMode::Desktop,
            mic_enabled: settings.mic_enabled,
            echo_cancel: settings.echo_cancel,
            // Pad audio (0xD1): the DualSense haptics/speaker render settings. The gamepad
            // service learns the same prefs below so tier-A slots declare their render caps
            // at open; the session pump gates CLIENT_CAP_PAD_AUDIO + the renderer on these.
            pad_haptics: settings.pad_haptics,
            pad_speaker: settings.pad_speaker.clone(),
            clipboard,
            // The Settings preference (auto → VAAPI where it exists; the presenter
            // demotes to software on boxes whose Vulkan can't import the dmabufs).
            // PUNKTFUNK_DECODER still overrides inside the decoder for bisects.
            decoder: settings.decoder.clone(),
            launch,
            vulkan,
            pin,
            identity,
            connect_timeout: connect_timeout(),
            force_software,
            profile,
            // Presentation-tier, carried per launch rather than read once by the run loop:
            // the console streams many sessions through ONE loop, so this is the only way a
            // tier the user picked between streams (or one a host's profile carries) reaches
            // the overlay before the app is restarted. Single mode passes the same value its
            // presenter options already hold, so it changes nothing there.
            stats_verbosity: stats_tier(settings),
            // Phase-locked capture (design/phase-locked-capture.md, Apple/Android parity):
            // advertised only when the presenter has real on-glass latch stamps
            // (VK_KHR_present_wait) — without them there is no latch grid to report. The
            // grid itself is written by the presenter (run_session clones the Arc out of
            // these params) and folded into ~1 Hz PhaseReports by the session pump.
            phase_lock,
            latch_grid: std::sync::Arc::new(pf_client_core::session::LatchGrid::default()),
        }
    }

    /// The window's starting size under Match-window: the persisted last size, so the
    /// first connect's mode already matches the glass; `None` (policy off / never
    /// stored) = the 1280×720 default.
    pub(crate) fn window_size(settings: &trust::Settings) -> Option<(u32, u32)> {
        (settings.match_window && settings.last_window_w > 0 && settings.last_window_h > 0)
            .then_some((settings.last_window_w, settings.last_window_h))
    }

    /// The Match-window policy hook for the presenter loop
    /// (design/midstream-resolution-resize.md D1/D2): `Some(persist)` turns the
    /// debounced resize→`Reconfigure` machinery on; the callback stores each resize-end's
    /// logical window size (load-modify-save, like the console settings screen) so the
    /// next launch opens at it.
    /// The Match-window policy hook (design/midstream-resolution-resize.md D1/D2). The
    /// callback used to load-modify-save the shared settings file from inside the renderer —
    /// one of that file's five concurrent writers, for a value only the parent needs. It now
    /// REPORTS the size on stdout and the spawner persists it
    /// (design/client-architecture-split.md §5).
    ///
    /// `persist_locally` keeps a hand-run session remembering its own window: nobody is
    /// listening to stdout there, so the event alone would drop the value. A spawned session
    /// leaves the write to its parent, which is the whole point.
    pub(crate) fn match_window(
        settings: &trust::Settings,
        persist_locally: bool,
    ) -> Option<Box<dyn FnMut(u32, u32)>> {
        settings.match_window.then(|| {
            Box::new(move |w: u32, h: u32| {
                println!("{{\"window\":{{\"w\":{w},\"h\":{h}}}}}");
                if persist_locally {
                    pf_client_core::orchestrate::persist_window_size(w, h);
                }
            }) as Box<dyn FnMut(u32, u32)>
        })
    }

    /// One JSON status line on stdout (the shell parses these; strings hand-escaped via
    /// the minimal rules a reason string can need). `pub(crate)`: browse mode emits its
    /// failure through the same contract when spawned with `--json-status`.
    pub(crate) fn json_line(key: &str, msg: &str, trust_rejected: Option<bool>) {
        let escaped: String = msg
            .chars()
            .flat_map(|c| match c {
                '"' => vec!['\\', '"'],
                '\\' => vec!['\\', '\\'],
                '\n' => vec!['\\', 'n'],
                c if (c as u32) < 0x20 => vec![' '],
                c => vec![c],
            })
            .collect();
        match trust_rejected {
            Some(t) => println!("{{\"{key}\":\"{escaped}\",\"trust_rejected\":{t}}}"),
            None => println!("{{\"{key}\":\"{escaped}\"}}"),
        }
    }

    /// Steam Deck / RADV: Mesa gates Vulkan Video decode — the `VK_KHR_video_decode_*`
    /// extensions AND the decode-capable queue family — behind `RADV_PERFTEST=video_decode`.
    /// Without it the presenter's device advertises no decode queue, so `Decoder::new`'s
    /// `auto` path can't build the Vulkan decoder and the session silently falls back to
    /// VAAPI (whose separate-plane dmabuf import shows chroma fringing — green/yellow specks
    /// around the cursor — on VanGogh). We want the Vulkan path, so opt in here, before the
    /// RADV driver loads (the Vulkan instance is created later, inside `run_session`).
    ///
    /// RADV-only knob: ANV/NVIDIA/other drivers ignore `RADV_PERFTEST`, and a box where video
    /// decode is already the default just no-ops. Append rather than clobber so a user's own
    /// `RADV_PERFTEST` survives; `PUNKTFUNK_DECODER=native-vaapi` still overrides the decoder
    /// choice (the pre-M10 `vaapi` spelling reaches the same rung — it migrates, loudly).
    ///
    /// ⚠⚠ Called from the TOP of [`run`], ahead of the `--list-adapters` / `--probe-decode`
    /// early exits — not merely "before `run_session` creates the instance". Those flags
    /// create Vulkan instances of their own and RADV latches `RADV_PERFTEST` when its ICD
    /// initialises, so a call placed after them leaves the triage tool describing a device
    /// that cannot decode while the streaming path decodes on it.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)] // the two SAFETY-commented single-threaded-startup env writes below
    fn enable_radv_video_decode() {
        const TOKEN: &str = "video_decode";
        match std::env::var("RADV_PERFTEST") {
            Ok(v) if v.split(',').any(|t| t == TOKEN) => return,
            // SAFETY: called at the very top of `run()`, before this process creates any
            // thread — the Vulkan loader, SDL, and the session runtime all start later.
            Ok(v) if !v.is_empty() => unsafe {
                std::env::set_var("RADV_PERFTEST", format!("{v},{TOKEN}"))
            },
            // SAFETY: as above — single-threaded startup.
            _ => unsafe { std::env::set_var("RADV_PERFTEST", TOKEN) },
        }
        tracing::info!(
            radv_perftest = %std::env::var("RADV_PERFTEST").unwrap_or_default(),
            "opted into RADV Vulkan Video decode (Mesa gates it behind RADV_PERFTEST on the Deck)"
        );
    }

    /// The driver's own answers about video images, printed with nothing in front of
    /// them (`--probe-decode`).
    ///
    /// Passing the five conjuncts above only says Vulkan Video EXISTS on a device; this
    /// says whether the zero-copy pipeline can be BUILT on it — a different question
    /// with, on at least one shipping driver, a different answer. Verbatim on purpose:
    /// the Intel Arc refusal was twice diagnosed from punktfunk's own error text and
    /// twice the diagnosis was wrong, and what broke it open both times was reading what
    /// the driver actually said.
    fn print_video_formats(a: &pf_presenter::vk::AdapterDecode) {
        use pf_presenter::vk::probe::{describe_create_flags, describe_usage};
        for p in &a.formats {
            println!("     {} (wants {:?}):", p.profile, p.wanted);
            for u in &p.usages {
                let answer = match &u.formats {
                    Err(e) => format!("query failed: {e:?}"),
                    Ok(entries) if entries.is_empty() => "no formats offered".to_string(),
                    Ok(entries) => entries
                        .iter()
                        .map(|f| {
                            format!(
                                "{:?} usage={} create={} {:?} {:?}",
                                f.format,
                                describe_usage(f.image_usage),
                                describe_create_flags(f.image_create_flags),
                                f.image_type,
                                f.image_tiling,
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                };
                println!("       {:<24} {answer}", u.label);
                // The second opinion, printed only where it differs from the video
                // format query. Worded as "also asked" rather than "disagrees" on
                // purpose: measured on both vendors this call answers "creatable" for
                // combinations the video query rejects (NVIDIA included, for SAMPLED
                // alone), so it does not honour the profile list and a difference here
                // is NOT the driver contradicting itself. Printed anyway because the
                // question gets re-asked by everyone who reads a refusal.
                let listed = u
                    .wanted_entry(p.wanted)
                    .is_some_and(|f| f.image_usage.contains(u.usage));
                if listed != u.image_format_support.is_ok() {
                    let second = match &u.image_format_support {
                        Ok(()) => "creatable".to_string(),
                        Err(e) => format!("{e:?}"),
                    };
                    println!(
                        "       {:<24} (also asked: \
                         vkGetPhysicalDeviceImageFormatProperties2 says {second} — that \
                         call does not honour the profile list; not authority)",
                        ""
                    );
                }
            }
        }
    }

    pub fn run() -> u8 {
        // Logs to STDERR — stdout is the machine interface (ready/stats/error lines) — plus
        // the in-process ring (`pf_client_core::logring`, DEBUG+ regardless of RUST_LOG) that
        // "Send logs to host" uploads. The env filter scopes the STDERR layer only: the ring
        // exists precisely for the diagnostics nobody enabled before the bug happened.
        {
            use tracing_subscriber::layer::SubscriberExt;
            use tracing_subscriber::util::SubscriberInitExt;
            use tracing_subscriber::Layer;
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::fmt::layer()
                        .with_writer(std::io::stderr)
                        .with_filter(
                            tracing_subscriber::EnvFilter::try_from_default_env()
                                .unwrap_or_else(|_| "info".into()),
                        ),
                )
                .with(
                    crate::ring_layer::RingLayer
                        .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
                )
                .init();
        }

        // Before ANY Vulkan call — and that includes the two probe flags below, which is the
        // whole reason this sits at the top of `run` instead of beside the session setup it
        // was written for. Make RADV expose its video-decode queue + extensions so the
        // decoder's `auto` path prefers Vulkan Video over VAAPI (Steam Deck, and any gated
        // RADV). Windows drivers (NVIDIA/AMD Adrenalin) expose theirs unconditionally.
        //
        // ⚠⚠ It USED to sit after the `--list-adapters` / `--probe-decode` / `--list-audio` /
        // `--pair` early exits, which meant the triage tool answered a DIFFERENT question from
        // the one the streaming path asks. Measured on a Steam Deck (2026-08-08, canary
        // `e22af40f`), same binary, back to back: bare `--probe-decode` printed `vulkan video
        // decode: no`, `driver decode ops: none (0x0)`, `no queue family advertises
        // VIDEO_DECODE`; the same call with `RADV_PERFTEST=video_decode` in the environment
        // printed `YES` and `H.264, H.265, AV1, VP9`. The tool exists to be believed, so any
        // Deck triage that consulted it reached the opposite of the truth.
        #[cfg(target_os = "linux")]
        enable_radv_video_decode();

        // `--list-adapters`: print the Vulkan physical devices' marketing names (one per
        // line, discrete first) for the desktop shells' GPU picker, then exit.
        if arg_flag("--list-adapters") {
            return match pf_presenter::vk::list_adapters() {
                Ok(names) => {
                    for n in names {
                        println!("{n}");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("list-adapters: {e:#}");
                    EXIT_PRESENTER_FAILED
                }
            };
        }

        // `--probe-decode`: per-adapter Vulkan Video decode capability, then exit. Human
        // output on purpose — this is a triage tool, not a picker source, which is also
        // why it is a separate flag: `--list-adapters` is parsed line-by-line by the
        // desktop shells' GPU picker and must keep printing bare names.
        if arg_flag("--probe-decode") {
            return match pf_presenter::vk::probe_decode() {
                Ok(adapters) => {
                    if adapters.is_empty() {
                        println!("no Vulkan physical devices");
                    }
                    for (i, a) in adapters.iter().enumerate() {
                        // The bracketed number is the PUNKTFUNK_VK_DEVICE value, and the
                        // FIRST listed entry is what
                        // a default run presents on — the decoder shares that device, so
                        // on a hybrid box this line is usually the answer.
                        let kind = if a.discrete { "discrete" } else { "integrated" };
                        // `a.index`, NOT the loop position. This list is sorted
                        // discrete-first for reading, but PUNKTFUNK_VK_DEVICE indexes the
                        // raw enumeration, which puts the iGPU first on some hybrids —
                        // printing the loop position would name the other GPU on exactly
                        // the machines this flag is for. The `i == 0` marker is still the
                        // loop position, because sorted-first IS what pick_device lands on
                        // when nothing overrides it.
                        println!(
                            "[{}] {} ({kind}){}",
                            a.index,
                            a.name,
                            if i == 0 { "  <- default presenter" } else { "" }
                        );
                        println!(
                            "     vulkan video decode: {}",
                            if a.usable { "YES" } else { "no" }
                        );
                        // Name every bit, and ACCOUNT for the ones we cannot name. The
                        // 5070 Ti reports 0xF — four bits — while punktfunk decodes three
                        // codecs, so the first version of this line printed three names
                        // beside a four-bit mask and looked complete. VP9 (bit 3) is a
                        // real decode operation this client has no rung for; a codec the
                        // tool cannot name must not silently vanish from a mask it prints,
                        // or the reader is left to trust that the words cover the number.
                        const OPS: [(u32, &str); 4] = [
                            (0x1, "H.264"),
                            (0x2, "H.265"),
                            (0x4, "AV1"),
                            (0x8, "VP9 (no punktfunk rung)"),
                        ];
                        let mut codecs: Vec<String> = OPS
                            .iter()
                            .filter(|(bit, _)| a.codec_ops & bit != 0)
                            .map(|(_, n)| (*n).to_string())
                            .collect();
                        let named: u32 = OPS.iter().map(|(b, _)| b).sum();
                        let unknown = a.codec_ops & !named;
                        if unknown != 0 {
                            codecs.push(format!("unrecognised bits 0x{unknown:X}"));
                        }
                        println!(
                            "     driver decode ops:   {}",
                            if codecs.is_empty() {
                                format!("none (0x{:X})", a.codec_ops)
                            } else {
                                format!("{} (0x{:X})", codecs.join(", "), a.codec_ops)
                            }
                        );
                        if !a.usable {
                            // Say which conjunct failed. "no" with no reason is the thing
                            // this whole flag exists to stop.
                            let mut why: Vec<String> = Vec::new();
                            if !a.api_1_3 {
                                why.push("device is not Vulkan 1.3".into());
                            }
                            if !a.features_ok {
                                why.push(
                                    "missing samplerYcbcrConversion / timelineSemaphore / \
                                     synchronization2"
                                        .into(),
                                );
                            }
                            if a.decode_family.is_none() {
                                why.push("no queue family advertises VIDEO_DECODE".into());
                            }
                            if !a.base_missing.is_empty() {
                                why.push(format!("missing {}", a.base_missing.join(", ")));
                            }
                            if a.codec_exts.is_empty() {
                                why.push("no VK_KHR_video_decode_{h264,h265,av1} extension".into());
                            }
                            println!("     why not:             {}", why.join("; "));
                        } else {
                            println!("     extensions:          {}", a.codec_exts.join(", "));
                        }
                        print_video_formats(a);
                    }
                    if adapters.len() > 1 {
                        // The single most common misreading of this output: seeing a
                        // capable GPU listed and concluding the decoder will use it.
                        // Vulkan Video decodes on the PRESENTER's device, and the decoder
                        // preference does not move the presenter.
                        println!();
                        println!(
                            "Vulkan Video decodes on the presenter's device. PUNKTFUNK_DECODER \
                             picks the rung,"
                        );
                        println!(
                            "not the GPU — move the presenter with PUNKTFUNK_VK_DEVICE=<index \
                             above> or"
                        );
                        println!(
                            "PUNKTFUNK_VK_ADAPTER=<name substring>, which is the safer knob \
                             where two"
                        );
                        println!("adapters share a name.");
                    }
                    0
                }
                Err(e) => {
                    eprintln!("probe-decode: {e:#}");
                    EXIT_PRESENTER_FAILED
                }
            };
        }

        // `--list-audio`: the PipeWire endpoints the settings pickers offer, as
        // `sink|source<TAB>node.name<TAB>description` lines — a debug window into the
        // same enumeration the GTK shell probes.
        #[cfg(target_os = "linux")]
        if arg_flag("--list-audio") {
            return match pf_client_core::audio::devices() {
                Ok((sinks, sources)) => {
                    for d in sinks {
                        println!("sink\t{}\t{}", d.name, d.description);
                    }
                    for d in sources {
                        println!("source\t{}\t{}", d.name, d.description);
                    }
                    0
                }
                Err(e) => {
                    eprintln!("list-audio: {e:#}");
                    EXIT_PRESENTER_FAILED
                }
            };
        }

        // `--pad-audio-test [--seconds N] [--speaker] [--coils]`: the controller-audio
        // correlation, printed, then a tone driven into the pad. The one tool that separates
        // "the plane never arrived" from "it arrived and the graph folded the coil pair away"
        // — no host, no game, no pairing needed, just a wired DualSense.
        #[cfg(target_os = "linux")]
        if arg_flag("--pad-audio-test") {
            let seconds = arg_value("--seconds")
                .and_then(|v| v.parse().ok())
                .unwrap_or(3);
            // Coils by default: they are the half that silently disappears, so they are the
            // half worth testing. `--speaker` adds (or, with nothing else, selects) the
            // speaker pair.
            let speaker = arg_flag("--speaker");
            let coils = arg_flag("--coils") || !speaker;
            // Say up front whether a real session would render what this is about to prove
            // works. The devtest drives the pad DIRECTLY, so it is deliberately blind to the
            // settings — which makes "the tone plays here but the game is silent" a genuinely
            // confusing result, and one that has cost a whole debugging evening: the toggle is
            // on the client while every instinct sends you measuring the host. The capability
            // is never advertised when the toggle is off, so no later log line can catch this.
            {
                let s = trust::Settings::load();
                if speaker && !pf_client_core::pad_audio::speaker_active(&s.pad_speaker) {
                    println!(
                        "note: \"Controller speaker\" is OFF in your settings (pad_speaker = \
                         {:?}), so a streaming session will NOT render the pad's speaker even if \
                         the tone below is audible.",
                        s.pad_speaker
                    );
                }
                if coils && !s.pad_haptics {
                    println!(
                        "note: \"Controller haptics\" is OFF in your settings, so a streaming \
                         session will NOT render the voice coils even if the tone below is felt."
                    );
                }
            }
            return match pf_client_core::pad_audio::pad_audio_test(seconds, coils, speaker) {
                Ok(()) => 0,
                Err(e) => {
                    eprintln!("pad-audio-test: {e:#}");
                    EXIT_PRESENTER_FAILED
                }
            };
        }

        // `--pair <PIN>`: enrol this machine against a host and exit. DEPRECATED — pairing is
        // a trust ceremony and belongs to the brain, fronted by `punktfunk pair` or a shell
        // (design/client-architecture-split.md §5). It still works, with a notice, for the one
        // release this needs; a renderer owning a trust ceremony is exactly the mixing of
        // concerns the split exists to undo.
        if let Some(pin) = arg_value("--pair") {
            eprintln!(
                "note: punktfunk-session --pair is deprecated \u{2014} use `punktfunk pair \
                 <host[:port]>` instead (same store, same result)."
            );
            return headless_pair(&pin);
        }

        // (The RADV video-decode opt-in that used to live here now runs at the very top of
        // `run` — it has to precede the probe flags too, not just the session.)

        // The Settings device picks → env, unless the user already forced one by hand:
        // the GPU (the shells' pickers store the adapter's marketing name) for the
        // presenter's device selection, and the audio endpoints (PipeWire node names /
        // WASAPI endpoint ids) for the playback/mic streams. Before any Vulkan call,
        // like the RADV knob (covers --connect and --browse).
        //
        // Spec mode takes them from the SPEC's settings — the spawner's resolve — which
        // keeps the §5 zero-store-reads invariant and lets a profile overlay reach these
        // fields if they ever become profileable. Parsed leniently here (the `--connect`
        // flow re-reads the spec authoritatively and errors there); the compat path and
        // `--browse` (which never carries a spec) still load the store.
        {
            let s = arg_value("--resolved-spec")
                .and_then(|p| {
                    pf_client_core::orchestrate::ResolvedSpec::read(std::path::Path::new(&p)).ok()
                })
                .map_or_else(trust::Settings::load, |spec| spec.settings);
            for (var, value) in [
                ("PUNKTFUNK_VK_ADAPTER", &s.adapter),
                ("PUNKTFUNK_AUDIO_SINK", &s.speaker_device),
                ("PUNKTFUNK_AUDIO_SOURCE", &s.mic_device),
            ] {
                if std::env::var_os(var).is_none() && !value.is_empty() {
                    // SAFETY: still the single-threaded startup stretch of `run()` — the
                    // early-exit probes above return out of the process, and everything that
                    // spawns threads (the session, the console, SDL) only starts below.
                    #[allow(unsafe_code)]
                    unsafe {
                        std::env::set_var(var, value)
                    };
                }
            }
        }

        // Steam launches its shortcuts with SDL_GAMECONTROLLER_IGNORE_DEVICES naming
        // every pad Steam Input has virtualized; capturing the Deck's real built-in
        // controller needs it cleared (same rationale as the GTK client's `app::run`).
        for var in [
            "SDL_GAMECONTROLLER_IGNORE_DEVICES",
            "SDL_GAMECONTROLLER_IGNORE_DEVICES_EXCEPT",
        ] {
            if let Ok(v) = std::env::var(var) {
                tracing::info!(var, value = %v, "clearing Steam's SDL device filter");
                // SAFETY: as the settings block above — single-threaded startup, before SDL
                // (the reader of these variables) or any other thread exists.
                #[allow(unsafe_code)]
                unsafe {
                    std::env::remove_var(var)
                };
            }
        }

        if arg_flag("--browse") {
            // Bare `--browse` opens the console home (hosts, pairing, settings);
            // `--browse host[:port]` opens straight into that host's library.
            let target = arg_value("--browse");
            #[cfg(feature = "ui")]
            return crate::console::run(target.as_deref());
            #[cfg(not(feature = "ui"))]
            {
                let _ = target;
                eprintln!(
                    "--browse needs the console UI — this is the minimal build \
                     (rebuild without --no-default-features)"
                );
                return EXIT_PRESENTER_FAILED;
            }
        }
        let Some(target) = arg_value("--connect") else {
            eprintln!(
                "usage: punktfunk-session --connect host[:port] [--fp HEX] [--launch id] [--profile REF] [--fullscreen]\n\
                 \x20      punktfunk-session --browse [host[:port]] [--mgmt PORT] [--fullscreen] [--json-status]\n\
                 \x20      punktfunk-session --pair <PIN> --connect host[:port] [--name LABEL]\n\
                 \n\
                 Streams from a paired punktfunk host in a Vulkan window. --browse opens the\n\
                 gamepad console instead: bare --browse is the host list (discovery, PIN\n\
                 pairing, settings, wake-on-LAN); with a target it opens that host's game\n\
                 library. --profile picks a settings profile by id or name for this session\n\
                 only (\"\" = the global defaults); without it the host's own profile applies.\n\
                 --connect never dials a host it has no pinned fingerprint for —\n\
                 enrol with --pair (no display needed), in the console, or from the desktop\n\
                 client."
            );
            return EXIT_CONNECT_FAILED;
        };
        let (addr, port) = parse_host_port(&target);

        // WireGuard overlay: `--wg-server addr:port --wg-server-pub B64 --wg-client-key B64`
        // starts an in-process WG relay (the remote gate's mirror) and the session then
        // dials its loopback listeners. All three flags come together or not at all.
        let wg_args = (
            arg_value("--wg-server"),
            arg_value("--wg-server-pub"),
            arg_value("--wg-client-key"),
        );
        let wg = match wg_args {
            (None, None, None) => None,
            (Some(server), Some(server_pub), Some(client_key)) => {
                // Per-session loopback pair from the spawner (multi-WG-session support);
                // default pair keeps single-session behaviour byte-identical.
                let (lq, ld) = match arg_value("--wg-relay-listen") {
                    Some(v) => match v.split_once(':') {
                        Some((q, d)) => match (q.parse::<u16>(), d.parse::<u16>()) {
                            (Ok(q), Ok(d)) => (q, d),
                            _ => {
                                json_line("error", "wg: --wg-relay-listen wants QUIC:DATA ports", None);
                                return EXIT_CONNECT_FAILED;
                            }
                        },
                        None => {
                            json_line("error", "wg: --wg-relay-listen wants QUIC:DATA ports", None);
                            return EXIT_CONNECT_FAILED;
                        }
                    },
                    None => (WG_LOCAL_QUIC_PORT, WG_LOCAL_DATA_PORT),
                };
                let (saddr, sport) = parse_host_port(&server);
                let server_addr = match format!("{saddr}:{sport}").parse::<std::net::SocketAddr>()
                {
                    Ok(a) => a,
                    Err(_) => match std::net::ToSocketAddrs::to_socket_addrs(&(saddr.as_str(), sport))
                    {
                        Ok(mut it) => match it.next() {
                            Some(a) => a,
                            None => {
                                json_line("error", &format!("wg: cannot resolve {server}"), None);
                                return EXIT_CONNECT_FAILED;
                            }
                        },
                        Err(e) => {
                            json_line("error", &format!("wg: resolve {server}: {e}"), None);
                            return EXIT_CONNECT_FAILED;
                        }
                    },
                };
                let cfg = pf_wgtunnel::client::ClientConfig {
                    server: server_addr,
                    private_key: match pf_wgtunnel::keys::parse_private_key(&client_key) {
                        Ok(k) => k,
                        Err(e) => {
                            json_line("error", &format!("wg client key: {e}"), None);
                            return EXIT_CONNECT_FAILED;
                        }
                    },
                    server_public: match pf_wgtunnel::keys::parse_public_key(&server_pub) {
                        Ok(k) => k,
                        Err(e) => {
                            json_line("error", &format!("wg server public key: {e}"), None);
                            return EXIT_CONNECT_FAILED;
                        }
                    },
                    listen_quic: ([127, 0, 0, 1], lq).into(),
                    listen_data: ([127, 0, 0, 1], ld).into(),
                    // The host-side service ports the gate dispatches on — always the
                    // standard pair, independent of which local ports this session got.
                    quic_target_port: WG_LOCAL_QUIC_PORT,
                    data_target_port: WG_LOCAL_DATA_PORT,
                };
                // The data-plane handshake would otherwise aim video at
                // `welcome.udp_port` — the HOST-side service port the gate dispatches
                // on, identical for every session. With two WG sessions up, session 2's
                // video then lands in session 1's relay (zero frames on 2, stray traffic
                // killing 1). Only this process knows which relay pair IT got, so publish
                // the data listener for the core handshake before the pump starts.
                punktfunk_core::client::WG_RELAY_DATA_PORT
                    .store(ld, std::sync::atomic::Ordering::SeqCst);
                std::thread::Builder::new()
                    .name("wg-relay".into())
                    .spawn(move || {
                        if let Err(e) = pf_wgtunnel::client::run_client(cfg) {
                            tracing::error!("wg relay: {e:#}");
                        }
                    })
                    .ok();
                Some((lq, ld))
            }
            _ => {
                json_line(
                    "error",
                    "--wg-server, --wg-server-pub and --wg-client-key must be given together",
                    None,
                );
                return EXIT_CONNECT_FAILED;
            }
        };
        let (dial_addr, dial_port) = if let Some((lq, _)) = wg {
            ("127.0.0.1".to_string(), lq)
        } else {
            (addr.clone(), port)
        };

        let identity = match trust::load_or_create_identity() {
            Ok(i) => i,
            Err(e) => {
                json_line("error", &format!("client identity: {e:#}"), None);
                return EXIT_CONNECT_FAILED;
            }
        };
        // `--resolved-spec <path>`: the spawner already did the resolving, so this process
        // performs ZERO store reads (design/client-architecture-split.md §5) — no Settings
        // load, no known-hosts lookup, no profile resolution. Without it (a hand-run
        // `--connect`, an old Decky script) the session resolves for itself through the SAME
        // helper, so the two modes cannot drift.
        let spec = arg_value("--resolved-spec").map(std::path::PathBuf::from);
        let (settings, profile_name, clipboard_override) = match &spec {
            Some(path) => match pf_client_core::orchestrate::ResolvedSpec::read(path) {
                Ok(s) => {
                    tracing::info!(path = %path.display(), "running from a resolved spec");
                    (s.settings, s.profile, Some(s.clipboard))
                }
                Err(e) => {
                    json_line("error", &format!("resolved spec: {e}"), None);
                    return EXIT_CONNECT_FAILED;
                }
            },
            None => {
                let (settings, profile) =
                    trust::effective_settings(&addr, port, profile_arg().as_deref());
                (settings, profile.map(|p| p.name), None)
            }
        };
        if let Some(name) = &profile_name {
            tracing::info!(profile = %name, "streaming with a settings profile");
        }

        // Trust follows the GTK client's `--connect` rules: a stored (or `--fp`) pin
        // connects silently; an unknown host is REFUSED — there is no dialog here, and a
        // silent TOFU would defeat the pinning model. Pair via the desktop client.
        let known = trust::KnownHosts::load();
        let known_host = known.find_by_addr(&addr, port);
        let pin = arg_value("--fp")
            .as_deref()
            .and_then(trust::parse_hex32)
            .or_else(|| known_host.and_then(|h| trust::parse_hex32(&h.fp_hex)));
        // WG mode needs no pin: the tunnel handshake itself authenticates both peers, and the
        // host's TLS fingerprint is learned from the session's own Welcome (see on_connected).
        if pin.is_none() && wg.is_none() {
            json_line(
                "error",
                &format!(
                    "no pinned fingerprint for {addr}:{port} — pair first \
                     (punktfunk-session --pair <PIN> --connect {addr}:{port}) or pass --fp HEX"
                ),
                Some(true),
            );
            return EXIT_TRUST_REJECTED;
        }

        let host_label = known_host.map_or_else(|| addr.clone(), |h| h.name.clone());
        let launch = arg_value("--launch");
        let title = launch
            .clone()
            .map_or_else(|| host_label.clone(), |id| format!("{host_label} · {id}"));

        let fullscreen = arg_flag("--fullscreen")
            || std::env::var_os("SteamDeck").is_some()
            || std::env::var_os("GAMESCOPE_WAYLAND_DISPLAY").is_some();

        let wg_mode = wg.is_some();
        let fp_learn_addr = addr.clone();
        let opts = pf_presenter::SessionOpts {
            window_title: format!("Punktfunk · {title}"),
            fullscreen,
            window_pos: window_pos(),
            stats_verbosity: stats_tier(&settings),
            touch_mode: settings.touch_mode(),
            mouse_mode: settings.mouse_mode(),
            invert_scroll: settings.invert_scroll,
            inhibit_shortcuts: settings.inhibit_shortcuts,
            present_priority: settings.present_priority(),
            vsync: settings.vsync,
            allow_vrr: settings.allow_vrr,
            json_status: true,
            on_connected: Some(Box::new(move |fingerprint: [u8; 32], mgmt_port: u16| {
                let fp = trust::hex(&fingerprint);
                // WG mode connected with no pin: learn the host's TLS fingerprint NOW, keyed
                // by its real address, so the shell can fill the card in (learn only when the
                // record's fp is still empty; it must run before touch_last_used, which
                // matches by fp).
                if wg_mode {
                    trust::learn_fp_by_addr(&fp_learn_addr, port, &fp);
                }
                // This host's card carries the accent bar in the desktop client now.
                trust::touch_last_used(&fp);
                // Save where this host serves its library, learned from the session's own
                // Welcome rather than an mDNS advert — so it keeps working on a network where
                // discovery never does. `0` = the host advertised none; leave what we have.
                if mgmt_port != 0 {
                    trust::learn_mgmt_port_by_fp(&fp, mgmt_port);
                }
            })),
            // The Skia console UI (stats OSD, capture HUD) — compiled out of the
            // power-user build (`--no-default-features` drops the `ui` feature).
            #[cfg(feature = "ui")]
            overlay: Some(Box::new(pf_console_ui::SkiaOverlay::new())),
            #[cfg(not(feature = "ui"))]
            overlay: None,
            window_size: window_size(&settings),
            // A spawned session (spec mode) reports its window; a hand-run one persists it.
            match_window: match_window(&settings, spec.is_none()),
            render_scale: settings.render_scale,
            render_scale_max_dim: punktfunk_core::render_scale::max_dimension(&settings.codec),
        };

        let outcome =
            pf_presenter::run_session(opts, move |gamepad, native, force_software, vulkan| {
                session_params(
                    &settings,
                    profile_name,
                    clipboard_override,
                    dial_addr,
                    dial_port,
                    pin,
                    wg_mode.then_some((addr, port)),
                    identity,
                    launch,
                    gamepad,
                    native,
                    force_software,
                    vulkan,
                )
            });

        match outcome {
            Ok(pf_presenter::Outcome::Ended(None)) => 0,
            Ok(pf_presenter::Outcome::Ended(Some(reason))) => {
                // The host ending the session (game quit, host shutdown) is a normal end
                // for a one-shot stream binary — report the reason, exit clean.
                json_line("ended", &reason, None);
                0
            }
            Ok(pf_presenter::Outcome::ConnectFailed {
                msg,
                trust_rejected,
            }) => {
                json_line("error", &msg, Some(trust_rejected));
                if trust_rejected {
                    EXIT_TRUST_REJECTED
                } else {
                    EXIT_CONNECT_FAILED
                }
            }
            Err(e) => {
                json_line("error", &format!("presenter: {e:#}"), None);
                EXIT_PRESENTER_FAILED
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use trust::StatsVerbosity as V;

        /// `--stats` is a floor, never a ceiling: it lifts Off to Normal and leaves every
        /// richer chosen tier alone. Both run modes' presenter options AND the per-launch
        /// params read this one rule, which is the point of having it.
        #[test]
        fn the_stats_flag_lifts_off_and_demotes_nothing() {
            assert_eq!(stats_tier_with(V::Off, true), V::Normal);
            assert_eq!(stats_tier_with(V::Off, false), V::Off);
            for chosen in [V::Compact, V::Normal, V::Detailed] {
                assert_eq!(stats_tier_with(chosen, true), chosen);
                assert_eq!(stats_tier_with(chosen, false), chosen);
            }
        }

        /// The console reads the file ONCE for its window, so a tier changed between streams
        /// can only reach the overlay by riding the launch. Guards the wiring the field exists
        /// for: whatever settings a launch resolved is what the params carry.
        #[test]
        fn a_launch_carries_the_tier_its_settings_resolved() {
            let mut s = trust::Settings::default();
            for chosen in [V::Off, V::Compact, V::Normal, V::Detailed] {
                s.set_stats_verbosity(chosen);
                assert_eq!(stats_tier_with(s.stats_verbosity(), false), chosen);
            }
        }
    }
}

#[cfg(any(target_os = "linux", windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(session_main::run())
}

/// This stub keeps `cargo build --workspace` green elsewhere (the Mac client lives in
/// clients/apple).
#[cfg(not(any(target_os = "linux", windows)))]
fn main() {
    eprintln!(
        "punktfunk-session runs on Linux and Windows — the macOS client lives in clients/apple"
    );
    std::process::exit(2);
}
