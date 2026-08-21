//! `--browse [host[:port]]` — the console shell. Bare `--browse` opens the host list
//! (discovery, pairing, settings, wake — the whole couch flow); with a target it opens
//! straight into that host's library (the Decky per-host launch), B backing out to the
//! list — one press either way, because with "Start in collections" on it is the shelf
//! that hands over to the collections screen rather than a second screen being stacked on
//! it. A launches in the SAME window (no gamescope window handoff — the whole point
//! of one process), the session's end returns to the console, B at the root quits to
//! Gaming Mode.
//!
//! This file is the console's SERVICE side: the shell (pf-console-ui) renders and
//! raises [`ConsoleCmd`]s; worker threads here run everything that blocks — mDNS
//! discovery, reachability probes, the SPAKE2 pairing ceremony, wake-on-LAN loops,
//! library fetches, known-hosts persistence — and write results into the shared
//! models. `PUNKTFUNK_FAKE_LIBRARY=<file.json>` feeds canned entries with no host
//! (portrait paths starting with `/` load from disk), the GPU-only dev path.

use crate::session_main::{
    arg_flag, arg_value, fullscreen_mode, parse_host_port, session_params, stats_tier, window_pos,
};
use pf_client_core::gamepad::is_steam_deck;
use pf_client_core::{discovery, library, trust, wol};
use pf_console_ui::{
    ConsoleCmd, ConsoleEntry, ConsoleHandles, ConsoleOptions, ConsoleShared, HostRow, LibraryGame,
    LibraryPhase, LibraryShared, PairPhase, SkiaOverlay, WakeStatus,
};
use pf_presenter::overlay::OverlayAction;
use pf_presenter::ActionOutcome;
use std::collections::{HashMap, VecDeque};
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// A request-access connect awaiting the operator's approval on the host: stamped by the
/// launch handler and consumed by `on_connected`, which persists the host as paired.
struct PendingApproval {
    name: String,
    addr: String,
    port: u16,
    fp_hex: String,
}

pub fn run(target: Option<&str>) -> u8 {
    let identity = match trust::load_or_create_identity() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("client identity: {e:#}");
            return crate::session_main::EXIT_CONNECT_FAILED;
        }
    };

    // Resolve the entry point: a paired target opens straight into its library; an
    // unpaired/unknown one lands on Home with the target seeded into the list (one A
    // from pairing). The fake-library hook fabricates a paired host with no network.
    let fake = std::env::var_os("PUNKTFUNK_FAKE_LIBRARY").is_some();
    let known = trust::KnownHosts::load();
    let mut seed: Option<HostRow> = None;
    let (entry, window_label) = match target {
        Some(target) => {
            let (addr, port) = parse_host_port(target);
            let k = known
                .hosts
                .iter()
                .find(|h| h.addr == addr && h.port == port);
            let row = HostRow {
                key: k
                    .filter(|h| !h.fp_hex.is_empty())
                    .map_or_else(|| format!("{addr}:{port}"), |h| h.fp_hex.clone()),
                name: k
                    .map(|h| host_display_name(&h.name, &h.addr))
                    .unwrap_or_else(|| addr.clone()),
                addr: addr.clone(),
                port,
                fp_hex: k.map(|h| h.fp_hex.clone()).unwrap_or_default(),
                paired: k.is_some_and(|h| h.paired) || fake,
                saved: k.is_some(),
                online: false,
                // Explicit --mgmt wins; else the port this host's advert taught us and we saved;
                // else 47990. The middle rung is what survives mDNS being unavailable later.
                mgmt_port: arg_value("--mgmt")
                    .and_then(|p| p.parse().ok())
                    .or_else(|| k.and_then(|h| h.mgmt_port))
                    .unwrap_or(library::DEFAULT_MGMT_PORT),
                can_wake: false,
                clipboard_sync: k.is_some_and(|h| h.clipboard_sync),
                last_used: k.and_then(|h| h.last_used),
                os: k.map(|h| h.os.clone()).unwrap_or_default(),
                pin: None,
                bound_profile: None,
            };
            let label = row.name.clone();
            if k.is_none() {
                seed = Some(row.clone());
            }
            if row.paired {
                (ConsoleEntry::Library(Box::new(row)), Some(label))
            } else {
                (ConsoleEntry::Home, Some(label))
            }
        }
        None if fake => {
            let row = fake_host_row();
            (ConsoleEntry::Library(Box::new(row)), None)
        }
        None => (ConsoleEntry::Home, None),
    };
    let initial_fetch = match &entry {
        ConsoleEntry::Library(h) => Some(ConsoleCmd::FetchLibrary {
            addr: h.addr.clone(),
            mgmt: h.mgmt_port,
            fp_hex: h.fp_hex.clone(),
        }),
        ConsoleEntry::Home => None,
    };

    let opts = ConsoleOptions::desktop(trust::device_name(), is_steam_deck());
    let (overlay, handles) = match SkiaOverlay::console(opts, entry) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("console UI: {e:#}");
            return crate::session_main::EXIT_PRESENTER_FAILED;
        }
    };
    let ConsoleHandles {
        console,
        library: library_model,
        bus,
    } = handles;

    // The service loop: discovery, probes, wake, pairing, persistence, fetches.
    let service = Service::start(
        console.clone(),
        library_model.clone(),
        bus.clone(),
        identity.clone(),
        seed,
    );
    if let Some(cmd) = initial_fetch {
        bus.send(cmd);
    }

    // `--json-status`: a shell parent is reading stdout (the WinUI shell hides itself on
    // `{"ready":true}` and restores on exit) — plain CLI/gamescope runs stay silent.
    let json_status = arg_flag("--json-status");
    let settings_at_start = trust::Settings::load();
    // The console's window and its input models are built ONCE, from the global defaults, and
    // live across every launch — so the presentation-tier fields below (touch and mouse model,
    // shortcut inhibit, match-window, render scale) are latched here and a per-host profile
    // cannot move them in this mode. Everything the HOST is told (mode, bitrate, codec, audio,
    // pad) is re-resolved per launch and does honor the binding. Closing the rest of that gap
    // means rebuilding the presenter's models per launch — profiles P4 territory, not P0.
    //
    // ⚠ The STATS TIER used to be latched here too, and that was a bug people hit: the console's
    // own settings screen writes the tier to the file and redraws its row, so the choice looked
    // taken while every stream kept the tier the process started on — "no matter what I select
    // the overlay is stuck on Detailed", cured only by restarting the app. It now rides
    // `SessionParams` per launch (`stats_verbosity`), so the value below only seeds the loop
    // until the first stream. Anything else moved off this snapshot has to travel the same way.
    let latched_mouse = settings_at_start.mouse_mode();

    // Request-access hand-off: the launch handler stamps this when it starts a delegated-approval
    // connect; `on_connected` reads it once the host lets us in and persists the host as PAIRED,
    // so the next connect is an ordinary one. `None` for every normal launch, so `on_connected`
    // then only touches last-used.
    let pending_approval: Arc<Mutex<Option<PendingApproval>>> = Arc::new(Mutex::new(None));
    let pending_cb = pending_approval.clone();

    let opts = pf_presenter::SessionOpts {
        window_title: window_label.map_or_else(
            || "Punktfunk".to_string(),
            |label| format!("Punktfunk · {label}"),
        ),
        fullscreen: fullscreen_mode(),
        window_pos: window_pos(),
        // Seeds the loop only — every launch carries its own freshly resolved tier.
        stats_verbosity: stats_tier(&settings_at_start),
        touch_mode: settings_at_start.touch_mode(),
        mouse_mode: settings_at_start.mouse_mode(),
        invert_scroll: settings_at_start.invert_scroll,
        inhibit_shortcuts: settings_at_start.inhibit_shortcuts,
        // Presentation-tier like the rows above: latched at console start, a per-host
        // profile cannot move it in this mode (the documented P4 gap).
        present_priority: settings_at_start.present_priority(),
        vsync: settings_at_start.vsync,
        allow_vrr: settings_at_start.allow_vrr,
        json_status,
        on_connected: Some(Box::new(move |fingerprint: [u8; 32], mgmt_port: u16| {
            let fp_hex = trust::hex(&fingerprint);
            trust::touch_last_used(&fp_hex);
            // A request-access connect just succeeded → the operator approved us. Save the
            // host as paired (it was unsaved/discovered), keyed to the fingerprint we pinned.
            if let Some(p) = pending_cb.lock().unwrap().take() {
                if p.fp_hex == fp_hex {
                    trust::persist_host(&p.name, &p.addr, p.port, &fp_hex, true);
                }
            }
            // Where this host serves its library, from the session's own Welcome — recorded
            // AFTER the persist above so a host saved by this very connect gets it too. `0` =
            // the host advertised none, and the call is a no-op.
            trust::learn_mgmt_port_by_fp(&fp_hex, mgmt_port);
        })),
        overlay: Some(Box::new(overlay)),
        window_size: crate::session_main::window_size(&settings_at_start),
        // Latched at console start (like the stats tier above): toggling Match window in
        // the console's settings screen applies from the next console launch.
        // The console owns its own window across every launch, and no parent is listening to
        // its stdout, so it keeps persisting the size itself.
        match_window: crate::session_main::match_window(&settings_at_start, true),
        render_scale: settings_at_start.render_scale,
        render_scale_max_dim: punktfunk_core::render_scale::max_dimension(&settings_at_start.codec),
    };

    let result =
        pf_presenter::run_browse(opts, |action, gamepad, native, force_software, vulkan| {
            match action {
                OverlayAction::Launch {
                    addr,
                    port,
                    fp_hex,
                    launch,
                    title,
                    request_access,
                    profile,
                } => {
                    let Some(pin) = trust::parse_hex32(&fp_hex) else {
                        // Connect (and request-access) pin the host's advertised fingerprint;
                        // a pinless launch is a logic slip, never a silent TOFU.
                        tracing::warn!(%addr, "launch without a stored pin — refusing");
                        return ActionOutcome::Handled;
                    };
                    tracing::info!(%addr, %title, request_access,
                        launch = launch.as_deref().unwrap_or("desktop"),
                        "launching from the console");
                    // Settings re-resolve per launch: the console's own settings screen may
                    // have changed the defaults since the last stream, and the host may carry
                    // a profile binding. Console (and therefore Decky, which spawns this
                    // binary) honors bindings with no console-side work — the resolver is the
                    // same one `--connect` goes through. A pinned card's connect arrives as a
                    // one-off profile id; the resolver prefers it over the binding, and a
                    // dangling id falls back to the defaults without blocking the connect.
                    let (settings, profile) =
                        trust::effective_settings(&addr, port, profile.as_deref());
                    let mut params = session_params(
                        &settings,
                        profile.map(|p| p.name),
                        // In-process launch: no spawner resolved a clipboard decision for us.
                        None,
                        addr.clone(),
                        port,
                        Some(pin),
                        None,
                        identity.clone(),
                        launch,
                        gamepad,
                        native,
                        force_software,
                        vulkan,
                    );
                    // …with ONE field that must follow the latched model rather than this
                    // launch's: the cursor-channel advertisement says "this client draws the
                    // host cursor itself", which is only true while the presenter is in desktop
                    // mouse mode. A profile that flips `mouse_mode` here would make the host
                    // stop compositing the pointer into a presenter that isn't drawing one —
                    // a stream with no visible cursor at all.
                    params.cursor_forward = latched_mouse == trust::MouseMode::Desktop;
                    if request_access {
                        // The host PARKS the connect until the operator approves — outlast its
                        // approval window (host `PENDING_APPROVAL_WAIT`), matching the desktop
                        // shells' 185 s. On success `on_connected` persists the host as paired.
                        params.connect_timeout = Duration::from_secs(185);
                        *pending_approval.lock().unwrap() = Some(PendingApproval {
                            name: title.clone(),
                            addr,
                            port,
                            fp_hex: fp_hex.clone(),
                        });
                    }
                    ActionOutcome::Start(Box::new(params))
                }
                OverlayAction::CancelConnect => ActionOutcome::Handled, // run-loop-side
                // Also run-loop-side: the clipboard belongs to SDL, which this callback
                // has no handle on. Unreachable in practice — listed so adding an action
                // to the enum keeps failing loudly here instead of falling into a
                // wildcard that silently drops it.
                OverlayAction::CopyText(_) => ActionOutcome::Handled,
                OverlayAction::Quit => ActionOutcome::Quit,
            }
        });

    service.stop();

    match result {
        Ok(()) => 0,
        Err(e) => {
            // The shell contract's terminal line (a clean quit needs none — stdout EOF
            // already routes the shell back to its host list silently).
            if json_status {
                crate::session_main::json_line("error", &format!("{e:#}"), Some(false));
            }
            eprintln!("console: {e:#}");
            crate::session_main::EXIT_PRESENTER_FAILED
        }
    }
}

/// A console row key → its index in the known-hosts store. The key is the pinned
/// fingerprint when there is one, else `addr:port` (see the row builder), and a pinned
/// CARD's key carries the profile id past a NUL — the console strips that before it
/// sends a command, so nothing here has to.
fn index_for_key(known: &trust::KnownHosts, key: &str) -> Option<usize> {
    known
        .hosts
        .iter()
        .position(|h| !h.fp_hex.is_empty() && h.fp_hex == key)
        .or_else(|| {
            let (addr, port) = key.rsplit_once(':')?;
            known.index_by_addr(addr, port.parse().ok()?)
        })
}

fn host_display_name(name: &str, addr: &str) -> String {
    if name.trim().is_empty() {
        addr.to_string()
    } else {
        name.to_string()
    }
}

fn fake_host_row() -> HostRow {
    HostRow {
        key: "fake".into(),
        name: "Demo Host".into(),
        addr: "127.0.0.1".into(),
        port: 9777,
        fp_hex: String::new(),
        paired: true,
        saved: true,
        online: true,
        mgmt_port: library::DEFAULT_MGMT_PORT,
        can_wake: false,
        clipboard_sync: false,
        last_used: None,
        os: "linux/arch/steamos".into(),
        pin: None,
        bound_profile: None,
    }
}

/// The background service: owns discovery, probing, waking, pairing and persistence.
struct Service {
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Service {
    fn start(
        console: ConsoleShared,
        library_model: LibraryShared,
        bus: pf_console_ui::ConsoleBus,
        identity: (String, String),
        seed: Option<HostRow>,
    ) -> Service {
        let stop = Arc::new(AtomicBool::new(false));
        let stop_w = stop.clone();
        let thread = std::thread::Builder::new()
            .name("punktfunk-console".into())
            .spawn(move || {
                ServiceState {
                    console,
                    library: library_model,
                    bus,
                    identity,
                    seed,
                    discovered: HashMap::new(),
                    probed: Arc::new(Mutex::new(HashMap::new())),
                    probe_inflight: Arc::new(AtomicBool::new(false)),
                    last_probe: Instant::now() - Duration::from_secs(60),
                    wake_cancel: None,
                    rescan: None,
                }
                .run(stop_w)
            })
            .ok();
        Service { stop, thread }
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct ServiceState {
    console: ConsoleShared,
    library: LibraryShared,
    bus: pf_console_ui::ConsoleBus,
    identity: (String, String),
    /// A `--browse` target that isn't in the store yet — kept on the list until the
    /// store or discovery covers it.
    seed: Option<HostRow>,
    discovered: HashMap<String, discovery::DiscoveredHost>,
    /// Probe results by row key, written by sweep threads.
    probed: Arc<Mutex<HashMap<String, bool>>>,
    probe_inflight: Arc<AtomicBool>,
    last_probe: Instant,
    /// Cancels the active wake thread (it owns the model's wake status).
    wake_cancel: Option<Arc<AtomicBool>>,
    /// Forces the mDNS browse to re-query. Installed by `run`; `None` before it starts.
    rescan: Option<discovery::Rescan>,
}

impl ServiceState {
    fn run(mut self, stop: Arc<AtomicBool>) {
        let (discovery_rx, rescan) = discovery::browse();
        self.rescan = Some(rescan);
        while !stop.load(Ordering::SeqCst) {
            // mDNS churn.
            while let Ok(ev) = discovery_rx.try_recv() {
                match ev {
                    discovery::DiscoveryEvent::Resolved(host) => {
                        self.discovered.insert(host.fullname.clone(), host);
                    }
                    discovery::DiscoveryEvent::Removed { fullname } => {
                        self.discovered.remove(&fullname);
                    }
                }
            }

            // Shell commands (plus the binary's own seeded initial fetch).
            for cmd in self.bus.drain() {
                self.handle(cmd);
            }

            // The 10 s reachability sweep — saved hosts that don't advertise (routed /
            // multicast-filtered networks) still get honest presence pips.
            if self.last_probe.elapsed() >= Duration::from_secs(10) {
                self.last_probe = Instant::now();
                self.sweep();
            }

            self.console.set_hosts(self.rows());
            std::thread::sleep(Duration::from_millis(100));
        }
        if let Some(c) = &self.wake_cancel {
            c.store(true, Ordering::SeqCst);
        }
    }

    fn handle(&mut self, cmd: ConsoleCmd) {
        match cmd {
            ConsoleCmd::FetchLibrary { addr, mgmt, fp_hex } => {
                // Opening a library is the earliest honest signal that somebody intends to
                // play, so the box gets woken HERE rather than at connect time — by which
                // point they have chosen a title and are sitting through a cold boot. Resolved
                // the same way `Wake` does, and empty for a host with no MAC on record, which
                // simply means the fetch asks once instead of retrying across a boot window.
                let macs = trust::KnownHosts::load()
                    .hosts
                    .iter()
                    .find(|h| (!fp_hex.is_empty() && h.fp_hex == fp_hex) || h.addr == addr)
                    .map(|h| h.mac.clone())
                    .unwrap_or_default();
                spawn_fetch(
                    self.library.clone(),
                    addr,
                    mgmt,
                    self.identity.clone(),
                    fp_hex.clone(),
                    trust::parse_hex32(&fp_hex),
                    macs,
                );
            }
            ConsoleCmd::RefreshRunning { addr, mgmt, fp_hex } => {
                // Blocking network on a worker, like every other command here: the service
                // loop's own host refresh must keep running while a just-ended stream's host
                // is asked what it still has up.
                let shared = self.library.clone();
                let identity = self.identity.clone();
                let pin = trust::parse_hex32(&fp_hex);
                std::thread::Builder::new()
                    .name("punktfunk-running".into())
                    .spawn(move || {
                        shared.set_running(&running_ids(&addr, mgmt, &identity, pin));
                    })
                    .ok();
            }
            ConsoleCmd::SendLogs {
                addr,
                mgmt,
                fp_hex,
                host_name,
            } => {
                // Blocking network (5 s connect / 10 s global, the library agent's budgets) —
                // a worker thread keeps the service loop's host refresh alive meanwhile. The
                // result lands as a shared-model notice; the shell toasts it on its next sync.
                let identity = self.identity.clone();
                let pin = trust::parse_hex32(&fp_hex);
                let console = self.console.clone();
                std::thread::Builder::new()
                    .name("punktfunk-sendlogs".into())
                    .spawn(move || {
                        let header = format!(
                            "punktfunk-session {} ({} {}) — client log bundle",
                            env!("CARGO_PKG_VERSION"),
                            std::env::consts::OS,
                            std::env::consts::ARCH,
                        );
                        match pf_client_core::logring::send_to_host(
                            &addr, mgmt, &identity, pin, &header,
                        ) {
                            Ok(id) => {
                                tracing::info!(host = %host_name, id, "client logs uploaded");
                                console.set_notice(format!(
                                    "Logs sent to {host_name} — download them from its web \
                                     console's Logs page"
                                ));
                            }
                            Err(e) => {
                                tracing::warn!(host = %host_name, error = %e, "client log upload failed");
                                console.set_notice(format!("Couldn't send logs — {e}"));
                            }
                        }
                    })
                    .ok();
            }
            ConsoleCmd::Pair {
                addr,
                port,
                pin,
                device_name,
            } => {
                // Prefer what the list already calls this host (advert or store).
                let name = self
                    .rows()
                    .into_iter()
                    .find(|r| r.addr == addr && r.port == port)
                    .map_or_else(|| addr.clone(), |r| r.name);
                self.console.set_pair(PairPhase::Busy);
                let console = self.console.clone();
                let identity = self.identity.clone();
                std::thread::Builder::new()
                    .name("punktfunk-pair".into())
                    .spawn(move || {
                        match trust::pair_with_host(&addr, port, &identity, &pin, &device_name) {
                            Ok(fp) => {
                                let fp_hex = trust::hex(&fp);
                                trust::persist_host(&name, &addr, port, &fp_hex, true);
                                console.set_pair(PairPhase::Paired { key: fp_hex });
                            }
                            Err(e) => {
                                // Cause-specific wording (wrong PIN vs not-armed vs unreachable
                                // vs a typed host rejection) — shared with every other surface.
                                console.set_pair(PairPhase::Failed(trust::pair_error_message(&e)));
                            }
                        }
                    })
                    .ok();
            }
            ConsoleCmd::SaveHost { name, addr, port } => {
                let mut known = trust::KnownHosts::load();
                // Manual entries have no fingerprint yet, so `upsert` (fp-keyed) would
                // collide two of them — key manual saves by address instead.
                if let Some(h) = known
                    .index_by_addr(&addr, port)
                    .and_then(|i| known.hosts.get_mut(i))
                {
                    if !name.is_empty() {
                        h.name = name;
                    }
                } else {
                    known.hosts.push(trust::KnownHost {
                        name: if name.is_empty() { addr.clone() } else { name },
                        addr,
                        port,
                        ..Default::default()
                    });
                }
                if let Err(e) = known.save() {
                    tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                }
                self.last_probe = Instant::now() - Duration::from_secs(60); // probe it now
            }
            ConsoleCmd::UpdateHost {
                key,
                name,
                addr,
                port,
            } => {
                let mut known = trust::KnownHosts::load();
                let Some(h) = index_for_key(&known, &key).and_then(|i| known.hosts.get_mut(i))
                else {
                    tracing::warn!(%key, "edit for an unknown host — ignoring");
                    return;
                };
                // Edited IN PLACE rather than removed and re-added: the fingerprint, the
                // learned MAC, the pinned cards and the profile binding all hang off this
                // entry, and re-adding would silently unpair a host the user only renamed.
                h.name = if name.trim().is_empty() {
                    addr.clone()
                } else {
                    name
                };
                h.addr = addr;
                h.port = port;
                if let Err(e) = known.save() {
                    tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                }
                self.last_probe = Instant::now() - Duration::from_secs(60); // the address moved
            }
            ConsoleCmd::ForgetHost { key } => {
                let mut known = trust::KnownHosts::load();
                let Some(i) = index_for_key(&known, &key) else {
                    tracing::warn!(%key, "forget for an unknown host — ignoring");
                    return;
                };
                let gone = known.hosts.remove(i);
                if let Err(e) = known.save() {
                    tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                }
                // A forgotten host leaves no list of what somebody plays behind on disk. The
                // catalog cache is keyed on the fingerprint, so this is the only moment that
                // key is still known.
                pf_client_core::library_cache::forget(&gone.fp_hex);
                tracing::info!(name = %gone.name, addr = %gone.addr, "host forgotten");
                // It may still be advertising, in which case it comes straight back as a
                // DISCOVERED row — unsaved and unpaired, which is the honest state.
                self.last_probe = Instant::now() - Duration::from_secs(60);
            }
            ConsoleCmd::Wake { key, then_connect } => {
                if let Some(c) = self.wake_cancel.take() {
                    c.store(true, Ordering::SeqCst);
                }
                let Some(row) = self.rows().into_iter().find(|r| r.key == key) else {
                    return;
                };
                let known = trust::KnownHosts::load();
                let macs = known
                    .hosts
                    .iter()
                    .find(|h| {
                        h.fp_hex == row.fp_hex && !row.fp_hex.is_empty()
                            || (h.addr == row.addr && h.port == row.port)
                    })
                    .map(|h| h.mac.clone())
                    .unwrap_or_default();
                if macs.is_empty() {
                    self.console.set_pair(PairPhase::Idle); // no-op; keep state sane
                    return;
                }
                let cancel = Arc::new(AtomicBool::new(false));
                self.wake_cancel = Some(cancel.clone());
                spawn_wake(self.console.clone(), row, macs, then_connect, cancel);
            }
            ConsoleCmd::CancelWake => {
                if let Some(c) = self.wake_cancel.take() {
                    c.store(true, Ordering::SeqCst);
                }
                self.console.set_wake(None);
            }
            ConsoleCmd::Probe => {
                self.last_probe = Instant::now() - Duration::from_secs(60);
                // "Refresh presence" means the mDNS half too, not just the QUIC sweep: the browse
                // runs for the process's lifetime and `mdns-sd` backs its re-query interval off to
                // as much as an hour, so a host that appeared since startup may never be asked
                // for again. (No console screen emits Probe yet — every face button on the home
                // screen is spoken for — but the plumbing is correct for when one does.)
                if let Some(r) = &self.rescan {
                    r.request();
                }
            }
            // A platform-native screen (Android's Licences view) — the desktop shell has no
            // such row, so this never arrives here.
            ConsoleCmd::OpenPlatformScreen { .. } => {}
            // Grants and rumble tests from the controllers screen. Android-only for the same
            // reason: the settings row that opens that screen is not on the desktop's list.
            ConsoleCmd::PadAction { .. } => {}
            ConsoleCmd::SetPin {
                key,
                profile_id,
                pin,
            } => {
                // Presentation only (design §5.2a): order = card order, appended at the
                // end; never touches `profile_id` (the default binding). Idempotent, so
                // a repeated press inside one refresh window can't double-pin.
                let mut known = trust::KnownHosts::load();
                let idx = index_for_key(&known, &key);
                let Some(h) = idx.and_then(|i| known.hosts.get_mut(i)) else {
                    tracing::warn!(%key, "pin toggle for an unknown host — ignoring");
                    return;
                };
                if pin && !h.pinned_profiles.contains(&profile_id) {
                    h.pinned_profiles.push(profile_id);
                } else if !pin {
                    h.pinned_profiles.retain(|id| *id != profile_id);
                }
                if let Err(e) = known.save() {
                    tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                }
                // `run` refreshes the rows right after this drain, so the carousel and
                // the pin screen reflect the new card within the same service pass.
            }
            ConsoleCmd::BindProfile { key, profile_id } => {
                // The BINDING half of the profile pair — `KnownHost::profile_id`, what a
                // plain A-press on the primary tile connects with. `SetPin` above is the
                // presentation half and never touches this field; this never touches the
                // pins. Same store discipline, same refresh-after-drain.
                let mut known = trust::KnownHosts::load();
                let idx = index_for_key(&known, &key);
                let Some(h) = idx.and_then(|i| known.hosts.get_mut(i)) else {
                    tracing::warn!(%key, "profile bind for an unknown host — ignoring");
                    return;
                };
                if h.profile_id != profile_id {
                    h.profile_id = profile_id;
                    if let Err(e) = known.save() {
                        tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                    }
                }
            }
            ConsoleCmd::SetClipboard { key, on } => {
                // Per-host clipboard trust (`KnownHost::clipboard_sync`) — the host
                // menu's toggle. Same store discipline as the two arms above.
                let mut known = trust::KnownHosts::load();
                let idx = index_for_key(&known, &key);
                let Some(h) = idx.and_then(|i| known.hosts.get_mut(i)) else {
                    tracing::warn!(%key, "clipboard toggle for an unknown host — ignoring");
                    return;
                };
                if h.clipboard_sync != on {
                    h.clipboard_sync = on;
                    if let Err(e) = known.save() {
                        tracing::warn!(error = %format!("{e:#}"), "saving known hosts");
                    }
                }
            }
        }
    }

    /// One parallel reachability pass over every non-advertising row (advertising ones
    /// are online by definition). Runs on its own thread; at most one in flight.
    fn sweep(&self) {
        if self.probe_inflight.swap(true, Ordering::SeqCst) {
            return;
        }
        let targets: Vec<(String, (String, u16))> = self
            .rows()
            .into_iter()
            .filter(|r| !self.advertised(r))
            .map(|r| (r.key.clone(), (r.addr.clone(), r.port)))
            .collect();
        let probed = self.probed.clone();
        let inflight = self.probe_inflight.clone();
        std::thread::Builder::new()
            .name("punktfunk-probe".into())
            .spawn(move || {
                let (keys, addrs): (Vec<_>, Vec<_>) = targets.into_iter().unzip();
                let results = trust::probe_reachable_many(addrs, Duration::from_millis(900));
                let mut map = probed.lock().unwrap();
                for (key, ok) in keys.into_iter().zip(results) {
                    map.insert(key, ok);
                }
                inflight.store(false, Ordering::SeqCst);
            })
            .ok();
    }

    fn advertised(&self, row: &HostRow) -> bool {
        self.discovered.values().any(|d| {
            (!row.fp_hex.is_empty() && d.fp_hex == row.fp_hex)
                || (d.addr == row.addr && d.port == row.port)
        })
    }

    /// The console home's rows: saved hosts (most recent first) — each followed by its
    /// pinned profile cards (design §5.2a) — then discovered-but-unsaved ones, then a
    /// still-uncovered `--browse` seed.
    fn rows(&self) -> Vec<HostRow> {
        let known = trust::KnownHosts::load();
        let catalog = pf_client_core::profiles::ProfilesFile::load();
        let probed = self.probed.lock().unwrap();
        let chip = |p: &pf_client_core::profiles::StreamProfile| pf_console_ui::ProfileChip {
            id: p.id.clone(),
            name: p.name.clone(),
            accent: p.accent.clone(),
        };
        // Primary rows paired with their pinned cards, so the sort below can order hosts
        // while every host's cards stay glued behind its primary tile.
        let mut saved: Vec<(HostRow, Vec<HostRow>)> = known
            .hosts
            .iter()
            .map(|h| {
                let key = if h.fp_hex.is_empty() {
                    format!("{}:{}", h.addr, h.port)
                } else {
                    h.fp_hex.clone()
                };
                let advert = self.discovered.values().find(|d| {
                    (!h.fp_hex.is_empty() && d.fp_hex == h.fp_hex)
                        || (d.addr == h.addr && d.port == h.port)
                });
                let online = advert.is_some() || probed.get(&key).copied().unwrap_or(false);
                // Write down everything the advert teaches while the host is visible: the mgmt
                // port (so this console keeps working against a moved one once it is not), the
                // OS chain, and the wake MAC — which matters most here, because this console and
                // the Decky panel are the only surfaces a Deck in Gaming Mode ever runs, and a
                // record that never learned a MAC can never be woken. No-op (and no disk write)
                // when unchanged, so this is safe on every refresh tick.
                if let Some(a) = advert {
                    pf_client_core::trust::learn_from_advert(
                        &h.fp_hex,
                        &h.addr,
                        h.port,
                        &a.mac,
                        &a.os,
                        a.mgmt_port,
                    );
                }
                let row = HostRow {
                    key: key.clone(),
                    name: host_display_name(&h.name, &h.addr),
                    addr: h.addr.clone(),
                    port: h.port,
                    fp_hex: h.fp_hex.clone(),
                    paired: h.paired,
                    saved: true,
                    online,
                    // Live advert first, then what we saved from an earlier one, then 47990 —
                    // the same three rungs `os` uses just below. Reading the advert ALONE is why
                    // a host on a moved mgmt port lost its library the moment mDNS went quiet.
                    mgmt_port: advert
                        .and_then(|d| d.mgmt_port)
                        .or(h.mgmt_port)
                        .unwrap_or(library::DEFAULT_MGMT_PORT),
                    can_wake: !online && !h.mac.is_empty(),
                    clipboard_sync: h.clipboard_sync,
                    last_used: h.last_used,
                    os: advert
                        .filter(|d| !d.os.is_empty())
                        .map(|d| d.os.clone())
                        .unwrap_or_else(|| h.os.clone()),
                    pin: None,
                    bound_profile: h
                        .profile_id
                        .as_deref()
                        .and_then(|id| catalog.find_by_id(id))
                        .map(chip),
                };
                // A pinned card shares the primary tile's live state; its key rides the
                // profile id behind a NUL (impossible in a fingerprint or `addr:port`),
                // so cursor-follow and the wake path address the card itself.
                let pins = h
                    .resolved_pins(&catalog)
                    .into_iter()
                    .map(|p| HostRow {
                        key: format!("{key}\0{}", p.id),
                        pin: Some(chip(p)),
                        bound_profile: None,
                        ..row.clone()
                    })
                    .collect();
                (row, pins)
            })
            .collect();
        saved.sort_by(|(a, _), (b, _)| b.last_used.cmp(&a.last_used).then(a.name.cmp(&b.name)));
        let mut rows: Vec<HostRow> = saved
            .into_iter()
            .flat_map(|(row, pins)| std::iter::once(row).chain(pins))
            .collect();

        let mut extra: Vec<HostRow> = self
            .discovered
            .values()
            .filter(|d| {
                !known.hosts.iter().any(|h| {
                    (!h.fp_hex.is_empty() && h.fp_hex == d.fp_hex)
                        || (h.addr == d.addr && h.port == d.port)
                })
            })
            .map(|d| HostRow {
                key: if d.fp_hex.is_empty() {
                    format!("{}:{}", d.addr, d.port)
                } else {
                    d.fp_hex.clone()
                },
                name: host_display_name(&d.name, &d.addr),
                addr: d.addr.clone(),
                port: d.port,
                fp_hex: d.fp_hex.clone(),
                paired: false,
                saved: false,
                online: true,
                mgmt_port: d.mgmt_port.unwrap_or(library::DEFAULT_MGMT_PORT),
                can_wake: false,
                clipboard_sync: false,
                last_used: None,
                os: d.os.clone(),
                pin: None,
                bound_profile: None,
            })
            .collect();
        extra.sort_by(|a, b| a.name.cmp(&b.name));
        rows.extend(extra);

        if let Some(seed) = &self.seed {
            if !rows
                .iter()
                .any(|r| r.addr == seed.addr && r.port == seed.port)
            {
                let mut seed = seed.clone();
                seed.online = probed.get(&seed.key).copied().unwrap_or(false);
                rows.push(seed);
            }
        }
        rows
    }
}

/// The wake-and-wait loop (one per wake): re-send the magic packet every 6 s, probe the
/// host once a second, 90 s timeout — the Apple `HostWaker`'s cadence. The thread owns
/// the model's wake status; the shell reads `online`/`timed_out` and acts.
fn spawn_wake(
    console: ConsoleShared,
    row: HostRow,
    macs: Vec<String>,
    then_connect: bool,
    cancel: Arc<AtomicBool>,
) {
    std::thread::Builder::new()
        .name("punktfunk-wake".into())
        .spawn(move || {
            let last_ip = row.addr.parse::<Ipv4Addr>().ok();
            let started = Instant::now();
            let mut last_packet: Option<Instant> = None;
            loop {
                if cancel.load(Ordering::SeqCst) {
                    console.set_wake(None);
                    return;
                }
                let elapsed = started.elapsed();
                let timed_out = elapsed >= Duration::from_secs(90);
                if !timed_out && last_packet.is_none_or(|t| t.elapsed() >= Duration::from_secs(6)) {
                    wol::wake(&macs, last_ip);
                    last_packet = Some(Instant::now());
                }
                let online = trust::probe_reachable_many(
                    vec![(row.addr.clone(), row.port)],
                    Duration::from_millis(900),
                )
                .first()
                .copied()
                .unwrap_or(false);
                console.set_wake(Some(WakeStatus {
                    key: row.key.clone(),
                    name: row.name.clone(),
                    seconds: elapsed.as_secs() as u32,
                    timed_out,
                    online,
                    then_connect,
                }));
                if online || timed_out {
                    // Awake → the shell connects and cancels; timed out → the card
                    // waits for Try Again / Cancel. Either way this thread is done —
                    // a retry spawns a fresh one.
                    return;
                }
                std::thread::sleep(Duration::from_millis(1000));
            }
        })
        .ok();
}

/// How long to keep asking a host we have just sent a magic packet to. A cold box takes
/// 20–60 s to POST and start serving, so one attempt would almost always land on a machine
/// that is still booting — the same 90-second budget `spawn_wake` allows.
const WAKE_ATTEMPTS: u32 = 12;
const WAKE_RETRY_EVERY: Duration = Duration::from_secs(5);
/// Re-send the magic packet this often while retrying. A single packet can be missed, and some
/// NICs only wake on a fresh one after dropping into a deeper sleep state — `spawn_wake`'s rule,
/// expressed in this loop's units (every other attempt ≈ every 10 s).
const WAKE_RESEND_EVERY: u32 = 2;

/// Fetch the library off the service thread, then stream poster art into the shared
/// model as results land (the renderer drains `push_art` per frame).
///
/// Three things happen before the host is ever asked, and the order is the point:
/// 1. the CACHED catalog goes up immediately, marked stale — a library is the screen a player
///    uses to decide what to play, and an empty one while a sleeping box boots is the opposite
///    of useful;
/// 2. a magic packet goes out, so the box warms while they are still choosing;
/// 3. only then does the live fetch start, retrying across the boot window.
///
/// A cached catalog also outranks a failure: if the host never answers, the titles on screen are
/// still the right ones to choose from, and replacing them with a red error because a box is
/// asleep is precisely what the cache exists to prevent.
fn spawn_fetch(
    shared: LibraryShared,
    addr: String,
    mgmt: u16,
    identity: (String, String),
    fp_hex: String,
    pin: Option<[u8; 32]>,
    macs: Vec<String>,
) {
    // `begin_fetch`, not `set_phase(Loading)`: it also advances the model's fetch epoch, which
    // is how a shelf pushed a moment ago knows the titles it is about to see are its own rather
    // than the previous host's. A cached catalog can land within a millisecond of this, so there
    // is no phase transition for anyone to observe.
    shared.begin_fetch();
    std::thread::Builder::new()
        .name("punktfunk-library".into())
        .spawn(move || {
            if let Ok(path) = std::env::var("PUNKTFUNK_FAKE_LIBRARY") {
                load_fake(&shared, &path);
                return;
            }
            // Whatever we already know about this host, on screen before a single packet goes
            // out. Keyed on the pinned fingerprint, so a box that came back on a new DHCP lease
            // is still recognised as the same host with the same library.
            let mut have_cached = false;
            if let Some(cached) = pf_client_core::library_cache::load(&fp_hex) {
                if !cached.games.is_empty() {
                    have_cached = true;
                    shared.set_games_cached(to_model(&cached.games));
                }
            }
            // Fire-and-forget, and deliberately unconditional rather than only when the host
            // looks offline: a magic packet is one datagram that an already-awake machine
            // ignores, so finding out whether it is needed costs more than sending it.
            let waking = !macs.is_empty();
            let last_ip = addr.parse::<Ipv4Addr>().ok();
            if waking {
                wol::wake(&macs, last_ip);
            }

            let attempts = if waking { WAKE_ATTEMPTS } else { 1 };
            let mut last_err = None;
            let mut fetched = None;
            for attempt in 0..attempts {
                match library::fetch_games(&addr, mgmt, &identity, pin) {
                    Ok(games) => {
                        fetched = Some(games);
                        break;
                    }
                    Err(e) => {
                        // Anything other than "can't reach it" is settled — a rejected
                        // certificate does not become acceptable by waiting, and retrying an
                        // unpaired host twelve times only delays telling the user what is
                        // actually wrong.
                        let retryable = matches!(e, library::LibraryError::Unreachable(_));
                        last_err = Some(e);
                        if !retryable || attempt + 1 >= attempts {
                            break;
                        }
                        if attempt % WAKE_RESEND_EVERY == WAKE_RESEND_EVERY - 1 {
                            wol::wake(&macs, last_ip);
                        }
                        std::thread::sleep(WAKE_RETRY_EVERY);
                    }
                }
            }

            let Some(games) = fetched else {
                let e = last_err.expect("the loop runs at least once and every miss records why");
                if have_cached {
                    // The shelf stays; only the words change. The player can still pick a title
                    // — the launch will wake and dial the host on its own.
                    tracing::info!(%addr, error = %e, "library fetch failed; keeping the cached shelf");
                    shared.set_stale(pf_console_ui::Stale::Offline);
                } else {
                    shared.set_phase(LibraryPhase::Error {
                        title: "Couldn't load the library".into(),
                        body: e.to_string(),
                        can_retry: true,
                    });
                }
                return;
            };

            let base = library::base_url(&addr, mgmt);
            let jobs: VecDeque<(String, Vec<String>)> = games
                .iter()
                .map(|g| (g.id.clone(), g.art.poster_candidates(&base)))
                .filter(|(_, candidates)| !candidates.is_empty())
                .collect();
            shared.set_games(to_model(&games));
            // Remembered AFTER it is on screen: the disk write is not on the path to a shelf.
            pf_client_core::library_cache::store(&fp_hex, &games);
            // What the host has up right now, so a title the player can return to says so.
            // Deliberately after the catalog — a slow `/status` must not hold the titles back —
            // and never fatal: an older host answers nothing and every badge simply stays off.
            shared.set_running(&running_ids(&addr, mgmt, &identity, pin));
            if !jobs.is_empty() {
                let rx = library::spawn_art_fetch(base, identity, pin, jobs);
                while let Ok((id, bytes)) = rx.recv_blocking() {
                    shared.push_art(id, bytes);
                }
            }
        })
        .ok();
}

/// The wire catalog in the shell's own terms.
///
/// One conversion, because there are now three callers (a live fetch, a cached one and the dev
/// hook) and a fourth that quietly dropped a field would be a shelf missing its launcher grouping
/// or its platform line on one path only.
///
/// `running` is deliberately NOT derived here: it is host state that arrives from `/status`,
/// separately and later, and the catalog this reads from is the same shape that gets written to
/// the disk cache. Seeding it from a catalog would be how a cached shelf comes back claiming a
/// game is up because it was up the last time anybody looked.
fn to_model(games: &[library::GameEntry]) -> Vec<LibraryGame> {
    games
        .iter()
        .map(|g| LibraryGame {
            id: g.id.clone(),
            title: g.title.clone(),
            store: g.store.clone(),
            launcher: g.is_launcher(),
            icon: g.icon_token().unwrap_or_default().to_string(),
            platform: g.platform.clone(),
            running: false,
        })
        .collect()
}

/// Which library ids the host has up right now — the Resume set.
///
/// Best-effort by contract (see [`library::fetch_running`]): an older host, an unreachable one or
/// a shape we don't recognise yields an empty set, which correctly clears every badge rather than
/// failing anything. Entries with no `app_id` — an operator-typed GameStream command — are dropped:
/// there is no catalog entry to badge.
fn running_ids(
    addr: &str,
    mgmt: u16,
    identity: &(String, String),
    pin: Option<[u8; 32]>,
) -> std::collections::HashSet<String> {
    library::fetch_running(addr, mgmt, identity, pin)
        .into_iter()
        .filter(|g| g.is_up())
        .filter_map(|g| g.app_id)
        .collect()
}

/// Dev hook: entries from a JSON file; portrait paths starting with `/` load from disk.
fn load_fake(shared: &LibraryShared, path: &str) {
    let games: Vec<library::GameEntry> = std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    for g in &games {
        if let Some(p) = g.art.portrait.as_deref().filter(|p| p.starts_with('/')) {
            if let Ok(bytes) = std::fs::read(p) {
                shared.push_art(g.id.clone(), bytes);
            }
        }
    }
    shared.set_games(to_model(&games));
}
