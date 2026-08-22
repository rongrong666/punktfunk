//! The shell↔session handoff: streams run in the spawned `punktfunk-session` Vulkan
//! binary (session-always, mirroring the GTK shell's `clients/linux/src/spawn.rs`). This
//! module owns the child's lifecycle plumbing — spawned with CREATE_NO_WINDOW (the
//! session keeps the console subsystem for its stdout contract; without the flag a GUI
//! parent would pop a console window), its stdout contract parsed into typed
//! [`SpawnEvent`]s a reader thread hands to the app's navigation closure: spinner until
//! `{"ready":true}`, banner from the `{"error"|"ended": …}` line, `trust_rejected`
//! routed to the re-pair PIN ceremony, `stats:` lines to the session status page.

use std::io::BufRead as _;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

/// One parsed event from the session child.
pub(crate) enum SpawnEvent {
    /// The child presented its first frame (its window is up and streaming).
    Ready,
    /// One `stats:` line, already human-formatted by the session (per 1 s window).
    Stats(String),
    /// The child exited (stdout EOF + reap; a kill lands here too). `error`/`ended`
    /// carry the contract lines seen on the way out, when any — routing keys off those,
    /// which say strictly more than a number. `code` is the process exit status (-1 = no
    /// code, i.e. killed) and exists for the case where there were NO lines at all: a
    /// child that dies before it can speak the contract would otherwise be indistinguishable
    /// from a clean user-initiated quit, and the shell would bounce to the host list with a
    /// blank banner. That is exactly how the 0.22.0 session-binary regression presented.
    Exited {
        error: Option<(String, bool)>,
        ended: Option<String>,
        code: i32,
    },
}

/// Kills the spawned session child (the Disconnect button, request-access Cancel). Safe
/// to call any time; a child that already exited is a no-op. A FRESH handle is installed
/// per spawn (`Shared::session`) so a stale handle can never kill a newer session.
#[derive(Clone, Default)]
pub(crate) struct SessionChild(Arc<Mutex<Option<Child>>>);

impl SessionChild {
    pub(crate) fn kill(&self) {
        if let Some(child) = self.0.lock().unwrap().as_mut() {
            let _ = child.kill();
        }
    }

    /// Whether a spawned child is currently live (spawned and not yet reaped by its
    /// reader). The probe sweep pauses while one runs — the shell is hidden, and probing
    /// the host we're streaming from is just noise.
    pub(crate) fn is_running(&self) -> bool {
        self.0.lock().unwrap().is_some()
    }
}

/// One parsed stdout line of the session contract; `None` for anything unrecognized.
enum ChildLine {
    Ready,
    Error {
        msg: String,
        trust_rejected: bool,
    },
    Ended(String),
    Stats(String),
    /// The session window's logical size settled here under match-window — the SPAWNER
    /// persists it (design/client-architecture-split.md §5). This shell ignored the line
    /// until 2026-07-31, so its sessions fell back to persisting from the renderer.
    Window {
        w: u32,
        h: u32,
    },
}

fn parse_line(line: &str) -> Option<ChildLine> {
    if let Some(stats) = line.strip_prefix("stats: ") {
        return Some(ChildLine::Stats(stats.to_string()));
    }
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("ready").and_then(|r| r.as_bool()) == Some(true) {
        return Some(ChildLine::Ready);
    }
    if let Some(msg) = v.get("error").and_then(|m| m.as_str()) {
        return Some(ChildLine::Error {
            msg: msg.to_string(),
            trust_rejected: v.get("trust_rejected").and_then(|t| t.as_bool()) == Some(true),
        });
    }
    if let Some(msg) = v.get("ended").and_then(|m| m.as_str()) {
        return Some(ChildLine::Ended(msg.to_string()));
    }
    if let Some(win) = v.get("window") {
        let dim = |k: &str| win.get(k).and_then(|n| n.as_u64()).map(|n| n as u32);
        if let (Some(w), Some(h)) = (dim("w"), dim("h")) {
            return Some(ChildLine::Window { w, h });
        }
    }
    None
}

/// The banner for a child that exited having said NOTHING on stdout — no `ready`, no
/// `error`, no `ended`. `None` keeps the silent return the UI has always given a clean
/// quit: code 0 is the user closing the stream window, and -1 is our own Disconnect/Cancel
/// kill (no exit code). Anything else is the session dying before it could speak its
/// contract — a missing runtime DLL, a crash, or the wrong binary sitting next to the
/// shell — and reporting the code is the difference between a diagnosable failure and a
/// connect that silently drops back to the host list.
pub(crate) fn silent_exit_banner(code: i32) -> Option<String> {
    (code != 0 && code != -1).then(|| {
        // Name the log's actual location — "check the client log" without a path is a
        // scavenger hunt (Settings ▸ About's "Open log folder" reaches it too).
        let log = crate::logfile::path()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "客户端日志".into());
        format!(
            "会话未能启动（punktfunk-session 退出，代码 {code}）。请查看 {log}。"
        )
    })
}

/// The session binary: installed next to the shell (the MSIX layout and dev
/// `target\…` runs both land on the sibling), else `PATH`.
pub(crate) fn session_binary() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("punktfunk-session.exe");
        if sibling.exists() {
            return sibling;
        }
    }
    "punktfunk-session".into()
}

/// Spawn the session binary for a connect with `fp_hex` pinned and feed its lifecycle to
/// `on_event` from a reader thread. The child is parked in `slot` so Disconnect/Cancel
/// can kill it. `launch` carries a library title id for the host to launch during the
/// handshake; `profile` is a ONE-OFF settings-profile pick. `Err` = the spawn itself
/// failed (binary missing?) — surfaced as a connect error by the caller.
///
/// The argv and the `--resolved-spec` both come from the shared brain
/// ([`ConnectPlan::for_target`] → `session_args()` + `spec()`): this shell hand-assembled
/// its argv until 2026-07-31, which meant no spec — its sessions took the compat path and
/// re-resolved every setting from the stores (the drift `orchestrate.rs` documents as a
/// trap), and any field added to the spec was silently Windows-dead. Fullscreen now also
/// comes from the plan's EFFECTIVE settings (profile-aware) instead of a caller argument.
#[allow(clippy::too_many_arguments)] // one cohesive spawn spec (session_params precedent)
pub(crate) fn spawn_session(
    addr: &str,
    port: u16,
    fp_hex: &str,
    connect_timeout_secs: u64,
    launch: Option<&str>,
    profile: Option<&str>,
    slot: SessionChild,
    on_event: impl FnMut(SpawnEvent) + Send + 'static,
) -> Result<(), String> {
    use pf_client_core::orchestrate::{ConnectPlan, HostTarget};
    let mut plan = ConnectPlan::for_target(
        HostTarget {
            name: String::new(), // display-only; this shell's screens carry their own copy
            addr: addr.to_string(),
            port,
            // A pending placeholder is not a pin: pass no --fp for it.
            fp_hex: (!fp_hex.is_empty() && !crate::trust::is_pending_fp(fp_hex))
                .then(|| fp_hex.to_string()),
            mac: Vec::new(), // wake ran before this spawn (initiate_waking) — not the plan's job
            id: None,
            mgmt_port: None, // the library fetch runs in the shell (`Target`), never off a spawn plan
            wg: None, // resolved from the stored record inside `for_target`
        },
        launch.map(str::to_string),
        profile.map(str::to_string),
    );
    plan.connect_timeout_secs = Some(connect_timeout_secs);
    let mut cmd = Command::new(session_binary());
    let mut args = plan.session_args();
    // Spec mode (design/client-architecture-split.md §5): the child reads no stores and
    // cannot disagree with us about a file either of us might write. A spec we fail to
    // write is not fatal — the compat path resolves the same values via the same helper.
    let spec_path = match plan.spec(plan.clipboard).write_temp() {
        Ok(path) => {
            args.push("--resolved-spec".into());
            args.push(path.to_string_lossy().into_owned());
            Some(path)
        }
        Err(e) => {
            tracing::warn!(error = %e, "couldn't write the resolved spec; the session will resolve for itself");
            None
        }
    };
    cmd.args(args);
    add_window_pos(&mut cmd);
    spawn_with(cmd, &format!("{addr}:{port}"), spec_path, slot, on_event)
}

/// Spawn the session binary in `--browse` mode: the console (gamepad) library for a
/// PAIRED host, in the session window — launches run as streams in that same window.
/// The same stdout contract as a connect (`--json-status`): `ready` when the library
/// window presents, `error` on a failed start, EOF on quit.
pub(crate) fn spawn_browse(
    target: Option<(&str, u16)>,
    fullscreen: bool,
    slot: SessionChild,
    on_event: impl FnMut(SpawnEvent) + Send + 'static,
) -> Result<(), String> {
    let mut cmd = Command::new(session_binary());
    cmd.arg("--browse");
    // A target opens straight into that host's library; bare `--browse` opens the console's
    // OWN host view (discovery, pairing, settings, Wake-on-LAN) — the couch equivalent of
    // the shell's hosts page.
    if let Some((addr, port)) = target {
        cmd.arg(format!("{addr}:{port}"));
    }
    cmd.arg("--json-status");
    if fullscreen {
        cmd.arg("--fullscreen");
    }
    add_window_pos(&mut cmd);
    let label = target.map_or_else(|| "console".to_string(), |(a, p)| format!("{a}:{p}"));
    spawn_with(cmd, &label, None, slot, on_event)
}

/// Hand the shell window's position to the child (`--window-pos`) so the session window
/// opens on the same monitor, where the shell is — the hide/restore handoff then reads as
/// one window changing content instead of a window jumping displays.
fn add_window_pos(cmd: &mut Command) {
    if let Some((x, y)) = crate::shell_window::position() {
        cmd.arg("--window-pos").arg(format!("{x},{y}"));
    }
}

/// The shared spawn + stdout-contract reader behind [`spawn_session`]/[`spawn_browse`].
/// `spec_path` is the child's `--resolved-spec` temp file, deleted once the child exits.
fn spawn_with(
    mut cmd: Command,
    host_label: &str,
    spec_path: Option<std::path::PathBuf>,
    slot: SessionChild,
    mut on_event: impl FnMut(SpawnEvent) + Send + 'static,
) -> Result<(), String> {
    use std::os::windows::process::CommandExt as _;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;

    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Piped through the log tee: dev-terminal runs keep the interleaved stderr they always
        // had, and GUI runs — which have no console — finally keep the session's whole
        // receive/decode/present log in the client log file.
        .stderr(Stdio::piped())
        .creation_flags(CREATE_NO_WINDOW);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("无法启动 punktfunk-session：{e}"))?;
    tracing::info!(host = %host_label, "session binary spawned");

    if let Some(stderr) = child.stderr.take() {
        crate::logfile::forward_child_stderr(stderr);
    }
    let stdout = child.stdout.take().expect("piped stdout");
    // Park the child where the kill handle (and the reader, for the final reap) reach it.
    *slot.0.lock().unwrap() = Some(child);

    std::thread::Builder::new()
        .name("punktfunk-session-io".into())
        .spawn(move || {
            let mut error: Option<(String, bool)> = None;
            let mut ended: Option<String> = None;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                match parse_line(&line) {
                    Some(ChildLine::Ready) => on_event(SpawnEvent::Ready),
                    Some(ChildLine::Stats(s)) => on_event(SpawnEvent::Stats(s)),
                    Some(ChildLine::Error {
                        msg,
                        trust_rejected,
                    }) => error = Some((msg, trust_rejected)),
                    Some(ChildLine::Ended(msg)) => ended = Some(msg),
                    // The window size is the spawner's to persist — the renderer only
                    // reports it (same handling as orchestrate's own reader).
                    Some(ChildLine::Window { w, h }) => {
                        pf_client_core::orchestrate::persist_window_size(w, h);
                    }
                    None => {}
                }
            }
            // The spec has done its job the moment the child has read it; a leftover temp
            // file in %TEMP% is litter, and one per launch adds up.
            if let Some(path) = &spec_path {
                let _ = std::fs::remove_file(path);
            }
            // EOF — reap the child (killed-by-Disconnect lands here too; -1 = no code).
            let code = slot
                .0
                .lock()
                .unwrap()
                .take()
                .and_then(|mut c| c.wait().ok())
                .and_then(|s| s.code())
                .unwrap_or(-1);
            tracing::info!(code, "session binary exited");
            on_event(SpawnEvent::Exited { error, ended, code });
        })
        .map_err(|e| format!("session reader thread: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_stdout_contract() {
        assert!(matches!(
            parse_line("{\"ready\":true}"),
            Some(ChildLine::Ready)
        ));
        match parse_line("{\"error\":\"no route\",\"trust_rejected\":false}") {
            Some(ChildLine::Error {
                msg,
                trust_rejected,
            }) => {
                assert_eq!(msg, "no route");
                assert!(!trust_rejected);
            }
            _ => panic!("error line"),
        }
        match parse_line("{\"error\":\"pin\",\"trust_rejected\":true}") {
            Some(ChildLine::Error { trust_rejected, .. }) => assert!(trust_rejected),
            _ => panic!("trust line"),
        }
        match parse_line("{\"ended\":\"Host ended the session\"}") {
            Some(ChildLine::Ended(m)) => assert_eq!(m, "Host ended the session"),
            _ => panic!("ended line"),
        }
        // Stats lines become Stats events; stray output never becomes an event.
        match parse_line("stats: 1280\u{00D7}800@60 \u{00B7} 60 fps") {
            Some(ChildLine::Stats(s)) => assert!(s.starts_with("1280")),
            _ => panic!("stats line"),
        }
        // The match-window report: the SPAWNER persists it (§5) — dropping this line was
        // why Windows sessions fell back to renderer-local persistence.
        match parse_line("{\"window\":{\"w\":1600,\"h\":900}}") {
            Some(ChildLine::Window { w, h }) => assert_eq!((w, h), (1600, 900)),
            _ => panic!("window line"),
        }
        assert!(parse_line("").is_none());
        assert!(parse_line("{\"other\":1}").is_none());
    }

    #[test]
    fn a_silent_failing_exit_is_never_blank() {
        // Clean quit (stream window closed) and our own kill stay silent.
        assert!(silent_exit_banner(0).is_none());
        assert!(silent_exit_banner(-1).is_none());
        // A child that died without speaking the contract names its code — the 0.22.0
        // regression (a stub session binary exiting 2) showed as a blank bounce to the
        // host list precisely because nothing filled this in.
        let banner = silent_exit_banner(2).expect("failing exit must say something");
        assert!(banner.contains('2'), "{banner}");
        assert!(silent_exit_banner(101).is_some());
    }
}
