//! Host status model + the poller thread feeding the platform tray implementations.
//!
//! Two sources, service manager FIRST: the SCM (Windows) / systemd user unit (Linux) decides
//! stopped-vs-running — a malicious local process squatting the mgmt port while the service is
//! down can never make the tray say Running. Only when the service manager reports Running does
//! the poller consult the host's loopback-only `GET /api/v1/local/summary` for streaming detail.

use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// What the service manager reports for the host service.
#[derive(Clone, Debug, PartialEq)]
pub enum ServiceState {
    NotInstalled,
    Stopped,
    StartPending,
    StopPending,
    Running,
    /// Linux `ActiveState=failed` (with the sub-state), or a Windows stop with a failure exit code.
    Failed(String),
}

/// `GET /api/v1/local/summary` — the non-sensitive counts/booleans the host serves to loopback
/// peers without authentication (mgmt.rs `LocalSummary`). Unknown fields are ignored so a newer
/// host can grow the summary without breaking an older tray.
#[derive(Clone, Debug, PartialEq, serde::Deserialize)]
pub struct Summary {
    pub version: String,
    pub video_streaming: bool,
    pub audio_streaming: bool,
    pub session: Option<SessionInfo>,
    /// Display name of the streaming client (trust-store name, else the device's own), for the
    /// connect toast. `#[serde(default)]`: absent when idle, nameless, or from an older host.
    #[serde(default)]
    pub client_name: Option<String>,
    pub paired_clients: u32,
    pub native_paired_clients: u32,
    pub pin_pending: bool,
    pub pending_approvals: u32,
    /// Virtual displays kept with no live session (lingering/pinned). `#[serde(default)]` so an older
    /// host that doesn't send it deserializes as 0.
    #[serde(default)]
    pub kept_displays: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, serde::Deserialize)]
pub struct SessionInfo {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
}

/// What the icon shows.
#[derive(Clone, Debug, PartialEq)]
pub enum TrayStatus {
    NotInstalled,
    Stopped,
    /// Service starting, or running with the mgmt API not answering yet (within [`START_GRACE`]).
    Starting,
    Running(Summary),
    /// Service running but the summary unreachable past the grace period — amber, not red: a
    /// custom `PUNKTFUNK_HOST_CMD` (no mgmt API) or a relocated `--mgmt-bind` is legitimate.
    Degraded,
    Error(String),
}

impl TrayStatus {
    /// One-line headline for the tooltip / the disabled menu header.
    pub fn headline(&self) -> String {
        match self {
            TrayStatus::NotInstalled => "punktfunk 主机——未安装".into(),
            TrayStatus::Stopped => "punktfunk 主机——已停止".into(),
            TrayStatus::Starting => "punktfunk 主机——正在启动…".into(),
            TrayStatus::Degraded => "punktfunk 主机——运行中（状态不可用）".into(),
            TrayStatus::Error(e) => format!("punktfunk 主机——故障（{e}）"),
            TrayStatus::Running(s) => match (&s.session, self.is_streaming()) {
                (Some(sess), true) => format!(
                    "punktfunk 主机 {}——正在串流 {}×{}@{}",
                    s.version, sess.width, sess.height, sess.fps
                ),
                (_, true) => format!("punktfunk 主机 {}——正在串流", s.version),
                // Idle, but surface a kept (lingering/pinned) display: it — and, under an
                // exclusive topology, your physical monitors — is being held. Release it from
                // the console.
                _ if s.kept_displays > 0 => format!(
                    "punktfunk 主机 {}——空闲 · 保留 {} 个显示器",
                    s.version,
                    s.kept_displays
                ),
                _ => format!("punktfunk 主机 {}——空闲", s.version),
            },
        }
    }

    /// A client is streaming: the host's flag, OR a live session in the summary.
    ///
    /// The session is checked too because a host from before the `get_local_summary` fix raised
    /// `video_streaming` from the GameStream plane only — through a whole session on the native
    /// (default) plane it said false while still reporting that session's mode, which is what left
    /// the tray sitting at "idle" mid-stream. This keeps a newer tray honest against such a host.
    pub fn is_streaming(&self) -> bool {
        matches!(self, TrayStatus::Running(s) if s.video_streaming || s.session.is_some())
    }

    /// Virtual displays held with no live session (lingering/pinned) — offered as a one-click
    /// release in the menu, since holding one can also be keeping physical monitors dark.
    pub fn kept_displays(&self) -> u32 {
        match self {
            TrayStatus::Running(s) => s.kept_displays,
            _ => 0,
        }
    }

    /// A pairing attempt is waiting on the operator (shown as an extra menu entry).
    pub fn pairing_attention(&self) -> bool {
        matches!(self, TrayStatus::Running(s) if s.pin_pending || s.pending_approvals > 0)
    }
}

/// How long a running service may leave the summary unreachable before Starting turns Degraded.
/// Also re-applied mid-life: the SYSTEM supervisor relaunching a crashed host child looks like
/// "running, briefly unreachable" — that shows as Starting again, not an alarming flicker to red.
pub const START_GRACE: Duration = Duration::from_secs(15);

/// Pure status mapping (unit-tested): service-manager state first, summary second, grace third.
pub fn map_status(svc: &ServiceState, summary: Option<Summary>, grace_expired: bool) -> TrayStatus {
    match svc {
        ServiceState::NotInstalled => TrayStatus::NotInstalled,
        ServiceState::Stopped | ServiceState::StopPending => TrayStatus::Stopped,
        ServiceState::StartPending => TrayStatus::Starting,
        ServiceState::Failed(e) => TrayStatus::Error(e.clone()),
        ServiceState::Running => match summary {
            Some(s) => TrayStatus::Running(s),
            None if !grace_expired => TrayStatus::Starting,
            None => TrayStatus::Degraded,
        },
    }
}

// ── Poller ──────────────────────────────────────────────────────────────────────────────────────

pub struct Poller {
    shared: Arc<Shared>,
}

struct Shared {
    poked: Mutex<bool>,
    cv: Condvar,
}

impl Poller {
    /// Spawn the poll thread; `on_change(status, console_up)` fires (from that thread) whenever
    /// either changes. `console_up` is a live loopback probe of the web console on `web_port`. It
    /// annotates the "Open web console" entry ("not responding") rather than hiding it: the entry
    /// is the tray's most-wanted action, and a menu that silently drops it — because the console
    /// was still starting, or the probe timed out — is indistinguishable from a tray that never
    /// had one.
    pub fn spawn(
        mgmt_addr: String,
        mgmt_port: Option<u16>,
        web_port: u16,
        on_change: Box<dyn Fn(TrayStatus, bool) + Send>,
    ) -> Poller {
        let shared = Arc::new(Shared {
            poked: Mutex::new(false),
            cv: Condvar::new(),
        });
        let thread_shared = shared.clone();
        std::thread::Builder::new()
            .name("status-poll".into())
            .spawn(move || poll_loop(&thread_shared, &mgmt_addr, mgmt_port, web_port, on_change))
            .expect("spawn status-poll thread");
        Poller { shared }
    }

    /// Force an immediate re-poll (right after a start/stop/restart menu action).
    pub fn poke(&self) {
        *self.shared.poked.lock().unwrap() = true;
        self.shared.cv.notify_one();
    }
}

fn poll_loop(
    shared: &Shared,
    mgmt_addr: &str,
    mgmt_port: Option<u16>,
    web_port: u16,
    on_change: Box<dyn Fn(TrayStatus, bool) + Send>,
) {
    // Resolved PER TICK, not once: with no `--mgmt-port` the port is whatever the host last
    // published, and a host restarted on a moved `PUNKTFUNK_MGMT_BIND` must not leave the tray
    // polling the old one until the next login. One tiny file read every 3 s is nothing.
    let summary_url = || {
        let port = mgmt_port
            .or_else(pf_paths::published_mgmt_port)
            .unwrap_or(47990);
        // IPv6 literals bracketed, like the Linux client's `base_url`.
        if mgmt_addr.contains(':') {
            format!("https://[{mgmt_addr}]:{port}/api/v1/local/summary")
        } else {
            format!("https://{mgmt_addr}:{port}/api/v1/local/summary")
        }
    };
    // `/login`, not `/`: `/` is auth-gated and 302s to `/login`, and ureq follows redirects by
    // default — so probing `/` spent TLS + `/` + a full cold `/login` SSR render inside one 2 s
    // budget, and a console that was merely warming up read as down. `/login` is the cheapest page
    // that proves the server is answering, and the agent below refuses redirects so the probe is
    // exactly one round trip. (A 302 still counts as up via the `Status` arm in `probe_console`.)
    let console_url = format!("https://127.0.0.1:{web_port}/login");
    let agent = agent(load_pin());
    let mut last: Option<(TrayStatus, bool)> = None;
    // When the summary became unreachable while the service was running (grace anchor).
    // Runs for the process lifetime (the tray exits by process exit; nothing to unwind).
    let mut unreachable_since: Option<Instant> = None;
    // Consecutive failed console probes. One miss is not "down": the console is a bun/Nitro SSR
    // whose cold first render can outrun this agent's 2 s timeout, and a menu entry that changes
    // its label every few seconds reads as broken.
    let mut console_misses = 0u32;
    loop {
        let svc = probe_service();
        let summary = if svc == ServiceState::Running {
            let s = fetch_summary(&agent, &summary_url());
            match s {
                Some(_) => unreachable_since = None,
                None if unreachable_since.is_none() => unreachable_since = Some(Instant::now()),
                None => {}
            }
            s
        } else {
            unreachable_since = None;
            None
        };
        let grace_expired = unreachable_since.is_some_and(|t| t.elapsed() >= START_GRACE);
        let status = map_status(&svc, summary, grace_expired);
        let console_up = if probe_console(&agent, &console_url) {
            console_misses = 0;
            true
        } else {
            console_misses += 1;
            console_misses < 2
        };
        if last.as_ref() != Some(&(status.clone(), console_up)) {
            on_change(status.clone(), console_up);
            last = Some((status, console_up));
        }
        // 3 s while there is anything to watch; back off when the box just doesn't run a host.
        let cadence = match last.as_ref().map(|(s, _)| s) {
            Some(TrayStatus::Stopped) | Some(TrayStatus::NotInstalled) => Duration::from_secs(10),
            _ => Duration::from_secs(3),
        };
        let mut poked = shared.poked.lock().unwrap();
        if !*poked {
            (poked, _) = shared.cv.wait_timeout(poked, cadence).unwrap();
        }
        *poked = false;
    }
}

/// Is the web console answering on loopback? Any HTTP response (incl. the login redirect / 401)
/// counts as up — only a transport failure (nothing listening, TLS handshake dead) means down.
fn probe_console(agent: &ureq::Agent, url: &str) -> bool {
    match agent.get(url).call() {
        Ok(_) => true,
        Err(ureq::Error::StatusCode(..)) => true,
        Err(_) => false,
    }
}

// ── Summary fetch (loopback HTTPS) ──────────────────────────────────────────────────────────────

fn fetch_summary(agent: &ureq::Agent, url: &str) -> Option<Summary> {
    let body = agent
        .get(url)
        .call()
        .ok()?
        .body_mut()
        .read_to_string()
        .ok()?;
    serde_json::from_str(&body).ok()
}

/// The host identity cert's SHA-256, when `cert.pem` is readable (Linux: same-user file). On
/// Windows the file is SYSTEM/Administrators-DACL'd, so the per-user tray can't pin — `None` =
/// accept any cert. That is acceptable here: the connection is loopback, carries no credentials,
/// and only *reads* non-sensitive data; stopped-vs-running is decided by the service manager, so
/// a port-squatter gains nothing but a fake "streaming" tooltip on an already-compromised box.
fn load_pin() -> Option<[u8; 32]> {
    use rustls::pki_types::pem::PemObject;
    let dir = punktfunk_config_dir()?;
    // The mgmt API presents the NATIVE identity when one exists (the identity split —
    // host `crate::identity`); `cert.pem` is the legacy/GameStream identity, still what mgmt
    // serves on hosts that predate the split. Prefer the native cert, fall back to legacy.
    let pem = std::fs::read(dir.join("native-cert.pem"))
        .or_else(|_| std::fs::read(dir.join("cert.pem")))
        .ok()?;
    let der = rustls::pki_types::CertificateDer::from_pem_slice(&pem).ok()?;
    Some(punktfunk_core::tls::cert_fingerprint(der.as_ref()))
}

/// The host's config dir, mirroring `gamestream::config_dir()` without linking the host crate:
/// `PUNKTFUNK_CONFIG_DIR` override, else `$XDG_CONFIG_HOME`/`~/.config` + `punktfunk` (Linux).
/// `None` on Windows — everything the tray would read there is SYSTEM/Admins-DACL'd anyway.
pub fn punktfunk_config_dir() -> Option<std::path::PathBuf> {
    if let Some(d) = std::env::var_os("PUNKTFUNK_CONFIG_DIR") {
        if !d.is_empty() {
            return Some(std::path::PathBuf::from(d));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(x) = std::env::var_os("XDG_CONFIG_HOME") {
            if !x.is_empty() {
                return Some(std::path::PathBuf::from(x).join("punktfunk"));
            }
        }
        std::env::var_os("HOME").map(|h| {
            std::path::PathBuf::from(h)
                .join(".config")
                .join("punktfunk")
        })
    }
    #[cfg(not(target_os = "linux"))]
    None
}

/// A sync HTTPS agent over the same rustls(aws-lc-rs) stack the rest of the workspace uses, with a
/// pin-or-accept-any verifier (the Linux client's `PinVerify` pattern, `library.rs`).
fn agent(pin: Option<[u8; 32]>) -> ureq::Agent {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("rustls default protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(punktfunk_core::tls::PinVerify::new(pin)))
        .with_no_client_auth();
    // ureq's `TlsConfig` cannot install a custom verifier, so the agent wraps this `ClientConfig`
    // directly (the glue lives in punktfunk-core, shared with the desktop client's library fetch).
    punktfunk_core::tls::ureq_agent::agent(
        Arc::new(cfg),
        ureq::Agent::config_builder()
            .timeout_connect(Some(Duration::from_secs(2)))
            .timeout_global(Some(Duration::from_secs(2)))
            // No redirect-following. Neither user of this agent wants it: the summary is a
            // terminal JSON route, and the console probe treats any HTTP answer (302 included) as
            // "up", so chasing the hop only spends the 2 s budget re-rendering a page nobody reads.
            .max_redirects(0)
            .build(),
    )
}

// ── Service-manager probe ───────────────────────────────────────────────────────────────────────

/// The SCM name registered by `punktfunk-host service install` (windows/service.rs SERVICE_NAME).
#[cfg(windows)]
pub const SERVICE_NAME: &str = "PunktfunkHost";

#[cfg(windows)]
pub fn probe_service() -> ServiceState {
    use windows_service::service::{ServiceAccess, ServiceExitCode, ServiceState as Scm};
    use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
    // CONNECT + QUERY_STATUS work unprivileged. Re-opened every poll on purpose: a reinstall
    // (delete + create) invalidates old handles, and this picks the new service up within a poll.
    let Ok(manager) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
    else {
        return ServiceState::NotInstalled;
    };
    let Ok(svc) = manager.open_service(SERVICE_NAME, ServiceAccess::QUERY_STATUS) else {
        return ServiceState::NotInstalled; // ERROR_SERVICE_DOES_NOT_EXIST et al.
    };
    let Ok(status) = svc.query_status() else {
        return ServiceState::NotInstalled;
    };
    match status.current_state {
        Scm::StartPending => ServiceState::StartPending,
        Scm::StopPending => ServiceState::StopPending,
        Scm::Running | Scm::ContinuePending | Scm::PausePending | Scm::Paused => {
            ServiceState::Running
        }
        Scm::Stopped => match status.exit_code {
            // 0 = clean; 1077 = never started since boot (ERROR_SERVICE_NEVER_HAS_BEEN_RUN? no —
            // "no attempts to start have been made"): both are an ordinary Stopped, not a failure.
            ServiceExitCode::Win32(0) | ServiceExitCode::Win32(1077) => ServiceState::Stopped,
            ServiceExitCode::Win32(code) => ServiceState::Failed(format!("exit code {code}")),
            ServiceExitCode::ServiceSpecific(code) => {
                ServiceState::Failed(format!("service error {code}"))
            }
        },
    }
}

/// The systemd user unit the Linux packages install (scripts/punktfunk-host.service).
#[cfg(target_os = "linux")]
pub const UNIT_NAME: &str = "punktfunk-host.service";

#[cfg(target_os = "linux")]
pub fn probe_service() -> ServiceState {
    // `systemctl show` exits 0 even for unknown units (LoadState=not-found) — parse, don't rely
    // on the exit code.
    let Ok(out) = std::process::Command::new("systemctl")
        .args([
            "--user",
            "show",
            UNIT_NAME,
            "--property=LoadState,ActiveState,SubState",
        ])
        .output()
    else {
        return ServiceState::NotInstalled; // no systemctl → nothing to watch
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let prop = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or("")
            .to_string()
    };
    if prop("LoadState") == "not-found" {
        return ServiceState::NotInstalled;
    }
    match prop("ActiveState").as_str() {
        "active" | "reloading" => ServiceState::Running,
        "activating" => ServiceState::StartPending,
        "deactivating" => ServiceState::StopPending,
        "failed" => ServiceState::Failed(prop("SubState")),
        _ => ServiceState::Stopped, // "inactive" and anything new
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(streaming: bool) -> Summary {
        Summary {
            version: "0.5.1".into(),
            video_streaming: streaming,
            audio_streaming: streaming,
            session: streaming.then_some(SessionInfo {
                width: 2560,
                height: 1440,
                fps: 120,
            }),
            client_name: streaming.then(|| "studio-deck".into()),
            paired_clients: 1,
            native_paired_clients: 2,
            pin_pending: false,
            pending_approvals: 0,
            kept_displays: 0,
        }
    }

    /// The full (service state × summary × grace) table.
    #[test]
    fn status_mapping_table() {
        use ServiceState as S;
        use TrayStatus as T;
        let cases: Vec<(S, Option<Summary>, bool, T)> = vec![
            (S::NotInstalled, None, false, T::NotInstalled),
            (S::Stopped, None, false, T::Stopped),
            (S::StopPending, None, false, T::Stopped),
            (S::StartPending, None, false, T::Starting),
            (
                S::Failed("code 3".into()),
                None,
                false,
                T::Error("code 3".into()),
            ),
            // Running + summary → Running regardless of grace.
            (
                S::Running,
                Some(summary(false)),
                true,
                T::Running(summary(false)),
            ),
            // Running + unreachable: Starting within grace, Degraded past it.
            (S::Running, None, false, T::Starting),
            (S::Running, None, true, T::Degraded),
            // A summary while the SCM says Stopped is impossible by construction (the poller only
            // fetches when Running) — but the mapping must still trust the service manager.
            (S::Stopped, Some(summary(true)), false, T::Stopped),
        ];
        for (svc, sum, grace, want) in cases {
            assert_eq!(
                map_status(&svc, sum.clone(), grace),
                want,
                "{svc:?} {sum:?} grace={grace}"
            );
        }
    }

    /// Conflicting-host detection is deliberately NOT a tray concern: "installed" is not
    /// "running", and an always-on ⚠ over a merely-present Sunshine cried wolf. The host still
    /// detects and reports it (startup log, `detect-conflicts`, the mgmt summary) — the tray just
    /// ignores that field, which it must keep tolerating on the wire.
    #[test]
    fn a_summary_carrying_conflicts_still_deserializes_and_is_ignored() {
        let json = r#"{"version":"0.5.1","video_streaming":false,"audio_streaming":false,
            "session":null,"paired_clients":1,"native_paired_clients":2,"pin_pending":false,
            "pending_approvals":0,"kept_displays":0,"conflicts":["Sunshine (installed)"]}"#;
        let s: Summary = serde_json::from_str(json).expect("unknown fields are ignored");
        assert_eq!(
            TrayStatus::Running(s).headline(),
            "punktfunk 主机 0.5.1——空闲"
        );
    }

    #[test]
    fn headline_shows_session_and_reason() {
        assert_eq!(
            TrayStatus::Running(summary(true)).headline(),
            "punktfunk 主机 0.5.1——正在串流 2560×1440@120"
        );
        assert_eq!(
            TrayStatus::Running(summary(false)).headline(),
            "punktfunk 主机 0.5.1——空闲"
        );
        assert!(TrayStatus::Error("exit code 3".into())
            .headline()
            .contains("exit code 3"));
        assert!(TrayStatus::Degraded
            .headline()
            .contains("状态不可用"));
    }

    /// A live session means streaming even if the host's flag says otherwise — a host from before
    /// the `get_local_summary` fix only raised `video_streaming` for the GameStream plane, so a
    /// native session showed as "idle" with its own mode printed next to it.
    #[test]
    fn a_live_session_reads_as_streaming_without_the_flag() {
        let mut s = summary(true);
        s.video_streaming = false; // pre-fix host, native session
        let st = TrayStatus::Running(s);
        assert!(st.is_streaming());
        assert_eq!(
            st.headline(),
            "punktfunk 主机 0.5.1——正在串流 2560×1440@120"
        );
        // No session and no flag is still idle.
        assert!(!TrayStatus::Running(summary(false)).is_streaming());
    }

    #[test]
    fn kept_displays_are_reported_for_the_release_action() {
        assert_eq!(TrayStatus::Running(summary(false)).kept_displays(), 0);
        let mut s = summary(false);
        s.kept_displays = 2;
        assert_eq!(TrayStatus::Running(s).kept_displays(), 2);
        assert_eq!(TrayStatus::Degraded.kept_displays(), 0);
    }

    #[test]
    fn pairing_attention_flags() {
        let mut s = summary(false);
        assert!(!TrayStatus::Running(s.clone()).pairing_attention());
        s.pending_approvals = 1;
        assert!(TrayStatus::Running(s.clone()).pairing_attention());
        s.pending_approvals = 0;
        s.pin_pending = true;
        assert!(TrayStatus::Running(s).pairing_attention());
        assert!(!TrayStatus::Degraded.pairing_attention());
    }
}
