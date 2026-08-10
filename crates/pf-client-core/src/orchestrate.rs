//! The brain layer: what a connect *is*, and the one implementation of how it runs
//! (design/client-architecture-split.md §3).
//!
//! Wake-then-connect exists three times today — GTK's `WakeConnect`/`wake_fallback`, the
//! WinUI shell's `wake_and_connect`, Apple's `HostWaker` (whose comment in the Windows copy
//! literally says "mirrors the Apple HostWaker") — and the deep-link and profile work would
//! have made it five. This module is where that collapses: a [`ConnectPlan`] is built from a
//! card click, a CLI verb or a URL (one constructor each, one type out), and the orchestrator
//! runs it. Front-ends render; they don't decide.
//!
//! The split that keeps this honest is [`UiDelegate`]: prompts, progress and error surfaces
//! stay in the front-end, because a GTK dialog, a WinUI page, a Skia console screen and a
//! terminal prompt genuinely are different things — but *when* to prompt, *how long* to wait
//! for a sleeping box and *what counts as a refusal* are decided here, once.
//!
//! Wake timings are Apple's `HostWaker` verbatim, because it is the implementation that got
//! them right: a magic packet is fire-and-forget and a cold box takes 20–60 s to POST, boot
//! and re-advertise — far longer than any dial will sit — so the packet is re-sent every 6 s
//! (a single one gets missed, and some NICs only wake on a fresh packet after dropping into a
//! deeper sleep state), presence is polled once a second, and the whole wait is bounded at
//! 90 s, after which it PARKS for retry rather than erroring out from under the user.

use crate::deeplink::{DeepLink, HostResolution, Route};
use crate::profiles::{ProfilesFile, Resolution, StreamProfile};
use crate::trust::{effective_settings, KnownHost, KnownHosts, Settings};
use serde::{Deserialize, Serialize};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};

/// The host a plan dials, flattened out of whichever record or reference produced it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HostTarget {
    pub name: String,
    pub addr: String,
    pub port: u16,
    /// The pinned fingerprint. `None` = no pin, which the session binary refuses by design —
    /// a plan without one may only exist after the front-end's trust ceremony.
    pub fp_hex: Option<String>,
    pub mac: Vec<String>,
    pub id: Option<String>,
}

impl From<&KnownHost> for HostTarget {
    fn from(h: &KnownHost) -> HostTarget {
        HostTarget {
            name: h.name.clone(),
            addr: h.addr.clone(),
            port: h.port,
            fp_hex: (!h.fp_hex.is_empty()).then(|| h.fp_hex.clone()),
            mac: h.mac.clone(),
            id: h.id.clone(),
        }
    }
}

/// A resolved intent: everything needed to start one session, with every policy question
/// already answered. Built once, then executed — front-ends don't re-decide any of it.
#[derive(Clone, Debug, PartialEq)]
pub struct ConnectPlan {
    pub host: HostTarget,
    /// Library id for the host to launch on arrival.
    pub launch: Option<String>,
    /// The settings profile this connect resolved with (display + the stats overlay).
    pub profile: Option<StreamProfile>,
    /// The one-off profile reference to hand the session, if this connect overrides the host's
    /// binding: `Some(id)` for "Connect with ▸ X", `Some("")` to force the defaults, `None` to
    /// let the session resolve the host's own binding (the two paths call the same resolver,
    /// so they cannot disagree).
    pub profile_override: Option<String>,
    /// Effective settings — global defaults with the profile overlaid. What the front-end
    /// reads for anything it needs to know up front (fullscreen, match-window…).
    pub settings: Settings,
    /// Send a magic packet up front and fall back to wake-and-wait if the dial fails. Off for
    /// hosts with no MAC, and when the user turned auto-wake off (VPN hosts look offline when
    /// they aren't, and the wake+wait only adds delay).
    pub wake: bool,
    /// Handshake budget override — the request-access flow passes ~185 s because the host
    /// PARKS the connection until an operator approves.
    pub connect_timeout_secs: Option<u64>,
    /// The pin came from an advert rather than the store: persist it once the session reports
    /// ready (ready proves the host really holds that identity).
    pub tofu: bool,
    /// Share this machine's clipboard with this host — a trust decision about the HOST, so it
    /// lives on the record rather than in a profile, and the spawner resolves it once here
    /// instead of the renderer looking it up again.
    pub clipboard: bool,
}

impl ConnectPlan {
    /// The plain card-click plan: this host, its binding (or a one-off profile), its wake
    /// policy. `one_off_profile` is the "Connect with ▸" pick — `Some("")` forces the global
    /// defaults on a bound host, `None` honors the binding. Loads the stores; the pure form is
    /// [`ConnectPlan::resolve`], which a front-end that already holds them should use.
    pub fn for_host(
        host: &KnownHost,
        launch: Option<&str>,
        one_off_profile: Option<&str>,
    ) -> ConnectPlan {
        let (settings, profile) = effective_settings(&host.addr, host.port, one_off_profile);
        ConnectPlan {
            host: HostTarget::from(host),
            launch: launch.map(str::to_string),
            profile,
            profile_override: one_off_profile.map(str::to_string),
            wake: settings.auto_wake && !host.mac.is_empty(),
            settings,
            connect_timeout_secs: None,
            tofu: false,
            clipboard: host.clipboard_sync,
        }
    }

    /// The plan for a host a front-end carries in its OWN request type rather than as a stored
    /// [`KnownHost`] (the GTK shell's `ConnectRequest`, a resolved link target). Settings,
    /// profile and the clipboard decision are resolved here, through the same helpers
    /// [`ConnectPlan::for_host`] uses; the caller then sets only what is genuinely its own
    /// (`wake` when it runs its own wake fallback, `tofu`, `connect_timeout_secs`).
    ///
    /// It exists because hand-building the struct is a trap. [`spawn_session`] writes
    /// `settings` into the child's `--resolved-spec`, and a session running from a spec reads
    /// NO stores — so a `..Settings::default()` in a front-end does not fall back to the
    /// user's settings, it silently streams at every default: the host's fallback bitrate, the
    /// native resolution, `auto` codec, stereo audio. That shipped on the GTK shell (fixed
    /// 2026-07-31) and presented as "my bitrate is stuck at 20 Mbps".
    pub fn for_target(
        host: HostTarget,
        launch: Option<String>,
        one_off_profile: Option<String>,
    ) -> ConnectPlan {
        let known = KnownHosts::load();
        // No record yet — a first connect straight off an advert. A default record says
        // exactly the right thing: no profile binding, no clipboard opt-in.
        let fallback = KnownHost::default();
        let stored = known
            .find_by_addr(&host.addr, host.port)
            .unwrap_or(&fallback);
        let mut plan = ConnectPlan::resolve(
            stored,
            launch.as_deref(),
            one_off_profile.as_deref(),
            &ProfilesFile::load(),
            &Settings::load(),
        );
        // The CALLER's target wins over the stored record's: its fingerprint can be one the
        // host just advertised and we haven't persisted (trust on first use), and its name/MAC
        // come from the same discovery snapshot the card was drawn from — so `wake` has to be
        // re-decided against that MAC rather than the record's.
        plan.wake = plan.settings.auto_wake && !host.mac.is_empty();
        plan.host = host;
        plan
    }

    /// The same plan, built from stores the caller already has — no disk, no clock, no
    /// environment. This is the form the URL router uses: a front-end loads the three stores
    /// once per event and every decision below is a pure function of them.
    ///
    /// Profile precedence is the design's, unchanged: the one-off pick, else the host's
    /// binding, else nothing; `Some("")` forces the defaults; anything dangling resolves as
    /// no profile rather than an error.
    pub fn resolve(
        host: &KnownHost,
        launch: Option<&str>,
        one_off_profile: Option<&str>,
        catalog: &ProfilesFile,
        base: &Settings,
    ) -> ConnectPlan {
        let profile = match one_off_profile {
            Some("") => None,
            Some(reference) => catalog.resolve(reference).0.cloned(),
            None => host
                .profile_id
                .as_deref()
                .and_then(|id| catalog.find_by_id(id))
                .cloned(),
        };
        let settings = match &profile {
            Some(p) => p.overrides.apply(base),
            None => base.clone(),
        };
        ConnectPlan {
            host: HostTarget::from(host),
            launch: launch.map(str::to_string),
            profile,
            profile_override: one_off_profile.map(str::to_string),
            wake: settings.auto_wake && !host.mac.is_empty(),
            settings,
            connect_timeout_secs: None,
            tofu: false,
            clipboard: host.clipboard_sync,
        }
    }

    /// This plan as a [`ResolvedSpec`] — what a first-party spawner hands the session so it
    /// performs no store reads of its own.
    pub fn spec(&self, clipboard: bool) -> ResolvedSpec {
        ResolvedSpec {
            settings: self.settings.clone(),
            clipboard,
            profile: self.profile.as_ref().map(|p| p.name.clone()),
        }
    }

    /// The session binary's argv for this plan — the one place the flags are assembled, so a
    /// shell, the CLI and a URL launch cannot spawn subtly different sessions.
    pub fn session_args(&self) -> Vec<String> {
        let mut args = vec![
            "--connect".into(),
            format!("{}:{}", self.host.addr, self.host.port),
        ];
        if let Some(fp) = &self.host.fp_hex {
            args.push("--fp".into());
            args.push(fp.clone());
        }
        if let Some(launch) = &self.launch {
            args.push("--launch".into());
            args.push(launch.clone());
        }
        // Only a one-off rides the flag: without it the session resolves the host's own
        // binding through the same helper this plan used.
        if let Some(profile) = &self.profile_override {
            args.push("--profile".into());
            args.push(profile.clone());
        }
        if let Some(secs) = self.connect_timeout_secs {
            args.push("--connect-timeout".into());
            args.push(secs.to_string());
        }
        if self.settings.fullscreen_on_stream {
            args.push("--fullscreen".into());
        }
        // Deliberately NO `--window-pos` here. The Windows shell appends its own (its
        // window's desktop coordinates place the session on the same monitor), but on
        // Wayland neither GTK can read global window coordinates nor can SDL apply
        // them — the compositor owns placement — so from the GTK/CLI spawners the flag
        // would be a silent no-op everywhere it matters. X11 could carry it, but a
        // Linux-only special case that most Linux sessions ignore isn't worth the drift.
        args
    }
}

/// What a URL turned into. Everything a front-end must not decide for itself lives in this
/// enum: an unknown host is a *prompt*, never a connect, and a route this build doesn't do is
/// a notice, never a silent no-op.
#[derive(Clone, Debug, PartialEq)]
pub enum PlanOutcome {
    Connect(Box<ConnectPlan>),
    /// The link resolved to no local record. The front-end shows the confirmation sheet with
    /// exactly this, and the normal pairing/TOFU flow proceeds under the user's eyes (§3.1).
    ConfirmUnknown(Box<UnknownHost>),
    /// A route the grammar defines but this front-end hasn't implemented yet.
    Unsupported(Route),
}

/// The confirmation sheet's contents for a link to a host we don't know.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnknownHost {
    pub addr: String,
    pub port: u16,
    /// The label the link claimed — shown as *claimed*, never trusted.
    pub name: Option<String>,
    /// The fingerprint the link expects; pre-fills the sheet's pin so the first connect is
    /// verified rather than blind trust-on-first-use.
    pub fp: Option<String>,
    pub launch: Option<String>,
    pub profile: Option<String>,
}

/// Why a link can't become a plan. Each of these is a *notice*, never a degraded connect:
/// predictability over best-effort — a shortcut that silently streams with the wrong settings
/// or to the wrong box is worse than one that explains itself (design/client-deep-links.md §8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanError {
    /// The host name matched more than one saved host.
    AmbiguousHost(String),
    /// Nothing local matched and the link carries no address to fall back on.
    UnresolvableHost(String),
    /// The link's `fp` contradicts the pin we hold — the link is stale or lying.
    PinConflict {
        host: String,
    },
    UnknownProfile(String),
    AmbiguousProfile(String),
}

impl PlanError {
    /// The notice text. Every one of these names the reference that failed, because "it didn't
    /// work" on a shortcut double-click is unactionable.
    pub fn message(&self) -> String {
        match self {
            PlanError::AmbiguousHost(r) => {
                format!("已保存的主机中有多个名为 \"{r}\"——请打开 Punktfunk 手动选择。")
            }
            PlanError::UnresolvableHost(r) => {
                format!("没有与 \"{r}\" 匹配的已保存主机。")
            }
            PlanError::PinConflict { host } => format!(
                "该链接的指纹与为 {host} 保存的指纹不匹配——链接已过期，\
                 或并非该主机。未建立任何连接。"
            ),
            PlanError::UnknownProfile(p) => {
                format!("该链接要求使用名为 \"{p}\" 的设置配置，但本机不存在该配置。")
            }
            PlanError::AmbiguousProfile(p) => {
                format!("有多个设置配置名为 \"{p}\"——请重命名其一，或在链接中使用配置 ID。")
            }
        }
    }
}

/// Build a plan from a `punktfunk://` link against this device's stores — the shared half of
/// every platform's URL router (§4). The security rules of §3 live here, not in the shells:
/// no pairing, no silent trust, references resolved or refused.
///
/// Preempting a live session is the one rule that stays with the caller: only the front-end
/// knows whether a session is running, and the answer ("focus it" / "end that one first")
/// is UI, not policy.
pub fn plan_from_link(
    link: &DeepLink,
    known: &KnownHosts,
    catalog: &ProfilesFile,
    base: &Settings,
) -> Result<PlanOutcome, PlanError> {
    if link.route != Route::Connect {
        return Ok(PlanOutcome::Unsupported(link.route));
    }
    // The profile is resolved BEFORE anything is dialled: a link that can't honor its profile
    // must say so instead of streaming with the wrong settings.
    if let Some(reference) = &link.profile {
        match catalog.resolve(reference) {
            (Some(_), _) => {}
            (_, Resolution::Ambiguous) => {
                return Err(PlanError::AmbiguousProfile(reference.clone()))
            }
            _ => return Err(PlanError::UnknownProfile(reference.clone())),
        }
    }
    match crate::deeplink::resolve_host(link, known) {
        HostResolution::Known(i) => {
            let host = &known.hosts[i];
            if link.pin_conflict(host) {
                return Err(PlanError::PinConflict {
                    host: host.name.clone(),
                });
            }
            // A link with no `profile=` honors the host's binding, exactly like a card
            // click — the URL adds nothing there, so it changes nothing.
            let mut plan = ConnectPlan::resolve(
                host,
                link.launch.as_deref(),
                link.profile.as_deref(),
                catalog,
                base,
            );
            // A record we know but never pinned (added by address, never paired) is not a
            // silent connect either: the session refuses without a pin, and the front-end
            // should run its trust flow. Hand it back as the confirmation case.
            if plan.host.fp_hex.is_none() {
                return Ok(PlanOutcome::ConfirmUnknown(Box::new(UnknownHost {
                    addr: plan.host.addr,
                    port: plan.host.port,
                    name: Some(plan.host.name),
                    fp: link.fp.clone(),
                    launch: link.launch.clone(),
                    profile: link.profile.clone(),
                })));
            }
            if plan.host.name.is_empty() {
                // An address-only record has no label; the link's claimed one is fine for a
                // window title (it names nothing that is trusted).
                plan.host.name = link.name.clone().unwrap_or_else(|| plan.host.addr.clone());
            }
            Ok(PlanOutcome::Connect(Box::new(plan)))
        }
        HostResolution::Unknown {
            addr,
            port,
            name,
            fp,
        } => Ok(PlanOutcome::ConfirmUnknown(Box::new(UnknownHost {
            addr,
            port,
            name,
            fp,
            launch: link.launch.clone(),
            profile: link.profile.clone(),
        }))),
        HostResolution::Ambiguous => Err(PlanError::AmbiguousHost(link.host_ref.clone())),
        HostResolution::Unresolvable => Err(PlanError::UnresolvableHost(link.host_ref.clone())),
    }
}

// ---------------------------------------------------------------------------------------
// Wake-and-wait — the reference state machine, ported from Apple's `HostWaker`.
// ---------------------------------------------------------------------------------------

/// How long to wait for a woken host to come back. Generous on purpose: a cold boot plus
/// service start is routinely a minute-plus.
pub const WAKE_TIMEOUT_SECS: u64 = 90;
/// How often to re-send the magic packet while waiting.
pub const WAKE_RESEND_SECS: u64 = 6;

/// The wake-and-wait loop as a pure step function, so every front-end drives it from its own
/// loop (relm4 messages, a WinUI thread, the console's service tick, a CLI's sleep) and they
/// all still agree on the timings — and so the behavior is testable without waiting 90 s.
#[derive(Clone, Debug)]
pub struct WakeWait {
    elapsed_secs: u64,
    timeout_secs: u64,
    resend_secs: u64,
}

/// What the caller should do for this one-second step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeTick {
    /// Send (or re-send) the magic packet now.
    pub send_packet: bool,
    /// Seconds waited so far — the "Waking… 12s" line.
    pub seconds: u64,
    /// `None` = keep waiting (sleep a second, then tick again).
    pub outcome: Option<WakeOutcome>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeOutcome {
    /// The host answered — proceed with the connect.
    Online,
    /// The budget ran out. The UI PARKS here (Try again / Cancel); it does not error out
    /// from under the user, because "it didn't wake in 90 s" is often "give it 10 more".
    TimedOut,
}

impl Default for WakeWait {
    fn default() -> WakeWait {
        WakeWait {
            elapsed_secs: 0,
            timeout_secs: WAKE_TIMEOUT_SECS,
            resend_secs: WAKE_RESEND_SECS,
        }
    }
}

impl WakeWait {
    /// A wait with the shipped timings.
    pub fn new() -> WakeWait {
        WakeWait::default()
    }

    /// One second of the wait. `online` is this tick's presence reading (an mDNS advert, a
    /// reachability probe — whichever the front-end has; both are "did it answer").
    ///
    /// Order matters and matches the reference: the packet goes out *before* the presence
    /// check, so an already-awake host costs one wasted packet rather than a lost second, and
    /// the timeout is checked after it — a host that appears on the last tick still wins.
    pub fn tick(&mut self, online: bool) -> WakeTick {
        let send_packet = self.elapsed_secs % self.resend_secs == 0;
        let seconds = self.elapsed_secs;
        let outcome = if online {
            Some(WakeOutcome::Online)
        } else if self.elapsed_secs >= self.timeout_secs {
            Some(WakeOutcome::TimedOut)
        } else {
            self.elapsed_secs += 1;
            None
        };
        WakeTick {
            send_packet,
            seconds,
            outcome,
        }
    }

    /// Restart the same wait — "Try again" after a timeout replays it exactly (the reference's
    /// captured `replay` closure, minus the closure).
    pub fn restart(&mut self) {
        self.elapsed_secs = 0;
    }

    pub fn seconds(&self) -> u64 {
        self.elapsed_secs
    }
}

/// The front-end's obligations. Everything here is presentation; nothing here decides policy.
pub trait UiDelegate {
    /// A link or a card points at a host we don't know (or never pinned). Return true to
    /// proceed into the trust flow. A non-interactive front-end returns false — refusing is
    /// always safe, and the CLI reports it as "needs interaction" rather than pairing blind.
    fn confirm_unknown_host(&mut self, host: &UnknownHost) -> bool;
    /// Render "Waking <host>… 12s" / the timed-out park state.
    fn wake_progress(&mut self, host: &HostTarget, tick: WakeTick);
    /// The session ended, one way or another.
    fn report(&mut self, outcome: &ConnectOutcome);
}

/// How a connect finished — the typed outcome every front-end maps onto its own surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The stream ran and ended cleanly; `Some` carries the host's stated reason.
    Ended(Option<String>),
    /// The dial failed (and, where applicable, the wake wait did too).
    ConnectFailed(String),
    /// Trust rejected: no pin, or the pin no longer matches. Never retried silently.
    TrustRejected(String),
    /// The session binary itself failed to start or died abnormally.
    RendererFailed(String),
    /// The user cancelled.
    Cancelled,
}

// ---------------------------------------------------------------------------------------
// Session spawn + the stdout contract.
// ---------------------------------------------------------------------------------------

/// Everything a session needs, resolved by the caller — the spec `--resolved-spec` carries
/// (design/client-architecture-split.md §5).
///
/// The session binary is a renderer: given this, it performs ZERO store reads. Its old habit of
/// re-deriving state (loading `Settings`, looking up the host's `clipboard_sync`, resolving the
/// profile) meant policy was being evaluated inside the thing that draws pixels, and that the
/// spawner and the child could disagree about a file either of them might have written since.
///
/// The compat path — a hand-run `punktfunk-session --connect` with no spec — still resolves for
/// itself, but through the *same* helper (`effective_settings`), so the two modes cannot drift.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSpec {
    /// Effective settings: the global defaults with the chosen profile already applied.
    pub settings: Settings,
    /// Whether this host may share the clipboard — a per-host trust decision, resolved by the
    /// spawner rather than re-looked-up here.
    pub clipboard: bool,
    /// The profile's name, for the stats overlay. `None` = the global defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

impl ResolvedSpec {
    /// Write the spec somewhere the child can read it, returning the path. Temp files rather
    /// than a pipe because the session already takes a file path elsewhere and a crashed
    /// spawner leaves something inspectable; the name carries the pid so concurrent launches
    /// (a shell and a CLI, or two Decky invocations) never overwrite each other's spec.
    ///
    /// The pid alone was not enough: it is the SPAWNER's, so two launches from one shell — a
    /// cancelled connect and the retry right behind it — shared a single path, and the first
    /// child's exit deleted the file the second was still starting up to read ("resolved spec:
    /// No such file"). A per-launch counter separates them.
    pub fn write_temp(&self) -> std::io::Result<std::path::PathBuf> {
        static LAUNCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = LAUNCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("punktfunk-spec-{}-{n}.json", std::process::id()));
        let json = serde_json::to_vec_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(&path, json)?;
        Ok(path)
    }

    /// Read a spec written by the spawner.
    pub fn read(path: &std::path::Path) -> std::io::Result<ResolvedSpec> {
        let text = std::fs::read_to_string(path)?;
        serde_json::from_str(&text)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

/// One event from the session child's stdout contract (`{"ready":true}`, `{"error":…}`,
/// `{"ended":…}`, then EOF and an exit code). Parsed in one place so a shell, the console and
/// the CLI cannot disagree about what "ready" or "trust rejected" means.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SessionEvent {
    /// First frame presented — the stream is up.
    Ready,
    Error {
        msg: String,
        trust_rejected: bool,
    },
    Ended(String),
    /// The session window's logical size settled at this, under the match-window policy. The
    /// SPAWNER persists it (design §5): a renderer that load-modify-saves the shared settings
    /// file was one of its five concurrent writers, for a value only the parent needs.
    Window {
        w: u32,
        h: u32,
    },
    /// EOF: the child is gone. `-1` = killed by a signal.
    Exited(i32),
}

/// Parse one stdout line of the session contract; `None` for anything else (`stats:` lines,
/// stray output).
pub fn parse_session_line(line: &str) -> Option<SessionEvent> {
    let v: serde_json::Value = serde_json::from_str(line).ok()?;
    if v.get("ready").and_then(|r| r.as_bool()) == Some(true) {
        return Some(SessionEvent::Ready);
    }
    if let Some(msg) = v.get("error").and_then(|m| m.as_str()) {
        return Some(SessionEvent::Error {
            msg: msg.to_string(),
            trust_rejected: v.get("trust_rejected").and_then(|t| t.as_bool()) == Some(true),
        });
    }
    if let Some(msg) = v.get("ended").and_then(|m| m.as_str()) {
        return Some(SessionEvent::Ended(msg.to_string()));
    }
    if let Some(win) = v.get("window") {
        let dim = |k: &str| win.get(k).and_then(|n| n.as_u64()).map(|n| n as u32);
        if let (Some(w), Some(h)) = (dim("w"), dim("h")) {
            return Some(SessionEvent::Window { w, h });
        }
    }
    None
}

/// Persist a window size the session reported. The spawner's job now, not the renderer's — and
/// it writes only on a real change, so a session that never resizes never touches the file.
pub fn persist_window_size(w: u32, h: u32) {
    let mut s = Settings::load();
    if (s.last_window_w, s.last_window_h) != (w, h) {
        s.last_window_w = w;
        s.last_window_h = h;
        s.save();
    }
}

/// The session binary: installed next to this executable, else `$PATH` (a dev run out of
/// `target/…` lands on the sibling).
pub fn session_binary() -> std::path::PathBuf {
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name(SESSION_BIN);
        if sibling.exists() {
            return sibling;
        }
    }
    SESSION_BIN.into()
}

#[cfg(windows)]
const SESSION_BIN: &str = "punktfunk-session.exe";
#[cfg(not(windows))]
const SESSION_BIN: &str = "punktfunk-session";

/// Kills the spawned session child — the Cancel button of a parked request-access connect,
/// and the CLI's Ctrl-C path. Safe any time; a child that already exited is a no-op.
#[derive(Clone, Debug, Default)]
pub struct CancelHandle(Arc<Mutex<Option<Child>>>);

impl CancelHandle {
    pub fn kill(&self) {
        if let Some(child) = self.0.lock().unwrap().as_mut() {
            let _ = child.kill();
        }
    }
}

/// Spawn the session for this plan and supervise its stdout contract on a reader thread,
/// handing each event to `on_event` (which every front-end maps onto its own messages). The
/// final [`SessionEvent::Exited`] always arrives, so a caller can release its busy flag in
/// exactly one place.
/// `cancel` lets a front-end hold the abort handle BEFORE the child exists (a request-access
/// dialog arms its Cancel button first, then spawns); pass `None` to get a fresh one back.
pub fn spawn_session(
    plan: &ConnectPlan,
    cancel: Option<CancelHandle>,
    on_event: impl FnMut(SessionEvent) + Send + 'static,
) -> Result<CancelHandle, String> {
    let mut cmd = Command::new(session_binary());
    let mut args = plan.session_args();
    // Spec mode: hand the child the settings we already resolved, so it reads no stores and
    // cannot disagree with us about a file either of us might write (design §5). A spec we
    // fail to write is not fatal — the child's compat path resolves the same values through
    // the same helper, which is exactly why that path was kept.
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
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()); // the session's logs interleave with the front-end's
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("couldn't start {}: {e}", SESSION_BIN))?;
    tracing::info!(
        host = %plan.host.addr, port = plan.host.port,
        profile = plan.profile.as_ref().map(|p| p.name.as_str()).unwrap_or("-"),
        "session binary spawned"
    );
    let stdout = child.stdout.take().expect("piped stdout");
    let slot = cancel.unwrap_or_default();
    *slot.0.lock().unwrap() = Some(child);

    let reader_slot = slot.clone();
    let mut on_event = on_event;
    std::thread::Builder::new()
        .name("pf-session-io".into())
        .spawn(move || {
            use std::io::BufRead as _;
            for line in std::io::BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Some(ev) = parse_session_line(&line) {
                    // The window size is the spawner's to persist — the renderer only reports
                    // it. Front-ends still see the event; they just don't have to act on it.
                    if let SessionEvent::Window { w, h } = ev {
                        persist_window_size(w, h);
                    }
                    on_event(ev);
                }
            }
            // The spec has done its job the moment the child has read it; a leftover temp file
            // in %TEMP% is litter, and one per launch adds up.
            if let Some(path) = &spec_path {
                let _ = std::fs::remove_file(path);
            }
            // EOF — reap (a cancel-killed child lands here too; -1 = died on a signal).
            let code = reader_slot
                .0
                .lock()
                .unwrap()
                .take()
                .and_then(|mut c| c.wait().ok())
                .and_then(|s| s.code())
                .unwrap_or(-1);
            tracing::info!(code, "session binary exited");
            on_event(SessionEvent::Exited(code));
        })
        .map_err(|e| format!("session reader thread: {e}"))?;
    Ok(slot)
}

/// Become the session process (`--exec`): the CLI's gamescope-wrapper mode, where the launched
/// process identity must be the streaming one — a supervising parent would break focus and
/// lifecycle under gamescope. Never returns on success. Windows has no `exec`, so there this
/// runs the child to completion and exits with its code, which is the same contract minus the
/// pid.
pub fn exec_session(plan: &ConnectPlan) -> std::io::Error {
    let mut cmd = Command::new(session_binary());
    cmd.args(plan.session_args());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.exec()
    }
    #[cfg(not(unix))]
    {
        match cmd.status() {
            Ok(s) => std::process::exit(s.code().unwrap_or(1)),
            Err(e) => e,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deeplink;

    fn host(name: &str, addr: &str, id: &str, fp: &str) -> KnownHost {
        KnownHost {
            name: name.into(),
            addr: addr.into(),
            port: 9777,
            fp_hex: fp.into(),
            paired: true,
            mac: vec!["aa:bb:cc:dd:ee:ff".into()],
            id: Some(id.into()),
            ..Default::default()
        }
    }

    /// The wait is Apple's `HostWaker` second for second: a packet at 0 and every 6 s after,
    /// a presence check each second, 90 s of budget, and a park (not an error) at the end.
    #[test]
    fn wake_wait_matches_the_reference_cadence() {
        let mut w = WakeWait::new();
        // t=0: packet goes out before the first presence check.
        let t = w.tick(false);
        assert!(t.send_packet);
        assert_eq!(t.seconds, 0);
        assert_eq!(t.outcome, None);
        // t=1..5 wait quietly, t=6 re-sends.
        for s in 1..6 {
            let t = w.tick(false);
            assert!(!t.send_packet, "no packet at {s}s");
            assert_eq!(t.seconds, s);
        }
        assert!(w.tick(false).send_packet); // t=6
        assert_eq!(w.seconds(), 7);

        // A host that answers ends the wait immediately, whatever second it is.
        let mut w = WakeWait::new();
        w.tick(false);
        let t = w.tick(true);
        assert_eq!(t.outcome, Some(WakeOutcome::Online));

        // The budget: still waiting at 90 s of elapsed time, timed out on the tick after.
        let mut w = WakeWait::new();
        for _ in 0..WAKE_TIMEOUT_SECS {
            assert_eq!(w.tick(false).outcome, None);
        }
        assert_eq!(w.seconds(), WAKE_TIMEOUT_SECS);
        let t = w.tick(false);
        assert_eq!(t.outcome, Some(WakeOutcome::TimedOut));
        // A timed-out wait doesn't advance — it parks, and stays parked until asked again.
        assert_eq!(w.tick(false).outcome, Some(WakeOutcome::TimedOut));
        // …and a host that comes back while parked still wins ("Try again" isn't required).
        assert_eq!(w.tick(true).outcome, Some(WakeOutcome::Online));
        // Retry replays the identical wait.
        w.restart();
        assert_eq!(w.seconds(), 0);
        assert!(w.tick(false).send_packet);
    }

    /// The argv every door spawns through. A one-off profile rides the flag; a host BINDING
    /// deliberately doesn't — the session resolves it with the same helper, so passing it
    /// would be a second source of truth.
    #[test]
    fn session_args_are_assembled_in_one_place() {
        let h = host(
            "Desk",
            "192.168.1.50",
            "11111111-2222-4333-8444-555555555555",
            &"a".repeat(64),
        );
        let mut plan = ConnectPlan {
            host: HostTarget::from(&h),
            launch: Some("steam:570".into()),
            profile: None,
            profile_override: None,
            settings: Settings {
                fullscreen_on_stream: false,
                ..Default::default()
            },
            wake: true,
            connect_timeout_secs: None,
            tofu: false,
            clipboard: false,
        };
        assert_eq!(
            plan.session_args(),
            vec![
                "--connect",
                "192.168.1.50:9777",
                "--fp",
                &"a".repeat(64),
                "--launch",
                "steam:570"
            ]
        );

        plan.profile_override = Some("aaaaaaaaaaaa".into());
        plan.connect_timeout_secs = Some(185);
        plan.settings.fullscreen_on_stream = true;
        let args = plan.session_args();
        assert!(args.windows(2).any(|w| w == ["--profile", "aaaaaaaaaaaa"]));
        assert!(args.windows(2).any(|w| w == ["--connect-timeout", "185"]));
        assert!(args.contains(&"--fullscreen".to_string()));

        // "Connect with ▸ Default settings" on a bound host is an EMPTY override, which is
        // not the same as no override — it has to survive as a flag.
        plan.profile_override = Some(String::new());
        let args = plan.session_args();
        let i = args.iter().position(|a| a == "--profile").unwrap();
        assert_eq!(args[i + 1], "");
    }

    /// The §3 security rules, in the layer that owns them: an unknown host is a prompt, a
    /// contradicted pin is a refusal, an unhonorable profile is a refusal, and an ambiguous
    /// reference is never guessed at.
    #[test]
    fn link_plans_refuse_rather_than_degrade() {
        let fp = "a".repeat(64);
        let known = KnownHosts {
            hosts: vec![
                host(
                    "Desk",
                    "192.168.1.50",
                    "11111111-2222-4333-8444-555555555555",
                    &fp,
                ),
                host(
                    "Couch",
                    "192.168.1.60",
                    "22222222-3333-4444-8555-666666666666",
                    "",
                ),
                host(
                    "Couch",
                    "192.168.1.61",
                    "33333333-4444-4555-8666-777777777777",
                    "",
                ),
            ],
        };
        // Pure inputs — the test never touches the config directory.
        let catalog = ProfilesFile::default();
        let base = Settings::default();
        let plan =
            |url: &str| plan_from_link(&deeplink::parse(url).unwrap(), &known, &catalog, &base);

        // A known, pinned host with a matching (or absent) fp: a plain connect.
        let out = plan("punktfunk://connect/Desk").unwrap();
        match out {
            PlanOutcome::Connect(p) => {
                assert_eq!(p.host.addr, "192.168.1.50");
                assert_eq!(p.profile_override, None);
                assert!(p.host.fp_hex.is_some());
            }
            other => panic!("expected a connect, got {other:?}"),
        }

        // A lying/stale fingerprint never connects, and says which host it was about.
        assert_eq!(
            plan(&format!("punktfunk://connect/Desk?fp={}", "b".repeat(64))),
            Err(PlanError::PinConflict {
                host: "Desk".into()
            })
        );
        // Ambiguity is reported, never resolved by picking the first.
        assert_eq!(
            plan("punktfunk://connect/Couch"),
            Err(PlanError::AmbiguousHost("Couch".into()))
        );
        assert_eq!(
            plan("punktfunk://connect/00000000-0000-4000-8000-000000000000"),
            Err(PlanError::UnresolvableHost(
                "00000000-0000-4000-8000-000000000000".into()
            ))
        );
        // A profile the catalog can't honor refuses BEFORE anything is dialled.
        assert_eq!(
            plan("punktfunk://connect/Desk?profile=NoSuchProfile"),
            Err(PlanError::UnknownProfile("NoSuchProfile".into()))
        );
        // An unknown address is a confirmation sheet, never an auto-connect — and it carries
        // the claimed name and the expected pin so the first connect is verified, not TOFU.
        match plan(&format!(
            "punktfunk://connect/10.0.0.9:7000?name=Studio&fp={fp}"
        ))
        .unwrap()
        {
            PlanOutcome::ConfirmUnknown(u) => assert_eq!(
                *u,
                UnknownHost {
                    addr: "10.0.0.9".into(),
                    port: 7000,
                    name: Some("Studio".into()),
                    fp: Some(fp.clone()),
                    launch: None,
                    profile: None,
                }
            ),
            other => panic!("expected a confirmation, got {other:?}"),
        }
        // A saved host we never pinned is the same case: known ≠ trusted.
        match plan("punktfunk://connect/192.168.1.60").unwrap() {
            PlanOutcome::ConfirmUnknown(u) => {
                assert_eq!(u.addr, "192.168.1.60");
                assert_eq!(u.name.as_deref(), Some("Couch"));
            }
            other => panic!("expected a confirmation, got {other:?}"),
        }
        // Routes that parse but aren't implemented here are a notice, not a silent drop.
        assert!(matches!(
            plan("punktfunk://wake/Desk").unwrap(),
            PlanOutcome::Unsupported(Route::Wake)
        ));
    }

    /// The spec is the whole of what a session needs, and it round-trips — a field lost here
    /// is a setting the stream silently doesn't get.
    #[test]
    fn resolved_spec_round_trips() {
        let spec = ResolvedSpec {
            settings: Settings {
                width: 2560,
                height: 1440,
                bitrate_kbps: 55000,
                codec: "av1".into(),
                present_priority: "smooth".into(),
                smooth_buffer: 2,
                vsync: false,
                allow_vrr: false,
                ..Default::default()
            },
            clipboard: true,
            profile: Some("Work".into()),
        };
        let json = serde_json::to_string(&spec).unwrap();
        assert_eq!(serde_json::from_str::<ResolvedSpec>(&json).unwrap(), spec);

        // A spec without a profile is the defaults, and the key is simply absent.
        let plain = ResolvedSpec {
            profile: None,
            ..spec.clone()
        };
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("profile"));
        assert_eq!(serde_json::from_str::<ResolvedSpec>(&json).unwrap(), plain);
    }

    /// A plan's spec carries the settings the plan resolved — including the profile's name for
    /// the overlay, and the host's clipboard decision the renderer no longer looks up.
    #[test]
    fn plan_spec_carries_what_the_session_may_not_re_derive() {
        let h = KnownHost {
            name: "Desk".into(),
            addr: "192.168.1.50".into(),
            fp_hex: "a".repeat(64),
            clipboard_sync: true,
            profile_id: Some("aaaaaaaaaaaa".into()),
            ..Default::default()
        };
        let catalog = ProfilesFile {
            version: 1,
            profiles: vec![crate::profiles::StreamProfile {
                id: "aaaaaaaaaaaa".into(),
                name: "Game".into(),
                overrides: crate::profiles::SettingsOverlay {
                    bitrate_kbps: Some(80000),
                    ..Default::default()
                },
                ..crate::profiles::StreamProfile::new("")
            }],
        };
        let plan = ConnectPlan::resolve(&h, None, None, &catalog, &Settings::default());
        let spec = plan.spec(plan.clipboard);
        assert_eq!(spec.settings.bitrate_kbps, 80000, "the overlay is baked in");
        assert_eq!(spec.profile.as_deref(), Some("Game"));
        assert!(spec.clipboard, "the host's decision, resolved once");
    }

    /// The stdout contract, parsed once for every front-end.
    #[test]
    fn session_contract_lines() {
        assert_eq!(
            parse_session_line(r#"{"ready":true}"#),
            Some(SessionEvent::Ready)
        );
        assert_eq!(
            parse_session_line(r#"{"error":"no route","trust_rejected":false}"#),
            Some(SessionEvent::Error {
                msg: "no route".into(),
                trust_rejected: false
            })
        );
        assert_eq!(
            parse_session_line(r#"{"error":"pin","trust_rejected":true}"#),
            Some(SessionEvent::Error {
                msg: "pin".into(),
                trust_rejected: true
            })
        );
        assert_eq!(
            parse_session_line(r#"{"ended":"Host ended the session"}"#),
            Some(SessionEvent::Ended("Host ended the session".into()))
        );
        // The window report the spawner persists on the session's behalf.
        assert_eq!(
            parse_session_line(r#"{"window":{"w":1600,"h":900}}"#),
            Some(SessionEvent::Window { w: 1600, h: 900 })
        );
        // A half-formed window line is not an event — persisting half a size would be worse
        // than ignoring it.
        assert_eq!(parse_session_line(r#"{"window":{"w":1600}}"#), None);
        // Stats lines and stray output are never events.
        assert_eq!(parse_session_line("stats: 1280×800@60 · 60 fps"), None);
        assert_eq!(parse_session_line(""), None);
        assert_eq!(parse_session_line(r#"{"other":1}"#), None);
    }
}
