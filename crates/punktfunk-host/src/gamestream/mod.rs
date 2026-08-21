//! GameStream (P1) control plane — what a stock Moonlight/Artemis client talks to around
//! the media streams: mDNS discovery, the nvhttp serverinfo + pairing HTTP(S) API, RTSP,
//! and the ENet control stream. `tokio`/`axum` live here (control plane, I/O-bound — never
//! the per-frame hot path; that is `punktfunk_core`'s P1 wire codec). See `design/gamestream-host-plan.md`.
//!
//! Status: P1.1 — mDNS `_nvstream._tcp` advertisement + `/serverinfo`. Pairing, RTSP, and
//! the media streams follow (see the GameStream host task list / plan).

// The Moonlight-protocol modules exist only behind the `gamestream` cargo feature (rust-safety
// WP19): a native-only build (`--no-default-features --features pyrowave`) contains none of this
// code — and none of its dependencies (`rusty_enet`, `rsa`). What stays unconditional in this
// module is the shared vocabulary history parked here: `AppState`, `Host`, the port/version
// constants, the paired-list persistence, `serve` itself, and `tls` (the mgmt API's TLS lives
// there; only its Moonlight-client-cert leniency is feature-gated).
#[cfg(feature = "gamestream")]
pub mod apps;
// Platform-neutral wire/negotiation logic + the Linux capture/encode pipeline (non-Linux
// builds get a stub `start` inside the module).
#[cfg(feature = "gamestream")]
mod audio;
#[cfg(feature = "gamestream")]
pub(crate) mod cert;
#[cfg(feature = "gamestream")]
mod control;
#[cfg(feature = "gamestream")]
mod crypto;
#[cfg(feature = "gamestream")]
pub mod gamepad;
#[cfg(feature = "gamestream")]
mod input;
#[cfg(feature = "gamestream")]
mod mdns;
#[cfg(feature = "gamestream")]
mod nvhttp;
#[cfg(feature = "gamestream")]
mod pairing;
/// Moonlight `SS_PEN`/`SS_TOUCH` → the native pen model / wire touch (design/pen-tablet-input.md §4).
#[cfg(feature = "gamestream")]
mod pen;
#[cfg(feature = "gamestream")]
mod rtsp;
#[cfg(feature = "gamestream")]
mod serverinfo;
#[cfg(feature = "gamestream")]
mod stream;
pub(crate) mod tls;
#[cfg(feature = "gamestream")]
mod video;

use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::sync::Arc;

/// nvhttp ports (Moonlight derives all stream ports by offset from the HTTP base 47989).
pub const HTTP_PORT: u16 = 47989;
pub const HTTPS_PORT: u16 = 47984;
pub const RTSP_PORT: u16 = 48010;
pub const VIDEO_PORT: u16 = 47998;
pub const CONTROL_PORT: u16 = 47999;
pub const AUDIO_PORT: u16 = 48000;

/// Advertised host version. Major ≥ 7 tells Moonlight to use SHA-256 for pairing.
pub const APP_VERSION: &str = "7.1.431.-1";
pub const GFE_VERSION: &str = "3.23.0.74";
/// `ServerCodecModeSupport` flags, from moonlight-common-c `src/Limelight.h` (verified
/// against master, 2026-06-10): SCM_H264 0x1, SCM_HEVC 0x100, SCM_HEVC_MAIN10 0x200,
/// SCM_AV1_MAIN8 0x10000, SCM_AV1_MAIN10 0x20000 (+ 4:4:4 Sunshine extensions we don't do).
pub const SCM_H264: u32 = 0x0000_0001;
pub const SCM_HEVC: u32 = 0x0000_0100;
pub const SCM_HEVC_MAIN10: u32 = 0x0000_0200;
pub const SCM_AV1_MAIN8: u32 = 0x0001_0000;
pub const SCM_AV1_MAIN10: u32 = 0x0002_0000;
/// The **SDR baseline** codec mask: H.264, HEVC Main, AV1 Main 8-bit (= 65793). HEVC Main10 (HDR) is
/// layered on top of this at runtime by `serverinfo::codec_mode_support` when — and only when — the
/// host can actually deliver it ([`host_hdr_capable`]); it is never a static claim, because a non-HDR
/// host (a host where `PUNKTFUNK_10BIT` was explicitly turned off, or a Linux host whose video
/// source / encoder can't do Main10) must not invite a client into an HDR mode it can't produce. (The previous placeholder 3843 = 0xF03 wrongly claimed HEVC Main10 +
/// 4:4:4 and *no* AV1.) 4:4:4 stays off entirely on GameStream: stock Moonlight is 4:2:0 —
/// full-chroma is a punktfunk/1-native negotiation only (`crate::capture::capturer_supports_444`).
pub const SERVER_CODEC_MODE_SUPPORT: u32 = SCM_H264 | SCM_HEVC | SCM_AV1_MAIN8;

/// Whether this host can deliver an **HDR** (10-bit BT.2020 PQ) GameStream at all — the gate for
/// `IsHdrSupported` per app, for layering the 10-bit codec bits in serverinfo, and (together with
/// the live capture-side check and the session's own codec at RTSP time) for honoring a client's
/// `dynamicRangeMode` request. Host-wide and codec-agnostic on purpose: the per-codec depth
/// question belongs to whoever knows which codec is in play. Behind the host's `PUNKTFUNK_10BIT`
/// policy gate — **default ON**, explicit-off grammar (`=0`/`false`/`off`/`no` disables), the same
/// gate the native punktfunk/1 plane honors — on both OSes.
///
/// **Windows**: the IDD-push capturer streams HEVC Main10 PQ whenever the desktop is HDR, and a
/// client HDR request proactively enables advanced color on the per-session virtual display so PQ
/// flows even from an SDR desktop.
///
/// **Linux**: two sources can do it, and they are gated differently because they fail differently.
/// The GNOME 50+ portal **monitor mirror** (`video_source=portal`) negotiates the 10-bit PQ
/// formats only while the mirrored monitor is in HDR mode — a LIVE box-state fact, re-checked at
/// RTSP honor time ([`pf_capture::gnome_hdr_monitor_active`]), so this fn can only make the static
/// claim. A **gamescope virtual output** negotiates them whenever the resolved gamescope offers
/// them (our `pipewire-hdr` build) — a STATIC binary-identity fact, so
/// [`crate::capture::capturer_supports_hdr_for`] is the whole answer and the RTSP gate has nothing
/// live to add. Every other virtual output stays SDR (Mutter's RecordVirtual streams and the
/// KWin/wlroots equivalents are 8-bit upstream). Both arms also need the encoders' probed Main10
/// path ([`crate::encode::can_encode_10bit`]).
pub fn host_hdr_capable() -> bool {
    if !pf_host_config::config().ten_bit {
        return false;
    }
    #[cfg(target_os = "windows")]
    {
        true
    }
    #[cfg(target_os = "linux")]
    {
        let source_can_hdr = match pf_host_config::config().video_source.as_deref() {
            Some("portal") => true,
            // A virtual-output GameStream session drives the host's configured compositor; the
            // gamescope arm is the only one that can be HDR. `detect()` is the same resolution
            // the session itself will do, and it is cheap + cached downstream.
            _ => crate::vdisplay::detect()
                .ok()
                .is_some_and(|c| crate::capture::capturer_supports_hdr_for(Some(c))),
        };
        // ANY 10-bit-capable codec makes the host HDR-capable; which BITS get advertised, and
        // whether a given session's negotiated codec can carry it, are per-codec questions
        // answered by `serverinfo::apply_hdr` and the RTSP honor respectively.
        source_can_hdr
            && (crate::encode::can_encode_10bit(crate::encode::Codec::H265)
                || crate::encode::can_encode_10bit(crate::encode::Codec::Av1))
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        false
    }
}

/// Stable host identity + advertised capabilities, shared across control-plane handlers.
pub struct Host {
    pub hostname: String,
    /// Stable per-host id (persisted), echoed in serverinfo + matched on pairing.
    pub uniqueid: String,
    pub local_ip: IpAddr,
    pub http_port: u16,
    pub https_port: u16,
    /// OS identity chain (`windows` | `macos` | `linux[/<family>][/<id>]`), advertised in the
    /// mDNS `os=` TXT record and `HostInfo.os` so clients can show an OS icon.
    pub os_chain: String,
    /// Human-readable OS name (os-release `PRETTY_NAME`), surfaced as `HostInfo.os_name` only.
    pub os_name: String,
    // Pairing state (server cert, paired client certs) lands in the next P1.1 slice.
}

impl Host {
    pub fn detect() -> Result<Host> {
        let os = crate::osinfo::detect();
        Ok(Host {
            hostname: hostname_string(),
            uniqueid: load_or_create_uniqueid()?,
            local_ip: primary_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            http_port: HTTP_PORT,
            https_port: HTTPS_PORT,
            os_chain: os.chain.clone(),
            os_name: os.pretty.clone(),
        })
    }
}

/// The stream parameters a client passes at `/launch`, shared with the RTSP + media stages.
#[derive(Clone, Copy, Debug)]
pub struct LaunchSession {
    /// AES-128 key for the RTSP/control/video/audio planes (from `rikey`).
    pub gcm_key: [u8; 16],
    /// `rikeyid` — seeds the per-stream GCM IVs.
    pub rikeyid: i32,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    /// `/launch?appid=N` — selects the app-catalog entry (session recipe).
    pub appid: u32,
    /// Source IP of the paired HTTPS client that issued `/launch`. The unauthenticated RTSP/UDP
    /// media plane binds to this so only the launching peer can start/own the stream — an
    /// unpaired RTSP peer cannot ride a paired client's launch (security-review 2026-06-28 #4).
    /// `None` if the address could not be captured (then RTSP falls back to launch-present only).
    pub peer_ip: Option<std::net::IpAddr>,
    /// SHA-256 cert fingerprint of the paired client that owns this session — mode-conflict admission
    /// (Stage 4) compares it against a launching client to tell a same-client re-launch (always
    /// allowed) from a DIFFERENT client (subject to the `mode_conflict` policy). `[u8; 32]` keeps
    /// [`LaunchSession`] `Copy`; `None` when the peer cert couldn't be read.
    pub owner_fp: Option<[u8; 32]>,
}

/// Shared control-plane state used as the axum app state.
pub struct AppState {
    pub host: Host,
    /// The GameStream (RSA-2048) identity — Moonlight pins it, its pairing hashes bind its X.509
    /// signature bytes. The native planes present `crate::identity` instead (the identity split).
    #[cfg(feature = "gamestream")]
    pub identity: cert::ServerIdentity,
    #[cfg(feature = "gamestream")]
    pub pairing: pairing::Pairing,
    /// Pinned (paired) client certificate DERs — the post-pair allow-list. Unconditional on
    /// purpose: the mgmt list/unpair endpoints stay in every build (a native-only host can still
    /// list + revoke pairings made by a GameStream-featured build sharing the config dir).
    pub paired: std::sync::Mutex<Vec<Vec<u8>>>,
    /// The ENet control port's lifecycle gate (rust-safety WP0): 47999 is bound only while
    /// `paired` is non-empty — see [`control::sync`] / [`sync_control`].
    #[cfg(feature = "gamestream")]
    pub(crate) control_gate: control::Gate,
    /// The active launch session (set by `/launch`, consumed by RTSP/media).
    pub launch: std::sync::Mutex<Option<LaunchSession>>,
    /// Negotiated video config from RTSP ANNOUNCE (consumed by the stream on PLAY).
    #[cfg(feature = "gamestream")]
    pub stream: std::sync::Mutex<Option<stream::StreamConfig>>,
    /// Negotiated audio parameters from RTSP ANNOUNCE (channels/quality/packet duration);
    /// defaults to stereo when a client never ANNOUNCEs them.
    #[cfg(feature = "gamestream")]
    pub audio_params: std::sync::Mutex<audio::AudioParams>,
    /// True while the video stream thread is running (also its keep-running flag).
    pub streaming: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Whether the current session is ending **deliberately** — the compat plane's answer to the
    /// native plane's `QUIT_CODE` close, which RTSP has no equivalent of.
    ///
    /// Set by the three things that mean "this is over": the client's `/cancel` (Moonlight's Quit
    /// App), the management API's stop, and the launched game exiting. An ENet vanish or an
    /// unreachable client leaves it clear — those are drops, and the difference decides whether the
    /// virtual display skips its keep-alive linger and whether the end-game policy sees an intent or
    /// a network blip. Cleared by `/launch`, which is where a session begins.
    pub quit: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// True while the audio stream thread is running (also its keep-running flag).
    pub audio_streaming: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Set by the control stream when the client requests an IDR / invalidates reference
    /// frames (recovery after loss); the video thread forces a keyframe and clears it.
    pub force_idr: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// A client reference-frame-invalidation request carrying the lost frame range (0x0301). The
    /// video thread drains it and calls `Encoder::invalidate_ref_frames`, falling back to a full
    /// IDR when the encoder can't invalidate (range too old / no NVENC RFI). `None` = nothing pending.
    pub rfi_range: std::sync::Arc<std::sync::Mutex<Option<(i64, i64)>>>,
    /// Persistent screen capturer, reused across streams so reconnects don't spawn a second
    /// (conflicting) screencast session. The video thread borrows it for the stream's duration
    /// and returns it; `set_active` gates its cost while idle. The slot's `bool` records whether
    /// it was opened with the HDR (10-bit PQ) offer — a stream whose negotiated `hdr` differs
    /// drops the pooled capturer and opens a fresh screencast session at the right depth
    /// (mirroring the audio capturer's channel-count reuse gate).
    #[cfg(feature = "gamestream")]
    pub video_cap: stream::CapturerSlot,
    /// Persistent audio capturer, reused across streams when the channel count still matches
    /// (avoids a PipeWire stream setup per reconnect); drained on reuse so no stale audio is
    /// sent, dropped + reopened when a session negotiates a different channel count.
    pub audio_cap: std::sync::Arc<std::sync::Mutex<Option<Box<dyn crate::audio::AudioCapturer>>>>,
    /// Shared streaming-stats recorder (web-console capture/graph). The GameStream encode loop
    /// reads `is_armed()` per frame and emits samples; the same `Arc` is shared with the mgmt API
    /// and the native punktfunk/1 loops so one capture spans whichever path is streaming.
    pub stats: Arc<crate::stats_recorder::StatsRecorder>,
    /// The per-client access grants registry (design/per-client-access.md §8, WP13): the SAME
    /// registry the native plane's trust store owns, keyed by certificate fingerprint hex — it
    /// serves both paired stores. Set once by [`serve`] after the native-pairing handle exists;
    /// unset (tests, exotic embedders) the Moonlight plane treats every paired peer as
    /// ungoverned — full control, exactly the pre-grants behavior.
    pub access: std::sync::OnceLock<Arc<crate::native_pairing::NativePairing>>,
}

/// Session-lost callback the media threads invoke when they detect the client is unreachable
/// (a UDP send error): ends the WHOLE GameStream session via [`AppState::end_session`], not just
/// the thread that noticed — video and audio otherwise stop independently and leave the launch
/// state behind. Built by the RTSP PLAY handler (the one place with the `Arc<AppState>`).
pub(crate) type OnSessionLost = Arc<dyn Fn() + Send + Sync>;

impl AppState {
    /// End the GameStream session as one unit: signal BOTH media threads to stop (they observe
    /// their `streaming`/`audio_streaming` flags) and clear the launch + negotiated stream
    /// config. Idempotent — safe to call from every "the client is gone" site.
    ///
    /// This is THE teardown for the compat plane. Anything less leaves a stale session behind:
    /// a lingering `launch` 503-blocks a different client's `/launch` under
    /// `mode_conflict = reject`, and a stale `streaming = true` makes a reconnect's RTSP PLAY
    /// take its "stream already running" branch while the old threads still stream at the
    /// vanished client's endpoint (no new threads are started — the reconnect gets no media).
    /// Returns whether the video stream was live (for the caller's log line).
    pub(crate) fn end_session(&self, reason: &str) -> bool {
        use std::sync::atomic::Ordering;
        let was_streaming = self.streaming.swap(false, Ordering::SeqCst);
        let was_audio = self.audio_streaming.swap(false, Ordering::SeqCst);
        let had_launch = self
            .launch
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .is_some();
        #[cfg(feature = "gamestream")]
        self.stream.lock().unwrap_or_else(|e| e.into_inner()).take();
        if was_streaming || was_audio || had_launch {
            tracing::info!(
                reason,
                was_streaming,
                was_audio,
                had_launch,
                "gamestream: session ended"
            );
        }
        was_streaming
    }

    /// End the session as a **decision** rather than a drop: mark it deliberate, then tear it down.
    ///
    /// This is what a client's `/cancel`, the management stop, and a launched game's exit all use.
    /// The flag is read by the virtual display's keep-alive lease (skip the linger — nobody is coming
    /// back) and, at the video thread's teardown, by the end-game-on-session-end policy (which gives a
    /// mere drop a reconnect window first). See [`AppState::quit`].
    pub(crate) fn quit_session(&self, reason: &str) -> bool {
        self.quit.store(true, std::sync::atomic::Ordering::SeqCst);
        self.end_session(reason)
    }

    /// Fresh control-plane state: no active session; the pairing allow-list is loaded from
    /// disk (pairings persist across restarts). `stats` is the shared recorder handed to both the
    /// mgmt API and the streaming loops. (The native-only build's variant is below — same state
    /// minus the Moonlight identity/pairing machinery.)
    #[cfg(feature = "gamestream")]
    pub fn new(
        host: Host,
        identity: cert::ServerIdentity,
        stats: Arc<crate::stats_recorder::StatsRecorder>,
    ) -> AppState {
        AppState {
            host,
            identity,
            pairing: pairing::Pairing::new(),
            paired: std::sync::Mutex::new(load_paired()),
            control_gate: control::Gate::new(),
            launch: std::sync::Mutex::new(None),
            stream: std::sync::Mutex::new(None),
            audio_params: std::sync::Mutex::new(audio::AudioParams::default()),
            streaming: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            quit: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audio_streaming: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            force_idr: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rfi_range: std::sync::Arc::new(std::sync::Mutex::new(None)),
            video_cap: std::sync::Arc::new(std::sync::Mutex::new(None)),
            audio_cap: std::sync::Arc::new(std::sync::Mutex::new(None)),
            stats,
            access: std::sync::OnceLock::new(),
        }
    }

    /// The native-only build's [`AppState::new`]: identical control-plane state minus the
    /// Moonlight machinery (identity/pairing/control-gate and the RTSP-negotiated stream slots),
    /// which does not exist in this build.
    #[cfg(not(feature = "gamestream"))]
    pub fn new(host: Host, stats: Arc<crate::stats_recorder::StatsRecorder>) -> AppState {
        AppState {
            host,
            paired: std::sync::Mutex::new(load_paired()),
            launch: std::sync::Mutex::new(None),
            streaming: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            quit: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            audio_streaming: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            force_idr: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            rfi_range: std::sync::Arc::new(std::sync::Mutex::new(None)),
            audio_cap: std::sync::Arc::new(std::sync::Mutex::new(None)),
            stats,
            access: std::sync::OnceLock::new(),
        }
    }
}

/// Reconcile the ENet control port to the paired-client list — bound iff at least one pairing
/// exists (rust-safety WP0; see [`control::sync`]). A crate-visible wrapper so callers outside
/// `gamestream` (the management API's unpair) can reach it past the private `control` module.
/// A no-op unless `serve` armed the gate (`--gamestream`).
#[cfg(feature = "gamestream")]
pub(crate) fn sync_control(state: &Arc<AppState>) -> Result<()> {
    control::sync(state)
}

/// Native-only build: there is no ENet control port to reconcile — the callers (the mgmt unpair)
/// stay uniform and this is the whole implementation.
#[cfg(not(feature = "gamestream"))]
pub(crate) fn sync_control(_state: &Arc<AppState>) -> Result<()> {
    Ok(())
}

/// Run the host (blocks): mDNS, the nvhttp servers, and the management REST API.
/// `native = Some(cfg)` makes this the **unified** host — it also runs the native punktfunk/1
/// QUIC server on `cfg.port` in the same process, sharing one [`crate::native_pairing`] handle with
/// the management API so the web console can arm pairing and show the PIN. `None` = GameStream only
/// (the mgmt API's native endpoints report `enabled: false`).
/// Run the host. The **native punktfunk/1 plane + management API always run** (the secure default —
/// SPAKE2 pairing, per-direction AEAD nonces); `gamestream` additionally brings up the
/// GameStream/Moonlight-compat planes (nvhttp pairing, RTSP, ENet control, `_nvstream` mDNS), which
/// carry inherent on-path weaknesses (plain-HTTP pairing + legacy GCM nonce reuse, security-review
/// #5/#9) — so it is **opt-in** (`serve --gamestream`) and gated on a trusted LAN.
pub fn serve(
    mgmt: crate::mgmt::Options,
    native: crate::native::NativeServe,
    gamestream: bool,
) -> Result<()> {
    // WP19: `serve --gamestream` / PUNKTFUNK_GAMESTREAM=1 against a native-only binary is an
    // explicit ask this build cannot honor — refuse loudly rather than quietly serve less than
    // the operator configured.
    #[cfg(not(feature = "gamestream"))]
    if gamestream {
        anyhow::bail!(
            "this punktfunk-host was built WITHOUT the 'gamestream' feature — stock-Moonlight \
             compat is unavailable in this binary. Remove --gamestream / PUNKTFUNK_GAMESTREAM \
             from the configuration, or install a standard (GameStream-featured) build."
        );
    }
    let host = Host::detect()?;
    // The shared streaming-stats recorder: one handle for the mgmt API, the GameStream encode loop
    // (via `AppState`), and the native punktfunk/1 loops (passed to `native::serve`).
    let stats = crate::stats_recorder::StatsRecorder::new(crate::stats_recorder::default_dir());
    #[cfg(feature = "gamestream")]
    let state = {
        let identity = cert::ServerIdentity::load_or_create().context("host certificate")?;
        Arc::new(AppState::new(host, identity, stats.clone()))
    };
    #[cfg(not(feature = "gamestream"))]
    let state = Arc::new(AppState::new(host, stats.clone()));
    // The native plane always runs, so the shared native-pairing handle (linking the QUIC ceremony
    // and the management API) always exists.
    let np = Arc::new(
        crate::native_pairing::NativePairing::load_with(None, None, false)
            .context("native pairing store")?,
    );
    // WP13: hand the GameStream planes the grants registry — the nvhttp launch surface and the
    // ENet control thread resolve a Moonlight fingerprint's mask against the same registry the
    // native plane enforces (design §8: it keys on fingerprint hex and serves both stores).
    let _ = state.access.set(np.clone());
    // The identity the native QUIC plane and the mgmt API present (the identity split): P-256 on
    // hosts no native client ever pinned, the legacy RSA cert otherwise — resolved ONCE here so
    // the two planes cannot race the first-run adoption. See `crate::identity`.
    let native_ident = crate::identity::load_or_adopt(&np).context("native host identity")?;
    tracing::info!(
        hostname = %state.host.hostname,
        uniqueid = %state.host.uniqueid,
        ip = %state.host.local_ip,
        native_port = native.port,
        require_pairing = native.require_pairing,
        gamestream,
        "punktfunk host"
    );
    // Surface a conflicting Moonlight-compatible host (Sunshine/Apollo/…) as early as possible:
    // scan once (cached for `/local/summary` → the web console) and warn loudly if one can actually
    // clash. A dormant leftover (an uninstalled Sunshine's Program Files folder, a disabled service)
    // is logged at INFO instead — it belongs in a support log, not in a warning that reads like a
    // fault on every boot.
    let conflicts = crate::detect::init();
    if !conflicts.is_empty() {
        let report = crate::detect::render_report(conflicts);
        if crate::detect::any_active(conflicts) {
            tracing::warn!(
                target: "punktfunk::detect",
                count = conflicts.len(),
                "{report}"
            );
        } else {
            tracing::info!(
                target: "punktfunk::detect",
                count = conflicts.len(),
                "{report}"
            );
        }
    }
    if gamestream {
        tracing::warn!(
            "GameStream/Moonlight compat ENABLED (--gamestream): its pairing runs over plain HTTP and \
             its legacy control encryption can reuse GCM nonces (security-review #5/#9) — an on-path \
             LAN attacker could MITM pairing or recover input. Enable only on a TRUSTED network; prefer \
             the native punktfunk/1 plane + clients for untrusted/WAN use."
        );
    }
    let rt = tokio::runtime::Runtime::new().context("build tokio runtime")?;
    rt.block_on(async move {
        // rustls needs a process-wide crypto provider before any TLS config is built.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let native_opts = crate::native::native_serve_opts(&native);
        // WireGuard gate mode (`serve --wg-key/--wg-peers`): the gate must own the public UDP
        // socket BEFORE any plane binds — QUIC + the data plane are loopback-only inside it.
        crate::native::spawn_wg_gate(&native_opts)?;
        // The hook runner consumes the live event tail for the host's lifetime — spawned BEFORE
        // `host.started` is emitted so operator hooks observe the full lifecycle (RFC §6).
        tokio::spawn(crate::hooks::runner());
        // Lifecycle events (RFC §4): `host.started` as the serve planes come up; `host.stopping`
        // when they wind down (clean end OR error exit) — the ring holds it for a consumer that
        // reconnects, and a graceful-signal path can move the emit earlier when one exists.
        crate::events::emit(crate::events::EventKind::HostStarted {
            version: env!("CARGO_PKG_VERSION").to_string(),
            gamestream,
        });
        let served: anyhow::Result<()> = if gamestream {
            // WP19: `gamestream` can only be true when the feature is compiled in — serve()'s
            // top bails otherwise — so the native-only build's arm is a plain unreachable.
            #[cfg(not(feature = "gamestream"))]
            {
                unreachable!("serve() refuses --gamestream in a native-only build")
            }
            #[cfg(feature = "gamestream")]
            {
                // Unified host: GameStream compat planes + native + mgmt. The `_nvstream` advert is
                // fatal on failure when enabled (Moonlight clients can't find the host without it) —
                // `--no-mdns` / PUNKTFUNK_MDNS=0 skips it for multicast-dead environments (stock
                // Moonlight then needs a manually-added host).
                let _advert = if native.mdns {
                    Some(mdns::advertise(&state.host).context("mDNS advertise")?)
                } else {
                    tracing::info!(
                        "GameStream mDNS advertisement disabled (--no-mdns / PUNKTFUNK_MDNS)"
                    );
                    None
                };
                rtsp::spawn(state.clone()).context("start RTSP server")?;
                // WP0 (rust-safety): the ENet control port is the host's one pre-auth-reachable
                // unsafe surface (`rusty_enet` is a transpiled C stack), so it binds only while a
                // pairing exists — a never-paired host on a hostile LAN exposes no ENet at all.
                // Pairing is HTTPS on nvhttp and never touches 47999; phase 4 re-syncs the port the
                // moment the first client pins, so it is up before that client can `/launch`.
                state.control_gate.enable();
                sync_control(&state).context("start ENet control server")?;
                tracing::info!(
                    port = native.port,
                    "unified host: GameStream/Moonlight compat + native punktfunk/1 (QUIC)"
                );
                tokio::try_join!(
                    nvhttp::run(state.clone()),
                    crate::mgmt::run(
                        state.clone(),
                        mgmt,
                        Some(np.clone()),
                        stats.clone(),
                        gamestream,
                        native_ident.clone(),
                    ),
                    crate::native::serve(
                        native_opts,
                        native.mgmt_port,
                        np,
                        stats.clone(),
                        native_ident
                    ),
                )
                .map(|_| ())
            }
        } else {
            // Secure default: native punktfunk/1 + management API only (no GameStream surface).
            tracing::info!(
                port = native.port,
                "secure host: native punktfunk/1 (QUIC) + management API \
                 (GameStream OFF — pass --gamestream for stock-Moonlight compat)"
            );
            tokio::try_join!(
                crate::mgmt::run(
                    state.clone(),
                    mgmt,
                    Some(np.clone()),
                    stats.clone(),
                    gamestream,
                    native_ident.clone(),
                ),
                crate::native::serve(
                    native_opts,
                    native.mgmt_port,
                    np,
                    stats.clone(),
                    native_ident
                ),
            )
            .map(|_| ())
        };
        crate::events::emit(crate::events::EventKind::HostStopping);
        served
    })
}

/// Host wall clock, unix seconds — the clock every per-client-access deadline is stored in and
/// evaluated against (design/per-client-access.md §4: wall time at each check, no cached
/// monotonic offset, so an NTP step moves a deadline with the clock). Shared by the nvhttp
/// launch gates and the control thread's expiry check.
#[cfg(feature = "gamestream")]
pub(crate) fn wall_unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// The name this host shows up under everywhere a human sees it: Moonlight's host tile (the
/// serverinfo `<hostname>` element) and Punktfunk's own client lists (the mDNS service *instance*
/// name of both adverts). `PUNKTFUNK_HOST_NAME` wins — that's the point of the knob, a box whose
/// machine name is `bazzite-htpc` can present itself as "Living Room" — otherwise it's the machine's
/// own hostname, as it always was.
fn hostname_string() -> String {
    if let Some(n) = pf_host_config::config().host_name.as_deref() {
        return sanitize_display_name(n);
    }
    machine_hostname()
}

/// The raw machine hostname (no `PUNKTFUNK_HOST_NAME` override, no display sanitizing) — what a
/// certificate SAN or a DNS-ish consumer wants, as opposed to [`hostname_string`]'s free-text
/// display name.
pub(crate) fn machine_hostname() -> String {
    #[cfg(target_os = "windows")]
    if let Some(n) = std::env::var_os("COMPUTERNAME") {
        let s = n.to_string_lossy().trim().to_string();
        if !s.is_empty() {
            return s;
        }
    }
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "punktfunk-host".to_string())
}

/// Make an operator-supplied host name safe to carry as an mDNS service instance name. Spaces and
/// punctuation are fine there ("Living Room PC" is a perfectly legal instance name), but two things
/// are not: a `.` splits the instance label — and clients derive the display name as the first label
/// of the fullname (`pf-client-core::discovery`), so "Ben's PC v1.2" would arrive as "Ben's PC v1" —
/// and DNS-SD caps a label at 63 bytes. Control characters go too.
fn sanitize_display_name(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '.' { '-' } else { c })
        .collect();
    // Truncate on a char boundary so multi-byte names can't produce invalid UTF-8.
    let mut out = String::new();
    for c in cleaned.trim().chars() {
        if out.len() + c.len_utf8() > 63 {
            break;
        }
        out.push(c);
    }
    let out = out.trim().to_string();
    if out.is_empty() {
        "punktfunk-host".to_string()
    } else {
        out
    }
}

/// Load the persisted host uniqueid, or mint one (from the kernel UUID source) and store it.
fn load_or_create_uniqueid() -> Result<String> {
    let path = pf_paths::config_dir().join("uniqueid");
    if let Ok(s) = std::fs::read_to_string(&path) {
        let t = s.trim();
        if !t.is_empty() {
            return Ok(t.to_string());
        }
    }
    let id = std::fs::read_to_string("/proc/sys/kernel/random/uuid")
        .map(|u| u.trim().replace('-', ""))
        .unwrap_or_else(|_| format!("{:016x}{:016x}", std::process::id(), HTTP_PORT));
    std::fs::create_dir_all(pf_paths::config_dir()).ok();
    std::fs::write(&path, &id).with_context(|| format!("write {}", path.display()))?;
    Ok(id)
}

/// Best-effort primary LAN IP: open a UDP socket "toward" a public address and read the
/// local address the OS would route through. No packets are actually sent.
fn primary_local_ip() -> Option<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip())
}

/// Where the paired-client allow-list persists (survives host restarts, like Sunshine).
fn paired_path() -> Option<std::path::PathBuf> {
    // Same dir as the host identity (HOME/.config/punktfunk on Linux, %APPDATA%\punktfunk on Windows).
    Some(pf_paths::config_dir().join("paired.json"))
}

/// Load the persisted paired-client certificate DERs (empty on first run / parse failure).
fn load_paired() -> Vec<Vec<u8>> {
    let Some(path) = paired_path() else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read(&path) else {
        return Vec::new();
    };
    match serde_json::from_slice::<Vec<Vec<u8>>>(&raw) {
        Ok(v) => {
            tracing::info!(clients = v.len(), "loaded persisted pairings");
            v
        }
        Err(e) => {
            tracing::warn!(error = %e, "paired.json unreadable — starting unpaired");
            Vec::new()
        }
    }
}

/// Persist the paired-client allow-list (called after each successful pairing). Written
/// atomically (temp file + rename) so a crash mid-write can't truncate `paired.json` — a partial
/// write would otherwise lock out every paired client until they re-pair.
pub(crate) fn save_paired(paired: &[Vec<u8>]) {
    let Some(path) = paired_path() else { return };
    if let Some(dir) = path.parent() {
        let _ = pf_paths::create_private_dir(dir);
    }
    let bytes = match serde_json::to_vec(paired) {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "serializing pairings failed");
            return;
        }
    };
    // Write to a sibling temp file (owner-only, so a local user can't tamper the allow-list), then
    // rename over the target (atomic replace on Unix and Windows). Never write `path` in place.
    let tmp = path.with_extension("json.tmp");
    if let Err(e) = pf_paths::write_secret_file(&tmp, &bytes) {
        tracing::warn!(error = %e, "persisting pairings failed (temp write)");
        return;
    }
    if let Err(e) = std::fs::rename(&tmp, &path) {
        tracing::warn!(error = %e, "persisting pairings failed (rename)");
        let _ = std::fs::remove_file(&tmp);
    }
}

#[cfg(test)]
mod host_name_tests {
    use super::sanitize_display_name;

    /// The display name rides the mDNS service INSTANCE label, and clients read it back as the
    /// first label of the fullname — so a `.` truncates the name in every client list. Split from
    /// the env read: `PUNKTFUNK_HOST_NAME` is process-global and must not race the parallel suite.
    #[test]
    fn display_name_survives_free_text_but_loses_the_label_breakers() {
        assert_eq!(sanitize_display_name("Living Room PC"), "Living Room PC");
        assert_eq!(sanitize_display_name("  Wohnzimmer  "), "Wohnzimmer");
        // A dot would otherwise cut the name short client-side ("Ben's PC v1").
        assert_eq!(sanitize_display_name("Ben's PC v1.2"), "Ben's PC v1-2");
        assert_eq!(sanitize_display_name("Küche ☕"), "Küche ☕");
        assert_eq!(sanitize_display_name("tab\there"), "tabhere");
        // Never empty — an empty instance name is not registerable.
        assert_eq!(sanitize_display_name("   "), "punktfunk-host");
        // 63-byte DNS-SD label ceiling, truncated on a char boundary.
        let long = sanitize_display_name(&"ü".repeat(100));
        assert!(long.len() <= 63, "{} bytes", long.len());
        assert_eq!(long, "ü".repeat(31));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;

    fn test_state() -> AppState {
        let host = Host {
            hostname: "test-host".into(),
            uniqueid: "deadbeef".into(),
            local_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            http_port: HTTP_PORT,
            https_port: HTTPS_PORT,
            os_chain: "linux".into(),
            os_name: "Linux".into(),
        };
        let stats = crate::stats_recorder::StatsRecorder::new(std::env::temp_dir().join(format!(
            "pf-gs-endsession-{}-{:p}",
            std::process::id(),
            &0u8 as *const u8
        )));
        // Both build flavors: the session teardown under test is feature-independent.
        #[cfg(feature = "gamestream")]
        {
            let identity = cert::ServerIdentity::ephemeral().expect("ephemeral identity");
            AppState::new(host, identity, stats)
        }
        #[cfg(not(feature = "gamestream"))]
        {
            AppState::new(host, stats)
        }
    }

    /// `end_session` is THE compat-plane teardown: one call must clear the whole session — both
    /// media-thread flags, the launch, and the negotiated stream config — and be idempotent.
    /// Guards the ENet-Disconnect / client-unreachable paths that previously stopped nothing
    /// (the "session stays alive after the client disconnects" bug).
    #[test]
    fn end_session_clears_the_whole_session() {
        use std::sync::atomic::Ordering;
        let state = test_state();
        state.streaming.store(true, Ordering::SeqCst);
        state.audio_streaming.store(true, Ordering::SeqCst);
        *state.launch.lock().unwrap() = Some(LaunchSession {
            gcm_key: [0; 16],
            rikeyid: 0,
            width: 1920,
            height: 1080,
            fps: 60,
            appid: 1,
            peer_ip: None,
            owner_fp: None,
        });
        #[cfg(feature = "gamestream")]
        {
            *state.stream.lock().unwrap() = Some(stream::StreamConfig {
                width: 1920,
                height: 1080,
                fps: 60,
                packet_size: 1024,
                bitrate_kbps: 20_000,
                codec: crate::encode::Codec::H265,
                min_fec: 0,
                hdr: false,
                slices: 1, // the no-request default — hardware decoders get single-slice AUs
            });
        }

        assert!(state.end_session("test"), "video was live");
        assert!(!state.streaming.load(Ordering::SeqCst));
        assert!(!state.audio_streaming.load(Ordering::SeqCst));
        assert!(state.launch.lock().unwrap().is_none());
        #[cfg(feature = "gamestream")]
        assert!(state.stream.lock().unwrap().is_none());

        // Idempotent: a second end (e.g. `/cancel` racing the ENet Disconnect) is a no-op.
        assert!(!state.end_session("test again"));
    }

    /// The compat plane has no close code, so the difference between "the player stopped" and "the
    /// client vanished" lives entirely in this flag — and it decides whether a display lingers and
    /// whether an operator's end-game policy sees a decision or a network blip. A teardown that
    /// forgets to set it silently downgrades a deliberate stop to a drop.
    #[test]
    fn quit_marks_a_teardown_deliberate_and_a_plain_end_does_not() {
        use std::sync::atomic::Ordering;
        let state = test_state();
        assert!(
            !state.quit.load(Ordering::SeqCst),
            "a fresh session is undecided"
        );

        // A drop (ENet vanish / unreachable client) must leave it clear.
        state.streaming.store(true, Ordering::SeqCst);
        state.end_session("client unreachable");
        assert!(!state.quit.load(Ordering::SeqCst));

        // `/cancel`, the management stop and a game exiting all go through `quit_session`.
        state.streaming.store(true, Ordering::SeqCst);
        assert!(state.quit_session("client /cancel"), "video was live");
        assert!(state.quit.load(Ordering::SeqCst));
        // …and it still performs the full teardown.
        assert!(!state.streaming.load(Ordering::SeqCst));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn secrets_are_written_owner_only() {
        let dir = std::env::temp_dir().join(format!("pf-secret-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        pf_paths::create_private_dir(&dir).expect("create private dir");
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "config dir must be owner-only (0700)");

        let key = dir.join("key.pem");
        pf_paths::write_secret_file(&key, b"-----BEGIN PRIVATE KEY-----\n...")
            .expect("write secret");
        let fmode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600, "private key must be owner-only (0600)");

        // Overwriting an existing secret keeps it 0600 (the truncate+reopen path).
        pf_paths::write_secret_file(&key, b"new contents").expect("rewrite secret");
        let fmode = std::fs::metadata(&key).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
