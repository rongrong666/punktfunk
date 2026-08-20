//! Session controller: the worker thread runs connect → pump (video pull + decode +
//! stats), a dedicated audio thread pulls + Opus-decodes the audio plane (Apple
//! `SessionAudio` parity — audio never waits behind a video decode), both feeding the GTK
//! main loop / PipeWire over channels. The UI keeps the `Arc<NativeClient>` from the
//! `Connected` event for direct input sends (no extra hop on the input path) —
//! `NativeClient` is `Sync`, planes stay one-consumer-per-thread: video here, audio on
//! its own thread, rumble+hidout on the gamepad thread.

use crate::audio;
use crate::video::{DecodedFrame, DecodedImage, Decoder};
use punktfunk_core::client::NativeClient;
use punktfunk_core::config::{CompositorPref, GamepadPref, Mode};
use punktfunk_core::reanchor::{index_gap, GateVerdict, ReanchorGate};
use punktfunk_core::PunktfunkError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// `Clone` so an embedder can keep the params a session was started with and re-dial with
/// one field changed — which is what the codec fallback ([`SessionEvent::CodecFallback`])
/// needs and the only reason the derive exists. Every field is either plain data or an
/// `Arc` the retry deliberately SHARES: the same `force_software` flag and the same
/// presenter-written `latch_grid`, because they belong to the presenter, not the session.
#[derive(Clone)]
pub struct SessionParams {
    pub host: String,
    pub port: u16,
    pub mode: Mode,
    pub compositor: CompositorPref,
    pub gamepad: GamepadPref,
    pub bitrate_kbps: u32,
    /// Requested audio channel count (2/6/8); the host echoes the resolved value.
    pub audio_channels: u8,
    /// The requested audio format — a stored [`AUDIO_FORMATS`] value
    /// ([`crate::trust::Settings::audio_format`]), `"opus"` for every ordinary session.
    ///
    /// A REQUEST, never a fact. It is filtered here against what this box can play and what
    /// [`audio_channels`](Self::audio_channels) resolved to, then the HOST runs its own
    /// five-condition gate and may answer Opus anyway — read `NativeClient::audio_codec` /
    /// `_sample_rate_hz` / `_bits` for what actually happened. A `String` rather than an enum
    /// because it comes straight out of a settings file a newer client may have written; an
    /// unknown value resolves to Opus rather than refusing a connect over a dropdown.
    ///
    /// `PUNKTFUNK_AUDIO_HIRES` overrides it — see `requested_audio_format` (not linked: it is
    /// private, and a public item may not link into the crate's internals).
    pub audio_format: String,
    /// The user's preferred video codec (a `quic::CODEC_*` bit, `0` = auto). Soft — the host honors
    /// it when it can emit it, else falls back; the resolved codec drives the decoder.
    pub preferred_codec: u8,
    /// `quic::CODEC_*` bits to REMOVE from this session's advertised decode caps.
    ///
    /// `0` for every ordinary connect. It is set by a retry after
    /// [`SessionEvent::CodecFallback`]: a session whose codec exhausted the decode ladder
    /// (in practice HEVC, whose CPU rung M8 removed — no permissively licensed software
    /// HEVC decoder exists) comes back advertising the codec set the host must pick
    /// from instead. The codec is fixed at Welcome and the control stream renegotiates
    /// shard payload only, so a fresh Hello is the ONLY lever; this field is it.
    pub exclude_codecs: u8,
    /// The advertised `quic::VIDEO_CAP_*` bits. Normally 10-bit + HDR (Main10/PQ: the
    /// Vulkan presenter decodes P010 everywhere and presents PQ on an HDR10 swapchain
    /// where the desktop offers one, tonemapping in the CSC shader where it doesn't;
    /// the host still gates the upgrade behind its own PUNKTFUNK_10BIT policy) — `0`
    /// when the user turned HDR off in Settings ("never send me 10-bit").
    pub video_caps: u8,
    /// This display's HDR colour volume (primaries/white/luminance), when the embedder can read
    /// it from the OS. Rides `Hello::display_hdr` → the host's virtual-display EDID, so host apps
    /// tone-map to THIS panel. `None` = unknown/SDR (host EDID defaults). Overridable for testing
    /// via `PUNKTFUNK_CLIENT_PEAK_NITS` (synthesizes a BT.2020 volume at that peak).
    pub display_hdr: Option<punktfunk_core::quic::HdrMeta>,
    /// Stream the default microphone to the host's virtual mic source.
    pub mic_enabled: bool,
    /// Run the uplink through the platform's echo cancellation ([`Settings::echo_cancel`]).
    /// Ignored when `mic_enabled` is false; `PUNKTFUNK_NO_AEC=1` overrides it off.
    pub echo_cancel: bool,
    /// Render the host's per-pad DualSense voice-coil haptics stream (0xD1 kind 0) on a wired
    /// physical DualSense ([`crate::trust::Settings::pad_haptics`]). With `pad_speaker` it
    /// gates the `CLIENT_CAP_PAD_AUDIO` advertisement and the pad-audio renderer thread.
    pub pad_haptics: bool,
    /// Where the DualSense built-in-speaker stream (0xD1 kind 1) goes: `"pad"` | `"mix"` |
    /// `"off"` ([`crate::trust::Settings::pad_speaker`]; `"mix"` is a TODO that renders as
    /// off — see [`crate::pad_audio::speaker_active`]).
    pub pad_speaker: String,
    /// Share the clipboard with this host (the per-host `KnownHost::clipboard_sync`). The
    /// bridge additionally needs the host to advertise `HOST_CAP_CLIPBOARD`.
    pub clipboard: bool,
    /// Advertise `quic::CLIENT_CAP_CURSOR`: this embedder renders the host cursor locally
    /// (the presenter's cursor channel, design/remote-desktop-sweep.md M2), so the host may
    /// stop compositing the pointer into the video. Only set when the embedder actually
    /// draws it (the SDL presenter in desktop mouse mode) — a session that advertises it
    /// without rendering streams with NO visible cursor. The host answers `HOST_CAP_CURSOR`
    /// when its capture can forward (Linux portal, not gamescope/Windows).
    pub cursor_forward: bool,
    /// Video decoder preference (Settings; `PUNKTFUNK_DECODER` overrides — see
    /// `video::Decoder::new`).
    pub decoder: String,
    /// Library id for the host to launch this session (`"steam:570"`, from the library
    /// page); `None` = plain desktop session.
    pub launch: Option<String>,
    /// The presenter's shared Vulkan device, when its stack can run Vulkan Video decode
    /// (decode lands as VkImages the presenter samples directly).
    pub vulkan: Option<crate::video::VulkanDecodeDevice>,
    /// Pinned host fingerprint; `None` = trust on first use (caller persists the observed one).
    pub pin: Option<[u8; 32]>,
    pub identity: (String, String),
    /// How long to wait for the handshake. The normal path uses a short budget; the
    /// "request access" (delegated-approval) path uses a long one, because the host PARKS the
    /// connection until the operator clicks Approve in its console (so this must exceed the
    /// host's approval window — see `PENDING_APPROVAL_WAIT`).
    pub connect_timeout: Duration,
    /// Raised by the PRESENTER when hardware frames can't be displayed (GL converter init
    /// failed / dmabuf import rejected): the pump demotes the decoder to software and
    /// re-requests a keyframe. Decode itself succeeds in that state, so nothing else
    /// would recover — without this the stream stays black.
    pub force_software: Arc<AtomicBool>,
    /// Name of the settings profile these params were resolved with (`None` = the global
    /// defaults). Display only — every value it influenced is already baked into the fields
    /// above; it rides along so the stats overlay can answer "which profile am I on?" without
    /// re-reading any store (design/client-settings-profiles.md §5.2).
    pub profile: Option<String>,
    /// The stats-overlay tier THIS launch resolved to — the globals, or the profile bound to
    /// this host. Presentation-tier, like [`profile`](Self::profile): the session controller
    /// never reads it, it rides along so the presenter can adopt it when a browse-mode launch
    /// starts.
    ///
    /// That adoption is the whole point. The console (Gaming Mode / Decky) builds its window
    /// and its run loop ONCE and streams many sessions through them, so a tier taken only from
    /// the loop's start-of-process options could never change again — a user picking a tier in
    /// the console's settings screen saw the row move, the file updated, and every stream keep
    /// the old overlay until the app was restarted. Carrying it per launch is what lets the
    /// choice land on the next stream, and it makes a profile's `stats_verbosity` reach the
    /// console too. The in-stream cycle chord still wins for the rest of the stream it moved.
    pub stats_verbosity: crate::trust::StatsVerbosity,
    /// Advertise `quic::CLIENT_CAP_PHASE_LOCK`: this embedder's presenter has REAL on-glass
    /// latch stamps (`VK_KHR_present_wait`) and will feed [`latch_grid`](Self::latch_grid),
    /// so the pump sends the ~1 Hz `PhaseReport`s the host phase-locks its capture tick to
    /// (design/phase-locked-capture.md — previously Apple/Android only). Never set without
    /// present timing: the host arms on report receipt, but the Hello should say what the
    /// client actually does.
    pub phase_lock: bool,
    /// The presenter-written latch grid the pump's reports are computed from.
    pub latch_grid: Arc<LatchGrid>,
}

/// The presenter's display-latch grid, shared presenter → pump (the `force_software`
/// pattern in the other direction): the presenter's 1 Hz present-timing fold writes a
/// recent on-glass latch instant plus the panel period; the pump's stats window folds its
/// per-AU arrival stamps against them into the ~1 Hz `PhaseReport`. All zeros until the
/// first fold — and forever when present timing isn't available — so the pump simply
/// stays quiet then.
#[derive(Default)]
pub struct LatchGrid {
    /// A recent on-glass latch instant (client `CLOCK_REALTIME` ns — the same domain as
    /// the AU arrival stamps). Any grid point works; the report extrapolates forward.
    pub anchor_ns: std::sync::atomic::AtomicU64,
    /// The panel's latch period (ns). `0` = no grid yet.
    pub period_ns: std::sync::atomic::AtomicU64,
}

/// The session pump's share of the unified stats window (design/stats-unification.md):
/// stream facts plus the two stages measured before the presenter. The frame consumer in
/// `ui_stream` contributes the `display` stage and the end-to-end percentiles.
#[derive(Clone, Copy, Default)]
pub struct Stats {
    /// AUs received (reassembled) per second, actual-elapsed-time denominator.
    pub fps: f32,
    /// Received payload bytes × 8 / elapsed (goodput, excludes FEC overhead).
    pub mbps: f32,
    /// p50 `host+network` stage: capture → received, host-clock corrected (ms).
    pub host_net_ms: f32,
    /// p50 `host` stage: the host's own capture→fully-sent, from the per-AU 0xCF host
    /// timings (design/stats-unification.md Phase 2). Valid only when `split`.
    pub host_ms: f32,
    /// p50 `network` stage: capture→received minus the host-reported share
    /// (`hostnet − host`, per-frame, saturating). Valid only when `split`.
    pub net_ms: f32,
    /// The window had matched host timings — the OSD splits `host+network` into
    /// `host + network`. An old host never emits 0xCF, so this stays false and the
    /// combined stage renders unchanged.
    pub split: bool,
    /// p50 host STAGE split (latency plan T0.1), valid only when `staged`: capture→submit
    /// queue age, encoder submit→bitstream, seal/FEC + send-channel wait (the residual
    /// `host − queue − encode − pace`), and the paced-send spread. Together they tile
    /// `host_ms`, giving per-stage attribution without a host-side log in hand.
    pub host_queue_ms: f32,
    pub host_encode_ms: f32,
    pub host_xfer_ms: f32,
    pub host_pace_ms: f32,
    /// The window had extended (staged) 0xCF timings — a host older than the stage tail
    /// sends the 13-byte form and the OSD keeps the plain `host` figure.
    pub staged: bool,
    /// p50 `decode` stage: received → decode COMPLETE, single-clock client-local (ms).
    /// Hardware paths measure GPU completion via the frame's timeline fence (an async
    /// decoder's submission returning in ~0.1 ms is not "decoded"); software measures
    /// the synchronous CPU decode.
    pub decode_ms: f32,
    /// Whether `decode_ms` OVERLAPS the presenter's `display` stage instead of tiling
    /// with it — true on the asynchronous native-Vulkan rung, false everywhere else.
    ///
    /// The other stages are a per-frame partition of `e2e`: `pts →(host+net)→ received
    /// →(decode)→ decoded →(display)→ displayed`. That holds while `decoded` is a
    /// COMPLETION stamp, which it is on the synchronous rungs. On the native-Vulkan rung
    /// `receive_frame` returns at SUBMISSION (~0.1 ms) and the stamp shipped to the
    /// presenter is taken there, so the GPU decode happens INSIDE the `display` stage —
    /// `host+net` and `display` already tile `e2e` between them, and `decode` (measured
    /// received → fence-complete) re-counts the GPU work that `display` contains.
    ///
    /// A 2026-08-13 field report read the row as a breakdown and asked why the parts did
    /// not add up: `host 5.4 · net 0.3 · decode 6.6 · display 1.4` against `e2e 8.1`. They
    /// do add up — without `decode` (5.4 + 0.3 + 1.4 ≈ 8.1). The figure is a true reading
    /// of a real quantity sitting in a row that reads like a partition, so the OSD renders
    /// it off that line rather than beside stages it does not tile with.
    pub decode_overlaps_display: bool,
    /// Unrecoverable network frame drops this window, and their share of
    /// received+lost (%). The OSD renders the counter line only when nonzero.
    pub lost: u32,
    pub lost_pct: f32,
    /// Mic uplink frames this window: handed to the QUIC datagram send, and shed anywhere
    /// client-side (queue-full at the producer + the pump's stale-oldest backlog governor —
    /// see [`NativeClient::mic_stats`]). Both stay 0 while the mic is off OR muted (a mute
    /// stops the sending, not the capture), so the OSD renders the mic line only while voice
    /// is actually going out — the muted case has its own badge, which does not need stats on.
    pub mic_sent: u32,
    pub mic_dropped: u32,
    /// How much decoded audio is queued ahead of the speaker right now (ms) — the playback
    /// ring's depth.
    ///
    /// The audio plane used to publish nothing any surface could render: depth and target existed
    /// only as a `tracing::debug!` line, and on a Steam Deck the client runs under Steam's
    /// `reaper` with its stdout on a pipe, so the one number that identifies a deep ring was
    /// unobtainable on the device reporting the latency. A field investigation ran to its
    /// conclusion without it. That is the gap this closes.
    pub audio_buffer_ms: u32,
    /// The A/V sync loop's smoothed offset (ms): **positive = audio playing BEHIND the picture**,
    /// negative = ahead of it. `0` before the loop has evidence, or with sync disabled.
    ///
    /// This is the figure that says whether audio is placed correctly, and it is the one the
    /// overhaul is judged by — an absolute buffer depth cannot distinguish "deep because the link
    /// needs it" from "deep and therefore late".
    pub audio_av_offset_ms: i32,
    /// The host RESOLVED the lossless `0xD3` PCM plane for this session (`AUDIO_CODEC_PCM`);
    /// false on the Opus plane every ordinary session runs.
    ///
    /// The RESOLVED format, emphatically not the requested one — the whole reason it is published.
    /// The Settings screen shows what this device ASKED for, and the host's five-condition gate
    /// (`design/hi-res-audio.md` §8.4, and its own switch is off by default) can decline every one
    /// of them, leaving a session that looks, sounds and measures exactly like a granted one. An
    /// OSD reading "lossless" on a session the host refused is §4.3's bug wearing a different hat,
    /// and this is the only surface that can answer it.
    pub audio_lossless: bool,
    /// The RESOLVED sample rate (Hz) and sample depth (bits) of the audio plane — what the decoder
    /// and the output device were actually built from, straight off the Welcome.
    ///
    /// `0` means the host said nothing, which an old host always does; a renderer must treat that
    /// as "no reading" rather than as a rate (`spawn_audio` folds it to the legacy 48 kHz for its
    /// own arithmetic, but the OSD has nothing honest to print).
    pub audio_rate_hz: u32,
    pub audio_bits: u8,
    /// The decode path frames actually took this window (`"vaapi"`/`"software"`, empty
    /// until the first frame) — the OSD's trailing tag; tracks a mid-session fallback.
    pub decoder: &'static str,
    /// The encoder's CURRENT target bitrate (kbps): the Welcome resolve, then live per
    /// `BitrateChanged` ack. What `mbps` (measured goodput) is judged AGAINST — a user
    /// staring at "19 Mb/s" can't otherwise tell "the encoder is capped at 20" from "my
    /// 200 Mb/s ask was honoured and this scene is cheap" (the gap that let the
    /// settings-drop bug ship four releases). `0` = an old host that never reported one.
    pub target_kbps: u32,
    /// Automatic bitrate is armed (ABR moves `target_kbps` on its own) — the OSD tags the
    /// target `(auto)` so a moving figure reads as policy, not a broken setting.
    pub auto_rate: bool,
    /// The host resolved full-chroma 4:4:4 for this session (`Welcome::chroma_format`).
    pub chroma_444: bool,
    /// This session ADVERTISED `VIDEO_CAP_444` (the Settings "Full chroma" opt-in): with
    /// `chroma_444` false, the host declined — the OSD says so instead of leaving the
    /// switch's effect unobservable.
    pub asked_444: bool,
    /// The decode lane can answer integrity questions AT ALL (M4). True on the native
    /// hardware rungs and false on the CPU rung and PyroWave. It exists because the
    /// libavcodec rungs it was written against could NOT answer — their Vulkan decoder
    /// created no status queries (`nb_queries = 0`), never set `AV_FRAME_FLAG_CORRUPT`,
    /// and reported trouble only as log lines, which is why the Xbox Ally X corruption
    /// was undetectable rather than merely undetected.
    ///
    /// Everything below is meaningless without it, and a surface that renders the
    /// four counters as zeros on a lane that cannot see damage is repeating the
    /// exact mistake this program exists to end: "clean" and "unmeasured" are not
    /// the same claim.
    pub decode_integrity: bool,
    /// AUs whose plan needed CONCEALMENT this window — a lost reference, a
    /// `frame_num` gap, a short NALU walk. Each one cost a frame (released unshown)
    /// and a re-anchor request.
    pub decode_damaged: u32,
    /// Frames the DRIVER reported corrupt this window through their per-op
    /// `RESULT_STATUS` query — the Xbox Ally X class, and the count no libavcodec rung
    /// could ever produce. Always 0 where `decode_status_queries` is false: there is no
    /// verdict to read, not nothing to report. (`video::DecodeHealth::note`
    /// enforces that, so the two fields can never contradict each other here.)
    pub decode_failed: u32,
    /// AUs the decoder REFUSED outright this window — a plan error, a
    /// Vulkan/session failure. Distinct from `decode_damaged`, and the difference
    /// is the whole diagnosis: concealment means the decoder coped with a damaged
    /// stream, refusal means it could not run and the screen is frozen. A rung
    /// refusing every AU used to report as a perfectly clean session.
    pub decode_refused: u32,
    /// Consecutive AUs with no showable picture as of this window's end (0 = the
    /// stream is decoding clean right now). The field that separates a lossy link
    /// from a stream that never came back — see `video::DecodeHealth::run`.
    pub concealed_run: u32,
    /// The LONGEST such run of the session so far — session-cumulative, not
    /// windowed, and deliberately so: `concealed_run` is an instant sampled once a
    /// second, which misses the bad moment almost every time. A window whose
    /// `concealed_run` is 0 and whose `worst_concealed_run` is 40 is a session that
    /// froze hard and recovered, and no other field on this struct says that.
    pub worst_concealed_run: u32,
    /// The device answers per-op decode-status queries (`queryResultStatusSupport`).
    /// FALSE on RADV, where recording one HANGS the VCN ring, and there the integrity
    /// report covers the parser's half only.
    pub decode_status_queries: bool,
}

/// Frames the pump keeps waiting for their 0xCF host timing (pts → capture→received µs).
/// ~2 s at 120 Hz — a timing arrives within a frame or two of its AU, and against an old
/// host (no 0xCF at all) this just caps the dead-weight ring.
const PENDING_SPLIT_CAP: usize = 256;

/// Sort a window of µs samples in place and return `(p50, p95)` per the spec's index
/// rules (`sorted[len/2]`, `sorted[min(len*95/100, len-1)]`); an empty window reads 0.
pub fn window_percentiles(samples: &mut [u64]) -> (u64, u64) {
    if samples.is_empty() {
        return (0, 0);
    }
    samples.sort_unstable();
    let p50 = samples[samples.len() / 2];
    let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
    (p50, p95)
}

pub enum SessionEvent {
    Connected {
        connector: Arc<NativeClient>,
        mode: Mode,
        fingerprint: [u8; 32],
    },
    /// `trust_rejected` is set when the connect failed the TLS trust check (a `Crypto`
    /// error): for a pinned connect this is the fingerprint-changed signal, so the UI can
    /// offer a re-pair (PIN) path rather than a dead-end error.
    Failed {
        msg: String,
        trust_rejected: bool,
    },
    Ended(Option<String>),
    /// The session's negotiated codec ran out of decode rungs and the client can finish
    /// this stream only as a DIFFERENT codec — terminal, like [`Self::Ended`], but with
    /// the retry already computed.
    ///
    /// The one case in practice is HEVC on a box whose hardware HEVC decode failed: M8
    /// dropped software HEVC (no permissively licensed decoder exists), so the ladder's
    /// last rung refuses instead of limping, and the answer is a reconnect advertising
    /// [`Self::CodecFallback::retry_caps`] — which never contains the codec that just
    /// failed. The other case is a picture SHAPE the CPU rung cannot decode (10-bit,
    /// 4:4:4), which is a different diagnosis with the same available action; the two
    /// pick different retry sets, and [`crate::video::last_rung_verdict`] is where that
    /// is decided.
    ///
    /// An embedder that does not implement the retry MUST still show `msg` and stop —
    /// treating it as an ordinary end is correct, just worse. It is a separate variant
    /// rather than a flag on `Ended` so the compiler asks every embedder the question
    /// once, which is how the two D3D11VA rungs' shared `stats:` tag went wrong when it
    /// was not asked (`1573a987`).
    CodecFallback {
        /// What to pass as [`SessionParams::exclude_codecs`] on the retry — DERIVED from
        /// [`Self::CodecFallback::retry_caps`], so applying it advertises exactly those
        /// caps and nothing wider.
        exclude_codecs: u8,
        /// The caps the retry will advertise — non-empty by construction, and what
        /// `exclude_codecs` above resolves to on the wire.
        retry_caps: u8,
        /// User-facing one-liner for the toast/status strip.
        msg: String,
    },
    Stats(Stats),
    /// The session's effective access (design/per-client-access.md §7): emitted once right
    /// after [`Self::Connected`] with the Welcome's advert, then again for every mid-session
    /// `AccessUpdate` the host sends (a console edit, the T−5 m / T−1 m expiry warnings) —
    /// latest wins. `notice` is the toast-worthy one-liner for a mid-session change
    /// ("Access is now Controller only", "Access ends in 5 m"); `None` on the initial
    /// snapshot and on updates with nothing worth interrupting for.
    ///
    /// Courtesy chrome only — the HOST enforces the mask whatever an embedder does with
    /// this. Embedders use it to gate capture (no pointer lock / keyboard grab without the
    /// bits) and to wear the overlay chip; a default access (full control, permanent — every
    /// old host) must render exactly today's look.
    Access {
        access: crate::access::SessionAccess,
        notice: Option<String>,
    },
}

/// How many times THIS PROCESS has had a session's codec exhaust the decode ladder — the
/// telemetry counter the risk register asks for ("telemetry on frequency") for the
/// software-HEVC drop.
///
/// Process-scoped and monotonic because the thing being counted is a property of the
/// machine, not of one session: a box whose hardware HEVC decode is broken produces one
/// of these per connect, and it is the RATE across a session history that says whether
/// dropping software HEVC hurt anybody. Read it with [`codec_fallbacks`].
static CODEC_FALLBACKS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// See [`CODEC_FALLBACKS`]. Surfaced on the session's Detailed stats block as an
/// additive `codec_fallbacks <N>` line once it is nonzero — appended last, never
/// removed, never reordered (`run.rs`'s `stats_text`).
pub fn codec_fallbacks() -> u64 {
    CODEC_FALLBACKS.load(Ordering::Relaxed)
}

/// The in-stream microphone mute (B4), shared between the embedder's toggle (a keyboard chord
/// in the presenter) and the capture callback that reads it every quantum.
///
/// Two flags, not one, so the indicator can never lie: `live` is raised by the pump only once
/// the uplink is actually running, so a session whose mic is off in Settings — or whose capture
/// device failed to open — reports "no mic here" and the chord is a documented no-op instead of
/// silently latching a mute nothing implements. Per session by design: the mute is a moment
/// ("don't send the doorbell"), not a preference, so it is never persisted and every new
/// session starts unmuted.
#[derive(Clone, Default)]
pub struct MicControl {
    muted: Arc<AtomicBool>,
    live: Arc<AtomicBool>,
}

impl MicControl {
    /// True when this session has a running uplink to mute at all.
    pub fn live(&self) -> bool {
        self.live.load(Ordering::Relaxed)
    }

    /// True when the user has muted a uplink that exists — what the OSD indicator draws.
    pub fn muted(&self) -> bool {
        self.live() && self.muted.load(Ordering::Relaxed)
    }

    /// Flip the mute. `Some(now_muted)` when it applied, `None` when this session has no
    /// uplink (the caller says so rather than pretending something happened).
    pub fn toggle(&self) -> Option<bool> {
        if !self.live() {
            return None;
        }
        let next = !self.muted.load(Ordering::Relaxed);
        self.muted.store(next, Ordering::Relaxed);
        Some(next)
    }

    /// The capture side's handle on the flag (the streamer reads it per quantum).
    fn flag(&self) -> Arc<AtomicBool> {
        self.muted.clone()
    }

    /// The pump's report that the uplink came up (or went away).
    fn set_live(&self, live: bool) {
        self.live.store(live, Ordering::Relaxed);
    }
}

pub struct SessionHandle {
    pub events: async_channel::Receiver<SessionEvent>,
    pub frames: async_channel::Receiver<DecodedFrame>,
    pub stop: Arc<AtomicBool>,
    /// The in-stream mic mute. Inert (`live()` false) until the pump has the uplink running,
    /// and for the whole session when the mic is off in Settings.
    pub mic: MicControl,
    /// The pump thread. A Vulkan-Video pump SUBMITS to the shared device's decode
    /// queue — the presenter must join this before any `vkDeviceWaitIdle`/teardown
    /// (external-sync rule over every device queue).
    pub thread: Option<std::thread::JoinHandle<()>>,
}

pub fn start(params: SessionParams) -> SessionHandle {
    let (ev_tx, ev_rx) = async_channel::unbounded();
    // Tiny frame queue, newest wins: force_send displaces the oldest when the UI lags.
    let (frame_tx, frame_rx) = async_channel::bounded(2);
    let stop = Arc::new(AtomicBool::new(false));
    let stop_w = stop.clone();
    let mic = MicControl::default();
    let mic_w = mic.clone();
    let thread = std::thread::Builder::new()
        .name("punktfunk-session".into())
        .spawn(move || pump(params, ev_tx, frame_tx, stop_w, mic_w))
        .expect("spawn session thread");
    SessionHandle {
        events: ev_rx,
        frames: frame_rx,
        stop,
        mic,
        thread: Some(thread),
    }
}

pub fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

/// The session's audio decoder — the `0xC9` Opus plane or the `0xD3` lossless PCM one, behind one
/// pair of methods so the pull loop below is plane-agnostic.
///
/// Which plane runs is decided ONCE, from `Welcome::audio_codec`, and never changes mid-session:
/// the output device is open at a fixed format, so a switch would mean a re-open (design
/// `hi-res-audio.md` §6). Nothing per-packet says which plane a datagram came from — the two share
/// a header by design — so this type is the only thing that knows.
///
/// Both arms hand back INTERLEAVED sample counts (libopus counts per channel, `pcm::to_f32` counts
/// interleaved); unifying on interleaved here is what lets the loop size its pushes, its
/// concealment and its ring reporting from one number.
struct AudioDec {
    /// The host-RESOLVED channel count, needed to turn libopus's per-channel counts into
    /// interleaved ones. The PCM arm needs it only through the frame sizing the caller does.
    channels: usize,
    kind: DecKind,
}

enum DecKind {
    /// Plain stereo libopus — the validated path.
    Stereo(opus::Decoder),
    /// Multistream libopus for 5.1/7.1, built from the shared layout table.
    Surround(opus::MSDecoder),
    /// The lossless plane: no codec and no decoder state, only the negotiated depth the wire bytes
    /// are unpacked at — plus the concealer, because **a lossless format has no PLC to borrow**
    /// (§4.5). libopus can synthesise a missing frame from its own internal state; there is
    /// nothing in a raw PCM frame to synthesise a successor from, so `PcmConceal` repeats and
    /// fades instead.
    Pcm {
        bits: u8,
        conceal: punktfunk_core::audio::pcm::PcmConceal,
    },
}

impl AudioDec {
    /// Build the decoder for the plane the host RESOLVED — `codec`/`rate_hz`/`bits` all come off
    /// the `Welcome`, never off what this client asked for.
    fn new(codec: u8, channels: u8, rate_hz: u32, bits: u8) -> Result<AudioDec, opus::Error> {
        let ch = channels.max(1) as usize;
        // A lossless session never reaches libopus, so it never has to justify its rate to it:
        // libopus accepts 8/12/16/24/48 kHz and nothing else, which is the whole reason the
        // hi-res ladder needed a second plane rather than a parameter (§2).
        if codec == punktfunk_core::quic::AUDIO_CODEC_PCM {
            // The depth is the STRIDE the wire is unpacked at, so a value the plane does not
            // define is not a cosmetic problem: core reads anything that is not 16 as 24, and a
            // mismatched stride desyncs every sample after the first. Say so rather than play
            // noise — the session still runs, because refusing would mean silence and the
            // negotiation should never produce this in the first place.
            if !punktfunk_core::audio::pcm::depth_is_supported(bits) {
                tracing::warn!(
                    bits,
                    "the host resolved a lossless depth this plane does not define — unpacking \
                     as 24-bit, which will be wrong if it meant anything else"
                );
            }
            return Ok(AudioDec {
                channels: ch,
                kind: DecKind::Pcm {
                    bits,
                    conceal: punktfunk_core::audio::pcm::PcmConceal::new(),
                },
            });
        }
        // The Opus plane is 48 kHz by construction, and `Welcome::audio_rate_hz` says so for every
        // Opus session. Taking it from the Welcome anyway (rather than repeating the literal
        // twice, as this did) means the decoder cannot disagree with the ring and the A/V-sync
        // loop about what a millisecond is.
        let kind = if channels == 2 {
            DecKind::Stereo(opus::Decoder::new(rate_hz, opus::Channels::Stereo)?)
        } else {
            let l = punktfunk_core::audio::layout_for(channels, false);
            DecKind::Surround(opus::MSDecoder::new(
                rate_hz, l.streams, l.coupled, l.mapping,
            )?)
        };
        Ok(AudioDec { channels: ch, kind })
    }

    /// Decode one arrived frame into `out`, returning its INTERLEAVED sample count (the caller
    /// reads `out[..n]`).
    ///
    /// `out` is the caller's scratch. The Opus arms decode into it as a fixed slice, so it must
    /// already be long enough for the biggest frame the plane can carry; the PCM arm hands the Vec
    /// to `pcm::to_f32`, which clears and grows it to the frame's true length — so a malformed
    /// oversized datagram cannot overrun it there.
    fn decode(&mut self, input: &[u8], out: &mut Vec<f32>) -> Option<usize> {
        let channels = self.channels;
        match &mut self.kind {
            DecKind::Stereo(d) => d.decode_float(input, out, false).ok().map(|n| n * channels),
            DecKind::Surround(d) => d.decode_float(input, out, false).ok().map(|n| n * channels),
            DecKind::Pcm { bits, conceal } => {
                // `None` here is a truncated datagram — a partial sample at the end would desync
                // every sample after it, so core rejects it outright rather than decoding a
                // shifted frame. Treated as a lost frame by the caller, which is what it is.
                let n = punktfunk_core::audio::pcm::to_f32(input, *bits, out)?;
                conceal.accept(&out[..n]);
                Some(n)
            }
        }
    }

    /// Synthesise one frame for a datagram that never arrived, into `out`; `Some(n)` = `out[..n]`
    /// is playable, `None` = nothing could be built (no frame has decoded yet) and the caller
    /// should let the ring re-prime.
    ///
    /// `interleaved` is the last good frame's length — the unit both planes conceal in. The Opus
    /// arm needs it because libopus PLC synthesises exactly the slice it is handed; the PCM arm
    /// ignores it, because `PcmConceal` already holds the frame it is repeating.
    fn conceal(&mut self, interleaved: usize, out: &mut Vec<f32>) -> Option<usize> {
        let channels = self.channels;
        match &mut self.kind {
            // `PcmConceal` already holds the frame it repeats, so it needs no size hint — and it
            // reports `false` when nothing has arrived yet to repeat from. The receiver runs
            // before the argument, so the length read here is the concealed frame's, not the
            // previous call's.
            DecKind::Pcm { conceal, .. } => conceal.conceal(out).then_some(out.len()),
            libopus => {
                // libopus PLC synthesises exactly the slice it is handed; before anything has
                // decoded there is no frame length to ask it for.
                let plc = interleaved.min(out.len());
                if plc == 0 {
                    return None;
                }
                let per_ch = match libopus {
                    DecKind::Stereo(d) => d.decode_float(&[], &mut out[..plc], false).ok()?,
                    DecKind::Surround(d) => d.decode_float(&[], &mut out[..plc], false).ok()?,
                    DecKind::Pcm { .. } => unreachable!("the PCM arm matched above"),
                };
                Some(per_ch * channels)
            }
        }
    }
}

// The audio-format vocabulary (`AUDIO_FORMAT_*`, the `AUDIO_FORMATS` table, `audio_format_wire`)
// lives in the portable `audio_format` module now — the Skia console's settings screen reads it
// on Android too, where nothing else in this file compiles. Re-exported here so every desktop
// caller's `session::AUDIO_FORMATS` spelling stays valid.
pub use crate::audio_format::{
    audio_format_wire, AUDIO_FORMATS, AUDIO_FORMAT_LOSSLESS_48, AUDIO_FORMAT_LOSSLESS_96,
    AUDIO_FORMAT_OPUS,
};

/// The lossless format this client ASKS the host for — `Some((rate_hz, bits))` when it is on,
/// `None` for the legacy Opus plane.
///
/// Two inputs, and **the environment wins**: `PUNKTFUNK_AUDIO_HIRES` overrides `setting` (the
/// user's stored [`AUDIO_FORMATS`] choice, already resolved through any settings profile).
///
/// That direction, not the reverse, for two reasons. It is how this crate treats every other
/// `PUNKTFUNK_*` lever — `PUNKTFUNK_DECODER` beats `Settings::decoder`, `PUNKTFUNK_NO_AEC` beats
/// `echo_cancel`, `PUNKTFUNK_CLIENT_PEAK_NITS` beats the panel's own volume — and a lever that
/// lost to whatever a stale profile happened to hold would be useless for the thing operators
/// actually use it for (A/B-ing one session against a field report). And the surfaces do not
/// overlap: a headless box, a Gaming-Mode kiosk and the CI probe have no settings UI at all, which
/// is exactly why the var is documented for operators rather than being removed here.
///
/// Env grammar: `1`/`true`/`on`/`yes` → 96 kHz / 24-bit (the flagship rung); `96000` → that rate at
/// 24-bit; `<48000|96000>/<16|24>` → an explicit pair, `48000/16` included — that is the cheapest
/// lossless rung and it is genuinely reachable, see [`AUDIO_FORMAT_UNSPECIFIED`], though no menu
/// row offers it. `0`/`off`/`false`/`no` force the Opus plane even when the setting asks for
/// lossless: an override that could only ever turn the feature ON would be half a lever.
///
/// ⚠ An UNSET var and an UNPARSEABLE one are not the same thing, and neither is "off". Unset means
/// the operator said nothing, so the setting decides. A typo is not an instruction either — it is
/// warned about and then IGNORED, so the setting still decides; the alternative (the pre-settings
/// behaviour, where garbage meant off) would silently defeat a switch the user had turned on in the
/// UI, which is the worse of the two failures now that there IS a UI.
fn requested_audio_format(setting: &str) -> Option<(u32, u8)> {
    resolve_audio_format(
        std::env::var("PUNKTFUNK_AUDIO_HIRES").ok().as_deref(),
        setting,
    )
}

/// The precedence half of [`requested_audio_format`], split out so the env-beats-setting rule is
/// testable without mutating the process environment — the same reason [`parse_audio_format`] is
/// its own function.
fn resolve_audio_format(env: Option<&str>, setting: &str) -> Option<(u32, u8)> {
    let Some(raw) = env else {
        return audio_format_wire(setting);
    };
    match parse_audio_format(raw) {
        AudioRequest::Legacy => None,
        AudioRequest::Hires(rate, bits) => Some((rate, bits)),
        AudioRequest::Unsupported => {
            // Loud, because the user set a lever and is not getting it — the same reason the
            // 4:4:4 fallback in `clients/session` shouts. What it falls back TO is the Settings
            // choice, which is why the message names it rather than promising Opus.
            tracing::warn!(
                value = %raw,
                setting,
                "PUNKTFUNK_AUDIO_HIRES is not a format this client can ask for — use 1, \
                 96000, 0, or <48000|96000>/<16|24>; ignoring it and using the audio-format \
                 setting instead"
            );
            audio_format_wire(setting)
        }
    }
}

/// `Hello`'s "I did not ask" for the audio format pair, which keeps the `Hello` byte-identical to
/// every pre-hi-res build's.
///
/// ⚠ **Not an explicit 48 000/16.** Core keys `CLIENT_CAP_AUDIO_HIRES` on *a format was specified*
/// rather than on *it differs from the default* — because 48 kHz/16-bit is BOTH the default and
/// the cheapest lossless rung, so a "differs from the default" rule would make it the one format
/// on the ladder nobody could ask for. `0`/`0` is what separates "not asking" from "asking for
/// 48/16 lossless", and passing an explicit 48 000/16 here would advertise hi-res on every
/// ordinary session (`design/hi-res-audio.md` §7, and `client::advertised_client_caps`).
const AUDIO_FORMAT_UNSPECIFIED: (u32, u8) = (0, 0);

/// What `PUNKTFUNK_AUDIO_HIRES` was set to, as the three answers that matter.
#[derive(Debug, PartialEq, Eq)]
enum AudioRequest {
    /// Unset or deliberately off — today's Opus plane, and no capability bit.
    Legacy,
    /// A rung the lossless plane can carry.
    Hires(u32, u8),
    /// Set to something this client cannot ask for at all.
    Unsupported,
}

/// The parse half of [`requested_audio_format`], split out so it is testable without touching the
/// process environment.
fn parse_audio_format(raw: &str) -> AudioRequest {
    use punktfunk_core::audio::pcm::{BITS_16, BITS_24};
    let v = raw.trim().to_ascii_lowercase();
    match v.as_str() {
        "" | "0" | "off" | "false" | "no" => return AudioRequest::Legacy,
        // 24-bit is the rung the plane earns its bandwidth at: 16-bit PCM would spend 1.5 Mbps to
        // sound like transparent 256 kbps Opus, so it is not what a bare "on" should mean.
        "1" | "on" | "true" | "yes" => return AudioRequest::Hires(96_000, BITS_24),
        _ => {}
    }
    // `<rate>` or `<rate>/<bits>`. Both halves are checked against what the plane can actually
    // carry rather than passed through: 44.1 kHz and its multiples are absent from the ladder
    // ON PURPOSE (they truncate `JitterPolicy`'s integer samples-per-millisecond arithmetic, §4.1),
    // and the host would decline them anyway — refusing here says so where the user can see it.
    //
    // 48 000/16 IS accepted — it is the cheapest lossless rung (1.5 Mbps against Opus's 256), and
    // core keys the capability bit on *a format was specified* rather than on *it differs from the
    // default* precisely so that this rung stays askable. Which is why the caller must send the
    // unspecified `0`/`0` when nobody asked, rather than an explicit 48 000/16.
    let (rate_s, bits_s) = v.split_once('/').unwrap_or((v.as_str(), "24"));
    match rate_s
        .trim()
        .parse::<u32>()
        .ok()
        .zip(bits_s.trim().parse::<u8>().ok())
        .filter(|&(r, b)| matches!(r, 48_000 | 96_000) && matches!(b, BITS_16 | BITS_24))
    {
        Some((r, b)) => AudioRequest::Hires(r, b),
        None => AudioRequest::Unsupported,
    }
}

fn pump(
    params: SessionParams,
    ev_tx: async_channel::Sender<SessionEvent>,
    frame_tx: async_channel::Sender<DecodedFrame>,
    stop: Arc<AtomicBool>,
    mic: MicControl,
) {
    // PUNKTFUNK_PREFER_PYROWAVE=1 — the Phase-2 lab opt-in for the wired-LAN wavelet codec
    // (a Settings toggle is the Phase-3 productization). Riding `preferred_codec` is exactly
    // the plan-§3 contract: the host only ever picks PyroWave when the client names it.
    #[allow(unused_mut)]
    let mut preferred = params.preferred_codec;
    #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
    if std::env::var("PUNKTFUNK_PREFER_PYROWAVE").as_deref() == Ok("1") {
        if params.vulkan.as_ref().is_some_and(|v| v.pyrowave_decode) {
            preferred = punktfunk_core::quic::CODEC_PYROWAVE;
        } else {
            tracing::warn!(
                "PUNKTFUNK_PREFER_PYROWAVE=1 but the presenter device failed the pyrowave probe — keeping the normal codec preference"
            );
        }
    }
    // Pad audio (0xD1): advertise only when the settings could render a stream — the per-pad
    // tier-A detection at slot open (gamepad.rs) still decides which pads declare render caps
    // on their arrivals, so this bit alone changes nothing without a wired DualSense.
    let pad_speaker_on = crate::pad_audio::speaker_active(&params.pad_speaker);
    let pad_audio_on = params.pad_haptics || pad_speaker_on;
    // What this session advertises it can decode, minus anything a previous attempt
    // proved it cannot FINISH (see `SessionParams::exclude_codecs`). Held for the whole
    // pump because the reconnect rule needs to know what was on the table, not just what
    // the host picked.
    let advertised_codecs = crate::video::decodable_codecs_for(
        params.vulkan.as_ref(),
        // The decoder pin is part of the answer: a session pinned to software has no HEVC
        // rung at all, so advertising HEVC would promise what this build cannot keep.
        &params.decoder,
    ) & !params.exclude_codecs;
    if params.exclude_codecs != 0 {
        tracing::info!(
            excluded = params.exclude_codecs,
            advertising = advertised_codecs,
            "retrying with reduced decode caps"
        );
    }
    // The lossless audio plane's client-side opt-in, filtered by what this box can genuinely
    // PLAY. `CLIENT_CAP_AUDIO_HIRES` means *capable **and** the user turned it on* — a client
    // that advertised it without being able to render it would spend 1.5–4.6 Mbps, taken off the
    // top of a link ABR can neither see nor reclaim, to play interpolation (`hi-res-audio.md` §7).
    // `Some` past this block is exactly "ask", and asking IS what sets the bit — core derives it
    // from the format pair being specified at all (see `AUDIO_FORMAT_UNSPECIFIED`).
    let hires = requested_audio_format(&params.audio_format).filter(|&(rate, _)| {
        if params.audio_channels != 2 {
            // §4.2: a hi-res surround frame does not fit one datagram at the default MTU and this
            // plane is never fragmented, so the host's gate declines it. Saying so here, where the
            // user's two settings are both visible, beats a decline logged on the other machine.
            //
            // ⚠ Not redundant with the settings UIs hiding the picker under surround. The two
            // fields are INDEPENDENT overlay keys: a profile can pin `audio_format` while the
            // global — or another profile — moves `audio_channels` to 5.1, and the env override
            // below answers to no UI at all. This is the one place both are known.
            tracing::warn!(
                channels = params.audio_channels,
                "lossless audio is stereo-only — a surround frame does not fit one QUIC \
                 datagram; asking for the default Opus plane instead"
            );
            return false;
        }
        // `can_render_at` says WHY when it declines — it is the one that read the device.
        audio::can_render_at(rate)
    });
    if let Some((rate, bits)) = hires {
        tracing::info!(rate, bits, "asking the host for the lossless audio plane");
    }
    // This pair IS the request: core derives `CLIENT_CAP_AUDIO_HIRES` from it being specified at
    // all, so `None` must reach the wire as unspecified rather than as an explicit 48 000/16.
    let (audio_rate_hz, audio_bits) = hires.unwrap_or(AUDIO_FORMAT_UNSPECIFIED);
    let connector = match NativeClient::connect_with_audio_format(
        &params.host,
        params.port,
        params.mode,
        params.compositor,
        params.gamepad,
        params.bitrate_kbps,
        params.video_caps,
        params.audio_channels,
        audio_rate_hz,
        audio_bits,
        // The codecs OUR rungs speak (`video::decodable_codecs`), plus CODEC_PYROWAVE when
        // the presenter device passed the probe, minus whatever a previous attempt proved
        // undecodable end to end.
        advertised_codecs,
        preferred, // the user's soft codec preference (0 = auto; see the pyrowave opt-in above)
        // This display's HDR volume → the host's virtual-display EDID. The env hatch wins so an
        // A/B run can pin an exact peak (PUNKTFUNK_CLIENT_PEAK_NITS=600).
        punktfunk_core::client::display_hdr_env_override().or(params.display_hdr),
        // CURSOR: this embedder renders the host cursor locally in desktop mouse mode.
        // PHASE_LOCK: the presenter has real latch stamps and the pump reports them below.
        (if params.cursor_forward {
            punktfunk_core::quic::CLIENT_CAP_CURSOR
        } else {
            0
        }) | (if params.phase_lock {
            punktfunk_core::quic::CLIENT_CAP_PHASE_LOCK
        } else {
            0
            // AUDIO_HIRES is NOT set here: core derives it from the `audio_rate_hz`/`audio_bits`
            // pair above being specified at all, which is the one rule that keeps 48 kHz/16-bit
            // lossless askable. Setting it here as well would be a second copy of that rule, and
            // setting it WITHOUT a format would advertise a request the host can only decline.
            // PAD_AUDIO: the embedder can render per-pad DualSense haptics/speaker (see above).
        }) | (if pad_audio_on {
            punktfunk_core::quic::CLIENT_CAP_PAD_AUDIO
        } else {
            0
        }),
        // Slice-progressive delivery: off — every rung here is fed whole AUs; a partial-feed
        // path can flip it later.
        false,
        params.launch.clone(),
        // The host's approval-list / trust-store label for this client. Without it every no-PIN
        // "request access" knock showed up as the fingerprint placeholder "device abcd1234".
        Some(crate::trust::device_name()),
        params.pin,
        Some(params.identity),
        params.connect_timeout,
        // THE session's stop flag, so the embedder's cancel reaches a dial that has not landed
        // yet. Without it this call parks the pump thread for the whole budget — 185 s on a
        // request-access connect the host holds pending approval — and the embedder's cancel
        // could not be answered until it returned: the console's takeover sat on "Canceling…"
        // with no session event to clear it.
        Some(stop.clone()),
    ) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            let trust_rejected = matches!(e, PunktfunkError::Crypto);
            let msg = match e {
                PunktfunkError::Crypto => {
                    "Host identity rejected — wrong fingerprint, or the host requires pairing"
                        .to_string()
                }
                PunktfunkError::Timeout => "Connection timed out".to_string(),
                // The host said WHY it turned us away (typed application close) — show that
                // verbatim instead of a generic failure: "the request was denied on the host"
                // and "connection timed out" call for very different next steps.
                PunktfunkError::Rejected(reason) => crate::trust::connect_reject_message(reason),
                other => format!("Connect failed: {other:?}"),
            };
            let _ = ev_tx.send_blocking(SessionEvent::Failed {
                msg,
                trust_rejected,
            });
            return;
        }
    };
    let _ = ev_tx.send_blocking(SessionEvent::Connected {
        connector: connector.clone(),
        mode: connector.mode(),
        fingerprint: connector.host_fingerprint,
    });
    // The Welcome's access advert, straight after Connected so the embedder can gate its
    // capture BEFORE it engages (design §7 "not capture what can't land"). Old hosts decode
    // to full-control/permanent and the embedder renders today's look unchanged.
    let mut access = crate::access::SessionAccess::from_connector(&connector);
    let _ = ev_tx.send_blocking(SessionEvent::Access {
        access,
        notice: None,
    });

    // Build the decoder for the codec the host resolved (never assume HEVC), honoring the
    // Settings backend preference (auto/native-*/software).
    //
    // The WIRE codec bit IS the vocabulary now: M10 deleted the last libavcodec rung and
    // with it `ffmpeg::codec::Id`, which this used to translate into here. That
    // translation was also a small lie in the log — its fallthrough mapped every unknown
    // wire bit, PyroWave included, to HEVC, so a wavelet session printed `codec_id=HEVC`.
    //
    // The picture shape the host RESOLVED (not what we asked for) goes with it — every
    // native rung probes its device against it at construction, so a 4:4:4 or Main 10
    // session that this GPU has no decode format for refuses BEFORE the rung is chosen
    // instead of error-streaking past it mid-stream.
    let stream_format = crate::video::StreamFormat {
        chroma_format_idc: connector.chroma_format,
        bit_depth: connector.bit_depth,
    };
    tracing::info!(
        codec = crate::video::wire_codec_name(connector.codec),
        welcome_codec = connector.codec,
        "negotiated video codec"
    );
    // A negotiated PyroWave session decodes on the presenter's device — reachable only
    // through the explicit preference above (resolve_codec never auto-picks the bit), so
    // failing loudly here is failing an opted-in experiment.
    #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
    let built = if connector.codec == punktfunk_core::quic::CODEC_PYROWAVE {
        let mode = connector.mode();
        // The wavelet bitstream has no VUI: the negotiated Welcome colour signalling IS
        // the session's colour contract (BT.709 limited SDR today, BT.2020 PQ once the
        // HDR leg lands), and the chroma the host resolved sizes the plane ring.
        let color = crate::video::ColorDesc {
            primaries: connector.color.primaries,
            transfer: connector.color.transfer,
            matrix: connector.color.matrix,
            full_range: connector.color.full_range != 0,
        };
        match params.vulkan.as_ref() {
            Some(vk) => Decoder::new_pyrowave(
                vk,
                mode.width,
                mode.height,
                connector.shard_payload as usize,
                connector.chroma_format == punktfunk_core::quic::CHROMA_IDC_444,
                color,
                connector.bit_depth >= 10,
            ),
            None => Err(anyhow::anyhow!(
                "pyrowave session without a presenter device"
            )),
        }
    } else {
        Decoder::new(
            connector.codec,
            &params.decoder,
            params.vulkan.as_ref(),
            stream_format,
        )
    };
    #[cfg(not(all(any(target_os = "linux", windows), feature = "pyrowave")))]
    let built = Decoder::new(
        connector.codec,
        &params.decoder,
        params.vulkan.as_ref(),
        stream_format,
    );
    let mut decoder = match built {
        Ok(d) => d,
        Err(e) => {
            // The ladder had NO rung for this codec at all — on a box with no hardware
            // HEVC decode (or one that pinned `PUNKTFUNK_DECODER=software` on an HEVC
            // session). Same answer as the mid-stream case below, one code path.
            let refusal = e.downcast_ref::<crate::video::NoSoftwareRung>().map(|nr| {
                codec_fallback_event(
                    connector.codec,
                    advertised_codecs,
                    nr.loss(),
                    &e.to_string(),
                )
            });
            // Nothing has been spawned yet at this point — the audio / pad / clipboard
            // threads and the mic uplink are all built BELOW — so "joined its threads" is
            // vacuously true here. Set the stop flag and drop the connector anyway, in
            // the same order the pump's end path does, so an embedder that reconnects on
            // receipt of this event finds the same world whichever refusal site produced
            // it (`run.rs` starts the retry the instant it reads one).
            stop.store(true, Ordering::SeqCst);
            mic.set_live(false);
            drop(connector);
            let _ = ev_tx.send_blocking(
                refusal.unwrap_or_else(|| SessionEvent::Ended(Some(format!("video decoder: {e}")))),
            );
            return;
        }
    };
    let force_software = params.force_software.clone();
    // Session-constant stats facts (design/stats-unification.md): what the target figure is
    // judged against and whether the 4:4:4 opt-in was honoured. `target_kbps` itself is read
    // live per window — an Automatic session's ABR moves it.
    let auto_rate = connector.wants_decode_latency();
    let chroma_444 = connector.chroma_format == punktfunk_core::quic::CHROMA_IDC_444;
    let asked_444 = params.video_caps & punktfunk_core::quic::VIDEO_CAP_444 != 0;
    // Audio is best-effort: a session without it still streams. Gamepads are the
    // app-lifetime service's job (the UI attaches it on Connected). Audio runs on its own
    // thread (one puller per plane), blocking on the audio queue like the Apple client.
    let audio_thread = spawn_audio(connector.clone(), stop.clone());
    // Pad audio (0xD1): its own drain thread (that plane's single consumer), spawned whenever
    // the settings could render. The output device is opened LAZILY once frames actually
    // arrive — which only happens after a tier-A pad declared render caps on its arrival — so
    // a session without a wired DualSense costs one idle 10 ms poll loop.
    let pad_audio_thread = pad_audio_on
        .then(|| {
            crate::pad_audio::spawn(
                connector.clone(),
                stop.clone(),
                params.pad_haptics,
                pad_speaker_on,
            )
        })
        .flatten();
    // The shared clipboard (design/clipboard-and-file-transfer.md §5): its own thread, since
    // `next_clip` blocks and the OS clipboard calls can wait on other apps. Returns straight
    // away when the host has no clipboard capability, so spawning is gated only by the
    // setting — and by the session's CLIPBOARD grant (the client half of design §5.4
    // "deny at setup": the host's coordinator never starts for an ungranted session, so a
    // bridge here would only ever collect NOT_PERMITTED refusals).
    let clipboard_thread = (params.clipboard
        && access.allows(punktfunk_core::quic::GRANT_CLIPBOARD))
    .then(|| {
        let c = connector.clone();
        let s = stop.clone();
        std::thread::Builder::new()
            .name("pf-clipboard".into())
            .spawn(move || crate::clipboard::run(c, s))
            .ok()
    })
    .flatten();
    // The uplink, and with it the mute the embedder's chord drives. `set_live` is what makes
    // the chord (and its indicator) real: a mic turned off in Settings, a capture device
    // that wouldn't open, OR a session without the MIC grant (the host would drop the
    // datagrams — don't open the capture device for a plane that can't land) leaves it
    // false and the chord stays an honest no-op. `mut`: a mid-session AccessUpdate moves
    // the grant, and the uplink follows it live below.
    let mut mic_uplink = (params.mic_enabled && access.allows(punktfunk_core::quic::GRANT_MIC))
        .then(|| {
            audio::MicStreamer::spawn(connector.clone(), mic.flag(), params.echo_cancel)
                .map_err(|e| tracing::warn!(error = %e, "mic uplink disabled"))
                .ok()
        })
        .flatten();
    mic.set_live(mic_uplink.is_some());

    // Live host↔client clock offset: loaded per frame (Relaxed) so mid-stream re-syncs (an NTP
    // step, drift) keep the capture-clock latency stats honest — never cached at session start.
    let clock_offset_live = connector.clock_offset_shared();
    // Phase-lock (advertised above): every received AU's arrival stamp, folded per stats
    // window against the presenter's latch grid into the ~1 Hz PhaseReport. Desktop
    // sessions receive whole AUs only (no frame parts), so every arrival counts — the
    // reference reporters (Apple/Android) sample the same signal. 256 ≈ 2 s at 120 Hz.
    let latch_grid = params.latch_grid.clone();
    let mut phase_arrivals: Vec<u64> = Vec::new();
    let mut last_applied_phase: Option<i32> = None;
    // PUNKTFUNK_DEBUG_RECONFIGURE=WxH@HZ:SECS — lab lever: request ONE mid-stream mode
    // switch N seconds in, so a headless session (no window manager to drag a window in)
    // can exercise the resize path deterministically — host pipeline rebuild, decoder
    // follow-through (e.g. the PyroWave in-place rebuild), overlay/aspect handling.
    let pump_start = Instant::now();
    let mut debug_reconfig = std::env::var("PUNKTFUNK_DEBUG_RECONFIGURE")
        .ok()
        .and_then(|s| {
            let parsed = parse_debug_reconfigure(&s);
            if parsed.is_none() {
                tracing::warn!(value = %s, "PUNKTFUNK_DEBUG_RECONFIGURE not understood (want WxH@HZ:SECS) — ignored");
            }
            parsed
        });
    let mut total_frames = 0u64;
    // Newest frame index handed to the decoder — the staleness bar for late partials.
    let mut newest_decoded_idx: Option<u32> = None;
    let mut window_start = Instant::now();
    let mut frames_n = 0u32;
    let mut bytes_n = 0u64;
    // Stage windows (µs samples): `host+network` = capture→received (host-clock
    // corrected), `decode` = received→decoded (client-local). p50 per 1 s window.
    let mut hostnet_us: Vec<u64> = Vec::with_capacity(256);
    let mut decode_us: Vec<u64> = Vec::with_capacity(256);
    // Whether this window's decode samples came from the async (submission-stamped) rung, so
    // the OSD keeps them off the partition line. Latches per window alongside the samples,
    // rather than being read off the rung name — a demote mid-window changes both together.
    let mut decode_overlaps = false;
    // Adaptive bitrate: report the decode stage back to the core controller only when it's armed
    // (Automatic, non-PyroWave). Constant for the session — resolve once, gate the per-frame call.
    let wants_decode = connector.wants_decode_latency();
    // Host/network split (Phase 2): frames awaiting their per-AU 0xCF host timing,
    // correlated by pts_ns. Bounded — an old host never sends any, so entries just age out.
    let mut pending_split: std::collections::VecDeque<(u64, u64)> =
        std::collections::VecDeque::with_capacity(PENDING_SPLIT_CAP);
    let mut host_us_win: Vec<u64> = Vec::with_capacity(256);
    let mut net_us_win: Vec<u64> = Vec::with_capacity(256);
    // T0.1 host-stage windows (extended 0xCF only; empty against an older host).
    let mut queue_us_win: Vec<u64> = Vec::with_capacity(256);
    let mut enc_us_win: Vec<u64> = Vec::with_capacity(256);
    let mut xfer_us_win: Vec<u64> = Vec::with_capacity(256);
    let mut pace_us_win: Vec<u64> = Vec::with_capacity(256);
    // What actually decoded the last frame — a VAAPI failure demotes mid-session, so
    // this is read off each frame's image variant rather than fixed at startup.
    let mut dec_path: &'static str = "";
    // The stats window keeps its own drop cursor — the OSD shows the per-window delta.
    let mut window_dropped = connector.frames_dropped();
    // Mic uplink cursor (same per-window diffing): a healthy 10 ms-frame mic reads ~100
    // sent/s; a nonzero drop delta is the queue shedding backlog (see NativeClient::mic_stats).
    let mut window_mic = connector.mic_stats();
    let mut last_kf_req: Option<Instant> = None;
    // Freeze-until-reanchor: the shared post-loss gate ([`punktfunk_core::reanchor::ReanchorGate`]).
    // Armed on any loss signal (frame-index gap, dropped-count climb, decoder wedge/demotion), it
    // withholds the decoder's concealed frames from the presenter — which then redraws the last good
    // picture — until a proven clean re-anchor (IDR / RFI anchor / second recovery mark) lifts it. It
    // also owns the no-output streak and the overdue-freeze backstop; the client keeps its own
    // `last_kf_req` request throttle and routes the gate's keyframe intents through it. Seeded with the
    // current drop count so the first `poll` doesn't read the baseline as a loss.
    let mut gate = ReanchorGate::new(connector.frames_dropped());
    // The frame_index we expect next (the host numbers frames consecutively). A jump means a frame
    // went missing — the earliest, most reliable signal that the decoder is about to conceal, ~120 ms
    // ahead of `frames_dropped` (the reassembler only declares a straggler lost once it ages out of
    // the loss window, by which point the concealment already reached the screen).
    let mut next_expected_index: Option<u32> = None;
    // Fixture capture for the native-decode program: every AU exactly as it reaches
    // `decode_frame`, plus a boundary/flags index — see `au_dump.rs` for the format.
    //
    // NOTE for fault runs: this captures what the HOST sent. `PUNKTFUNK_AU_FAULT`'s
    // injector lives one level down, at the native backend's decode entry, so on a
    // faulted run the fixture is the CLEAN bitstream and replaying it will not
    // reproduce the damage (reconstruct that from the spec — the injector is pure
    // and deterministic). Deliberate: the dump's job is to preserve the host's
    // output, and moving the injector above it would corrupt every backend's input
    // rather than only the lane whose detectors it exists to fire.
    let mut au_dump = crate::au_dump::AuDump::from_env(connector.codec);
    // The decode-order watermark at the latest arm of the freeze gate (M4 review):
    // a frame whose `decode_order` is at or below this was DECODED before the loss,
    // whatever order it was delivered in, so its recovery point SEI describes a wave
    // that completed before the loss and must not lift the freeze the loss raised.
    // `gate.arms()` is the trigger to re-stamp — it moves at every arm site,
    // including the two inside the gate, and not on the overdue backstop (which
    // re-asks without re-arming, and where discarding an in-flight heal would be
    // exactly wrong). Inert on every lane without its own parser: `decode_order` is
    // 0 there and `local_recovery` is NONE anyway.
    let mut gate_arms = gate.arms();
    let mut arm_decode_order: u64 = 0;
    // Decode-integrity window cursor (M4), the same per-window diffing as
    // `window_dropped`: the decoder's counters are session-cumulative, the OSD shows
    // the delta. `None` on every lane that cannot answer — see `Stats::decode_integrity`.
    let mut window_health = decoder.decode_health();
    // Set when the ladder ran out of rungs for this codec (M8): the loop breaks and this
    // event replaces the plain `Ended` at the bottom. `Some` is the only way the pump
    // ends with a retry attached.
    let mut codec_fallback: Option<SessionEvent> = None;

    let end: Option<String> = loop {
        if stop.load(Ordering::SeqCst) {
            break None;
        }
        if let Some((mode, delay)) = debug_reconfig {
            if pump_start.elapsed() >= delay {
                tracing::info!(
                    ?mode,
                    "PUNKTFUNK_DEBUG_RECONFIGURE: requesting mid-stream mode switch"
                );
                if let Err(e) = connector.request_mode(mode) {
                    tracing::warn!(error = ?e, "debug mode switch request failed");
                }
                debug_reconfig = None;
            }
        }
        // Mid-session access updates (a console edit, the T−5 m / T−1 m expiry warnings).
        // Drain the queue and re-read the connector's live truth ONCE — latest wins per
        // design, and the connector already folded every update before waking us. The mic
        // uplink follows its grant live: removed → the capture device closes now (the host
        // is dropping the plane anyway); granted back (and wanted in Settings) → it starts
        // again without a reconnect.
        {
            let mut updated = false;
            while connector.next_access_update(Duration::ZERO).is_ok() {
                updated = true;
            }
            if updated {
                let prev = access;
                access = crate::access::SessionAccess::from_connector(&connector);
                let notice = crate::access::update_notice(prev.grants, &access, Instant::now());
                let mic_on = params.mic_enabled && access.allows(punktfunk_core::quic::GRANT_MIC);
                if !mic_on && mic_uplink.is_some() {
                    tracing::info!("MIC grant removed mid-session — stopping the mic uplink");
                    mic_uplink = None;
                    mic.set_live(false);
                } else if mic_on && mic_uplink.is_none() {
                    mic_uplink = audio::MicStreamer::spawn(
                        connector.clone(),
                        mic.flag(),
                        params.echo_cancel,
                    )
                    .map_err(|e| tracing::warn!(error = %e, "mic uplink disabled"))
                    .ok();
                    mic.set_live(mic_uplink.is_some());
                }
                let _ = ev_tx.send_blocking(SessionEvent::Access { access, notice });
            }
        }
        // 20 ms wait: audio has its own thread now, so this only bounds stop-flag
        // responsiveness and the per-iteration keyframe-recovery check (a frame arrives
        // every ~8–16 ms at 60–120 Hz anyway, so this rarely times out mid-stream).
        match connector.next_frame(Duration::from_millis(20)) {
            Ok(frame) => {
                // The `received` point: reassembly COMPLETION, stamped by the core session as
                // the AU crossed poll_frame (ABI v9). Stamping here at the hand-off pull instead
                // would fold the pre-decode queue wait into `host+network` — a client-side
                // standing backlog masquerading as network latency (the 2026-07 two-pair
                // investigation). 0 = a core predating the stamp; fall back to the pull instant.
                let received_ns = if frame.received_ns > 0 {
                    frame.received_ns
                } else {
                    now_ns()
                };
                if params.phase_lock && phase_arrivals.len() < 256 {
                    phase_arrivals.push(received_ns);
                }
                // fps / goodput count every received AU (spec), decoded or not.
                frames_n += 1;
                bytes_n += frame.data.len() as u64;
                // Reference-continuity gate: the host numbers frames consecutively, so a jump in
                // frame_index means a frame is missing (lost, or an out-of-order straggler the
                // reassembler emitted a newer frame ahead of) and this AU references a picture we
                // never decoded. On RADV the decoder conceals that as a gray plate with the new
                // motion on top — the reported artifact, and it shows most on high-motion frames (a
                // full-screen pan bursts far more packets than a static desktop or a UFO-test's small
                // moving sprite, so it is the frame that loses shards). Arm the freeze at the FIRST
                // such frame — ~120 ms before `frames_dropped` would — so the gray never reaches the
                // screen; recovery IDRs stay on the existing throttled path (see the arm below).
                match next_expected_index {
                    Some(exp) if frame.frame_index == exp => {
                        next_expected_index = Some(exp.wrapping_add(1)); // contiguous
                    }
                    // A forward gap: hold the last good frame — but DO NOT ask for a keyframe here.
                    // Hiding the concealment is free (the presenter redraws the last picture); an IDR
                    // is not — at 4K120 it is a multi-megabyte frame and a visible stutter, and it can
                    // re-trigger the very burst loss that caused this. The existing loss recovery below
                    // (`frames_dropped`, host-coalesced + throttled) still requests it at exactly the
                    // cadence it did before this change, so we add zero IDR pressure per pan. A
                    // straggler behind us (`index_gap` → None) leaves the expectation put so the real
                    // gap still trips.
                    Some(exp) => {
                        if let Some(gap) = index_gap(exp, frame.frame_index) {
                            let now = Instant::now();
                            // Credited arm: the reassembler books these same lost frames into
                            // `frames_dropped` up to ~120 ms from now; the credit keeps that
                            // delayed climb from re-freezing a stream the RFI anchor healed in
                            // between (the double-arm race — see
                            // `ReanchorGate::arm_expecting_drops`).
                            gate.arm_expecting_drops(now, u64::from(gap));
                            next_expected_index = Some(frame.frame_index.wrapping_add(1));
                            // The gap carries the PRECISE lost range — [first missing, newest
                            // received - 1] — so this is the one recovery signal that can drive true
                            // reference-frame invalidation. Prefer an RFI request over a keyframe: an
                            // RFI-capable host (AMD LTR / NVENC) re-references a known-good picture and
                            // emits a clean P-frame tagged USER_FLAG_RECOVERY_ANCHOR (the freeze lifts
                            // on ONE frame, no 20-40× IDR spike); an incapable/old host forces a
                            // host-coalesced IDR instead, or ignores it (then the frames_dropped /
                            // overdue keyframe paths below are the backstop). Throttled with those
                            // paths (one recovery ask per 100 ms) so a burst of gaps — a full-screen
                            // pan shedding shards — can't storm the control stream. This fires ~120 ms
                            // before frames_dropped would, so recovery also starts sooner.
                            //
                            // A gap wider than RFI_MAX_RANGE is beyond any encoder's reference
                            // history (a seconds-long outage — or a phantom index jump, e.g. the
                            // first real AU after an old host's speed-test burst consumed video
                            // indexes): RFI is hopeless there, so ask for the IDR resync directly.
                            if last_kf_req
                                .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
                            {
                                last_kf_req = Some(now);
                                if gap > punktfunk_core::packet::RFI_MAX_RANGE {
                                    let _ = connector.request_keyframe();
                                } else {
                                    let _ = connector
                                        .request_rfi(exp, frame.frame_index.wrapping_sub(1));
                                }
                            }
                            tracing::trace!(
                                gap,
                                "frame gap — RFI recovery, holding last frame until re-anchor"
                            );
                        }
                    }
                    None => next_expected_index = Some(frame.frame_index.wrapping_add(1)),
                }
                // A PARTIAL that lost the race (a newer frame already decoded) is pure
                // time travel — skip it; each PyroWave frame is independent, so nothing
                // downstream needs it. Completes keep the normal path (reorder is handled
                // by the continuity gate).
                if !frame.complete
                    && newest_decoded_idx
                        .is_some_and(|n: u32| n.wrapping_sub(frame.frame_index) <= u32::MAX / 2)
                {
                    continue;
                }
                newest_decoded_idx = Some(match newest_decoded_idx {
                    Some(n) if frame.frame_index.wrapping_sub(n) > u32::MAX / 2 => n,
                    _ => frame.frame_index,
                });
                if let Some(d) = au_dump.as_mut() {
                    if !d.write(&frame.data, frame.flags, frame.complete) {
                        au_dump = None;
                    }
                }
                // Re-stamp the arm watermark BEFORE this AU decodes and advances the
                // decoder's ordinal, so it names the newest picture that existed when the
                // freeze was armed. One site covers every arm: the frame-gap arm above
                // happened moments ago in this same iteration, and the four sites below
                // (`on_no_output` ×2, the decoder-recovery arm, `poll`'s dropped climb) all
                // run AFTER the decode, so the next iteration reaches here with the ordinal
                // still exactly as they left it.
                if gate.arms() != gate_arms {
                    gate_arms = gate.arms();
                    arm_decode_order = decoder.decode_order();
                }
                match decoder.decode_frame(&frame.data, frame.flags, frame.complete) {
                    Ok(Some(image)) => {
                        // The decoder's OWN re-anchor observation FIRST (M4): a recovery point SEI
                        // is the only clean point an intra-refresh session has when the host does not
                        // mark the wire — its wave emits no IDR to flag, and only
                        // one of the three encoder backends that run a wave sets
                        // USER_FLAG_RECOVERY_POINT — so without this such a session freezes for the
                        // full REANCHOR_FREEZE_MAX and then forces the very IDR the wave exists to
                        // avoid. The gate pairs the mark against its own arm (only a wave that
                        // STARTED after the loss proves anything about it) and lifts on the first
                        // trusted one. Before `on_decoded`, so the frame that healed the picture is
                        // itself presented rather than held one more round. Inert on every other
                        // lane: `local_recovery` reports NONE and the wire path is untouched.
                        //
                        // The gate pairs by TIME; this pairs by DECODE ORDER, and both are
                        // needed. A decoder that flushes its DPB after a failed AU hands back
                        // every picture it still held — pictures decoded BEFORE the loss,
                        // carrying the marks of the wave they were decoded in — and they
                        // arrive after the arm, so the gate cannot tell. Their ordinal can.
                        let local = match image.decode_order() {
                            Some(order) if order <= arm_decode_order => {
                                tracing::trace!(
                                    order,
                                    arm_decode_order,
                                    "discarding the local recovery of a frame decoded before \
                                     the loss"
                                );
                                punktfunk_core::reanchor::LocalRecovery::NONE
                            }
                            _ => image.local_recovery(),
                        };
                        if gate.on_local_recovery(local) {
                            tracing::debug!(
                                "re-anchored on the stream's own recovery point SEI — no IDR needed"
                            );
                        }
                        // Then the shared freeze gate: it reads the AU's re-anchor wire flags
                        // (FLAG_SOF IDR marker / RECOVERY_ANCHOR / RECOVERY_POINT), takes
                        // `image.is_keyframe()` as the decoder's own IDR belt, applies the two-mark
                        // rule + the mark-patience backstop, clears the no-output streak, and returns
                        // whether to present this frame or withhold it as a post-loss concealment.
                        //
                        // CORROBORATED (the grey-frame fix): the wire's RECOVERY_ANCHOR is the host
                        // asserting something about THIS decoder — "the picture I coded this
                        // P-frame against is one you still hold, intact" — and it lifts the freeze
                        // on the FIRST occurrence, no two-mark wait. The host derives that from
                        // bookkeeping that tracks what the client RECEIVED, not what it managed to
                        // DECODE, and when those diverge the anchor lifts the freeze onto a
                        // concealed picture and LEAVES it lifted: grey with motion painted on it
                        // until some later signal re-arms and the 500 ms backstop extracts a real
                        // IDR. A rung that planned the AU itself knows better, so it says so here.
                        //
                        // What a refusal costs is exactly one thing: the freeze keeps holding the
                        // last good picture until the backstop fires on its ORIGINAL deadline and
                        // forces the IDR the anchor failed to be. That is strictly the better half
                        // of the trade — the alternative is presenting a picture this client can
                        // prove is damaged — and it is the same direction every rule in the gate
                        // errs in. Every non-native lane reports `Unavailable` and is untouched.
                        let evidence = image.anchor_evidence();
                        if evidence == punktfunk_core::reanchor::AnchorEvidence::ReferencesDamaged
                            && frame.flags & punktfunk_core::packet::USER_FLAG_RECOVERY_ANCHOR != 0
                        {
                            tracing::debug!(
                                "refused a host recovery anchor: this AU predicts from a picture \
                                 this decoder had to conceal — holding for a real IDR"
                            );
                        }
                        let present = gate.on_decoded_corroborated(
                            frame.flags,
                            image.is_keyframe(),
                            evidence,
                            Instant::now(),
                        ) == GateVerdict::Present;
                        total_frames += 1;
                        // ⚠ The `stats:` decode-path tag is a machine interface —
                        // additive only. M10 removed the rungs whose tags were `vaapi`,
                        // `vulkan` and `d3d11va`; every surviving tag keeps its exact
                        // spelling.
                        dec_path = match &image {
                            DecodedImage::Cpu(_) => "software",
                            #[cfg(target_os = "linux")]
                            DecodedImage::NativeDmabuf(_) => "native-vaapi",
                            #[cfg(windows)]
                            DecodedImage::D3d11(_) => "native-d3d11va",
                            #[cfg(all(any(target_os = "linux", windows), feature = "pyrowave"))]
                            DecodedImage::PyroWave(_) => "pyrowave",
                            DecodedImage::NativeVk(_) => "native-vulkan",
                        };
                        if total_frames == 1 {
                            let (w, h, path) = match &image {
                                DecodedImage::Cpu(c) => (c.width, c.height, "software"),
                                #[cfg(target_os = "linux")]
                                DecodedImage::NativeDmabuf(d) => {
                                    (d.width, d.height, "native-vaapi-dmabuf")
                                }
                                #[cfg(windows)]
                                DecodedImage::D3d11(d) => (d.width, d.height, "native-d3d11va"),
                                #[cfg(all(
                                    any(target_os = "linux", windows),
                                    feature = "pyrowave"
                                ))]
                                DecodedImage::PyroWave(f) => (f.width, f.height, "pyrowave"),
                                DecodedImage::NativeVk(f) => (f.width, f.height, "native-vulkan"),
                            };
                            tracing::info!(width = w, height = h, path, "first frame decoded");
                        }
                        // The `decoded` point — travels with the frame so the presenter
                        // can measure its `display` stage against it.
                        let decoded_ns = now_ns();
                        // `host+network` stage: received expressed in the host's capture
                        // clock, minus the host-stamped capture pts (clamped (0, 10 s)).
                        let clock_offset =
                            clock_offset_live.load(std::sync::atomic::Ordering::Relaxed);
                        let hn = (received_ns as i128 + clock_offset as i128 - frame.pts_ns as i128)
                            .max(0) as u64;
                        if hn > 0 && hn < 10_000_000_000 {
                            hostnet_us.push(hn / 1000);
                            // Remember the sample for the host/network split — matched
                            // against the AU's 0xCF host timing when it arrives.
                            if pending_split.len() >= PENDING_SPLIT_CAP {
                                pending_split.pop_front();
                            }
                            pending_split.push_back((frame.pts_ns, hn / 1000));
                        }
                        // Ship the frame FIRST, then settle the decode stat: on the
                        // Vulkan path receive_frame returns at SUBMISSION (~0.1 ms) and
                        // the hardware decodes asynchronously — the frame's timeline
                        // fence measures true received→decode-complete. But the fence
                        // wait BLOCKS this thread, and per-frame that serializes the
                        // pipeline to 1/decode_latency (observed: an APU's 19 ms decode
                        // capping a 5120×1440 stream at ~51 fps while the engine could
                        // pipeline several frames — and drivers may spin-wait, burning
                        // CPU). So sample ONE frame per stats window: the p50 the OSD
                        // shows becomes that sample — honest, at zero pipeline cost on
                        // every other frame. Software keeps the synchronous stamp on
                        // every frame (its decode really is done by now).
                        //
                        // M4 re-examined this against the native rung's non-blocking
                        // reads (`poll_status`, `get_semaphore_counter_value`) and left
                        // it exactly as it is. Polling can only ever answer "complete
                        // by NOW", and the only place this thread polls is once per AU
                        // — so every sample would be quantized up by as much as a whole
                        // frame interval (8.3 ms at 120 Hz, against decodes that
                        // measure ~0.1-2 ms). That is not a cheaper measurement, it is
                        // a wrong one, and it would replace a true figure with a
                        // plausible-looking upper bound nothing downstream could tell
                        // apart. Sampling faster needs either a spin (the CPU burn this
                        // comment already warns about) or a second thread on a decoder
                        // that is `Send` but deliberately not `Sync`. Correctness beats
                        // the metric: one honest sample per window stands.
                        let hw_fence = match &image {
                            // The native rung's frame carries the timeline pair: the
                            // decode signals `semaphore_value` when the pixels are
                            // ready (the presenter's write-back is the `+ 1`), so
                            // waiting it measures received→decode-complete. Fed since
                            // the WP-D hardware verdict landed (bit-exact parity, both
                            // DPB modes).
                            DecodedImage::NativeVk(f) => Some((f.semaphore, f.semaphore_value)),
                            _ => None,
                        };
                        if present {
                            let _ = frame_tx.force_send(DecodedFrame {
                                pts_ns: frame.pts_ns,
                                decoded_ns,
                                image,
                            });
                        } else {
                            // Post-loss concealment: withhold this frame (it references a lost/gray
                            // reference) so the presenter keeps redrawing the last good picture rather
                            // than flashing the decoder's gray plate. Dropped here — the hw-decode stat
                            // below still samples via `hw_fence` (raw handle + value, valid past the
                            // guard). The gate lifts the freeze on the next clean re-anchor / backstop.
                            tracing::trace!("holding last frame — awaiting post-loss re-anchor");
                        }
                        // `decode` stage: received→decode COMPLETE, single clock.
                        match hw_fence {
                            Some((sem, value)) => {
                                // A fence means `decoded_ns` above was stamped at SUBMISSION, so
                                // the GPU decode lands inside the presenter's `display` stage and
                                // this figure re-counts it: it does NOT tile with the others.
                                // Recorded so the OSD can render it off the partition line
                                // (`Stats::decode_overlaps_display`).
                                decode_overlaps = true;
                                if decode_us.is_empty()
                                    && decoder.wait_hw_decoded(sem, value, 50_000_000)
                                {
                                    decode_us.push(now_ns().saturating_sub(received_ns) / 1000);
                                }
                            }
                            None => {
                                decode_us.push(decoded_ns.saturating_sub(received_ns) / 1000);
                            }
                        }
                        // Adaptive bitrate: feed the decoder-backlog signal every frame (the network
                        // signals can't see the client's decoder). Uses the CPU-side decoded stamp:
                        // exact for the synchronous D3D11VA/software path; received→submit for the
                        // async Vulkan-Video path — still the decoder-input backpressure the rate
                        // controller needs, without the per-frame fence wait the HUD stat avoids.
                        if wants_decode {
                            let us = decoded_ns.saturating_sub(received_ns) / 1000;
                            connector.report_decode_us(us.min(u32::MAX as u64) as u32);
                        }
                    }
                    // The decoder produced nothing — under zero-reorder LOW_DELAY (one-in/one-out) that
                    // means it's wedged on missing references with no reassembler drop to trigger
                    // recovery. The gate counts the streak and, once it trips, arms the freeze and tells
                    // us to (throttled) request a fresh IDR to re-anchor. Both the empty-output and the
                    // survivable-decode-error arms feed it; a decoded frame resets the streak in
                    // `on_decoded`.
                    Ok(None) => {
                        let now = Instant::now();
                        if gate.on_no_output(now)
                            && last_kf_req
                                .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
                        {
                            last_kf_req = Some(now);
                            let _ = connector.request_keyframe();
                            tracing::debug!("requested keyframe (decoder produced no output)");
                        }
                    }
                    // NOT survivable, and the only decode error that isn't: the ladder
                    // demoted to its last rung and there is no such rung for this codec.
                    // Feeding more AUs would freeze the screen forever — the exact
                    // "limping on software" outcome M8's HEVC drop replaces with an
                    // action. Break out of the pump; the terminal event below carries the
                    // retry the embedder reconnects with.
                    Err(e) if e.downcast_ref::<crate::video::NoSoftwareRung>().is_some() => {
                        let loss = e
                            .downcast_ref::<crate::video::NoSoftwareRung>()
                            .expect("just matched")
                            .loss();
                        codec_fallback = Some(codec_fallback_event(
                            connector.codec,
                            advertised_codecs,
                            loss,
                            &e.to_string(),
                        ));
                        break None;
                    }
                    // Survivable (loss until the next IDR/RFI recovery) — keep feeding.
                    Err(e) => {
                        tracing::debug!(error = %e, "decode error (recovering)");
                        let now = Instant::now();
                        if gate.on_no_output(now)
                            && last_kf_req
                                .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
                        {
                            last_kf_req = Some(now);
                            let _ = connector.request_keyframe();
                            tracing::debug!("requested keyframe (decode error recovery)");
                        }
                    }
                }
                // The presenter's verdict: hardware frames can't be displayed (GL converter
                // init failed / dmabuf import rejected) — demote to software here, on the
                // decoder's own thread. Decode succeeds in that state, so the error-streak
                // demotion above never fires.
                if force_software.swap(false, Ordering::Relaxed) {
                    if let Err(e) = decoder.force_software() {
                        break Some(format!("software decoder rebuild: {e}"));
                    }
                }
                // A decode error / VAAPI→software demotion asks for a fresh IDR: the infinite
                // GOP has no periodic keyframe, so a rebuilt/erroring decoder would stay
                // gray/frozen until an unrelated packet drop happened to request one. Route it
                // through the same throttle as loss recovery below.
                //
                // The native rung's DAMAGE path arrives here too (M4): an AU whose plan needed
                // concealment answers `Ok(None)` and raises this flag rather than erroring, so
                // the ask happens at exactly this moment and through exactly this throttle
                // while the decoder keeps its rung — stream damage is not a decoder fault (see
                // `video_vk_native`'s recovery policy). That also bounds the whole thing: one
                // ask per 100 ms per session however fast the damage arrives, and once the gate
                // is armed further damage refreshes an existing freeze rather than compounding
                // into more requests.
                //
                // ARM ONLY WHEN NOT ALREADY HOLDING. This flag fires per DAMAGED AU, not per
                // loss, and every `arm` zeroes the gate's recovery-mark count and its
                // local-SEI credit. Re-arming on each one therefore made both re-anchor paths
                // — the wire's two-mark rule and M4's local SEI — impossible to complete
                // during exactly the sustained damage they were written for, leaving recovery
                // resting entirely on the throttled keyframe ask. A genuinely NEW loss still
                // re-arms with its marks zeroed: it arrives as a frame-index gap or a
                // `frames_dropped` climb, both of which arm unconditionally. The keyframe ask
                // below is untouched — it still fires per damaged AU, through the same 100 ms
                // throttle.
                if decoder.take_keyframe_request() {
                    let now = Instant::now();
                    if !gate.is_holding() {
                        gate.arm(now);
                    }
                    if last_kf_req
                        .is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
                    {
                        last_kf_req = Some(now);
                        let _ = connector.request_keyframe();
                        tracing::debug!("requested keyframe (decoder recovery)");
                    }
                }
            }
            Err(PunktfunkError::NoFrame) => {}
            // The session ended. `None` here means "normal finish" to every embedder — the browse
            // console returns to the library with no status strip, the one-shot binary exits 0
            // quietly — so only an ending that actually went wrong should carry a message.
            // Previously EVERY close reported "Host ended the session", which put an error-shaped
            // line in front of the player for quitting their own game.
            Err(PunktfunkError::Closed) => {
                use punktfunk_core::client::PunktfunkEndReason as End;
                // A typed mid-session rejection names itself — today that is the access
                // expiry (close 0x69, after the host's T−5 m / T−1 m warnings), which
                // would otherwise file under HostError and render as "the host ended the
                // session with an error": true, and exactly the wrong sentence. Same
                // wording as the connect-time path, one vocabulary (design §7).
                if let Some(reason) = connector.end_reject() {
                    break Some(crate::trust::connect_reject_message(reason));
                }
                break match connector.end_reason() {
                    // The player quit the game the host launched. Nothing to report; a launcher
                    // embedder returns to its library, which is where they were headed anyway.
                    End::GameExited => None,
                    // We closed it, or the host closed cleanly (an operator "End", or the session
                    // simply finishing). Both were asked for.
                    End::Local | End::HostEnded => None,
                    End::HostError => Some("主机因错误结束了会话".to_string()),
                    End::Lost => Some("连接已丢失".to_string()),
                    // No verdict (an older core, or the close raced the read): keep the wording
                    // this arm has always used rather than inventing a new one.
                    End::None => Some("主机已结束会话".to_string()),
                };
            }
            Err(e) => break Some(format!("session: {e:?}")),
        }

        // Drain the per-AU host timings (0xCF) non-blockingly and match them to received
        // frames by pts: host = the host's own capture→sent, network = our
        // capture→received minus it (the two tile per frame by construction). An old
        // host never emits any — the deque fills to its cap and the OSD keeps the
        // combined `host+network` stage.
        while let Ok(t) = connector.next_host_timing(Duration::ZERO) {
            // Phase-lock closed loop: the host's applied grid offset rides the 0xCF tail.
            // Log transitions so an on-glass run can watch the controller engage/settle
            // (the Android reporter's parity log).
            if params.phase_lock
                && t.applied_phase_ns.is_some()
                && t.applied_phase_ns != last_applied_phase
            {
                last_applied_phase = t.applied_phase_ns;
                tracing::info!(
                    applied_phase_ns = t.applied_phase_ns.unwrap_or(0),
                    "host phase-lock: applied capture-grid offset"
                );
            }
            if let Some(i) = pending_split.iter().position(|(p, _)| *p == t.pts_ns) {
                let (_, hn_us) = pending_split.remove(i).unwrap();
                host_us_win.push(t.host_us as u64);
                net_us_win.push(hn_us.saturating_sub(t.host_us as u64));
                // Extended 0xCF (T0.1): per-stage host split; the seal/FEC + channel-wait
                // residual is derived so the four stages tile host_us exactly.
                if let Some(s) = t.stages {
                    queue_us_win.push(s.queue_us as u64);
                    enc_us_win.push(s.encode_us as u64);
                    pace_us_win.push(s.pace_us as u64);
                    xfer_us_win.push(
                        (t.host_us as u64).saturating_sub(
                            s.queue_us as u64 + s.encode_us as u64 + s.pace_us as u64,
                        ),
                    );
                }
            }
        }

        // Loss recovery + overdue backstop, folded through the shared gate. A climb in the
        // reassembler's unrecoverable-drop count (`frames_dropped`) means the AUs after the lost one
        // reference a picture we never decoded — the decoder conceals them (gray on RADV) and returns
        // Ok, so a decode-error trigger rarely fires; the gate arms the freeze on the climb instead. An
        // overdue freeze (held a full REANCHOR_FREEZE_MAX with no clean re-anchor — a lost recovery IDR,
        // or a benign reorder that produced no `frames_dropped`) re-asks while it keeps holding: NEVER
        // resume to gray — a genuinely dead stream is the QUIC idle-timeout watchdog's job. Both route
        // the gate's keyframe intent through the shared 100 ms throttle; under infinite GOP the only
        // recovery keyframe is one we request.
        let dropped = connector.frames_dropped();
        let now = Instant::now();
        if gate.poll(dropped, now)
            && last_kf_req.is_none_or(|t| now.duration_since(t) >= Duration::from_millis(100))
        {
            last_kf_req = Some(now);
            let _ = connector.request_keyframe();
            tracing::debug!(
                dropped,
                "requested keyframe (loss recovery / overdue re-anchor)"
            );
        }

        if window_start.elapsed() >= Duration::from_secs(1) {
            // Phase-lock report (~1 Hz, riding the stats window — the reference reporters'
            // cadence): this window's arrival leads before the presenter's latch grid,
            // folded with the SHARED circular statistic (the host controller was tuned
            // against it). Quiet until the presenter has a grid (period 0 — no
            // present-timing samples yet) or the window is thin (< 8 arrivals —
            // `circular_latch` declines). 1 ms uncertainty = Apple/Android parity.
            if params.phase_lock {
                let period = latch_grid.period_ns.load(Ordering::Relaxed);
                let anchor = latch_grid.anchor_ns.load(Ordering::Relaxed);
                if period > 0 && anchor > 0 {
                    let leads_us: Vec<u64> = phase_arrivals
                        .iter()
                        .map(|a| {
                            ((anchor as i128 - *a as i128).rem_euclid(period as i128) / 1000) as u64
                        })
                        .collect();
                    if let Some((lead_ns, coherence)) =
                        punktfunk_core::phase::circular_latch(&leads_us, period as i64)
                    {
                        // Extrapolate the (possibly ~1 s old) anchor to the next latch at
                        // or after now, then express it on the host clock.
                        let (now, p, a) = (now_ns() as i128, period as i128, anchor as i128);
                        let k = ((now - a).max(0) + p - 1) / p;
                        let offset = clock_offset_live.load(Ordering::Relaxed) as i128;
                        connector.report_phase(
                            (a + k * p + offset).max(0) as u64,
                            period.min(u32::MAX as u64) as u32,
                            1_000_000,
                            lead_ns.min(u32::MAX as u64) as u32,
                            coherence,
                        );
                    }
                }
                phase_arrivals.clear();
            }
            let secs = window_start.elapsed().as_secs_f32();
            let (hn_p50, _) = window_percentiles(&mut hostnet_us);
            let (dec_p50, _) = window_percentiles(&mut decode_us);
            // Host/network split — present only when this window matched 0xCF timings.
            let split = !host_us_win.is_empty();
            let (host_p50, _) = window_percentiles(&mut host_us_win);
            let (net_p50, _) = window_percentiles(&mut net_us_win);
            let staged = !queue_us_win.is_empty();
            let (queue_p50, _) = window_percentiles(&mut queue_us_win);
            let (enc_p50, _) = window_percentiles(&mut enc_us_win);
            let (xfer_p50, _) = window_percentiles(&mut xfer_us_win);
            let (pace_p50, _) = window_percentiles(&mut pace_us_win);
            let lost = dropped.saturating_sub(window_dropped) as u32;
            window_dropped = dropped;
            let mic_now = connector.mic_stats();
            let mic_sent = mic_now.sent.saturating_sub(window_mic.sent) as u32;
            let mic_dropped = (mic_now.dropped_full + mic_now.dropped_stale)
                .saturating_sub(window_mic.dropped_full + window_mic.dropped_stale)
                as u32;
            window_mic = mic_now;
            // Decode integrity (M4): session-cumulative counters, diffed per window
            // like `frames_dropped`. `None` on a lane that cannot see damage at all —
            // and that stays distinguishable from "saw none" all the way to the OSD.
            let health_now = decoder.decode_health();
            let (decode_damaged, decode_failed, decode_refused) = match (health_now, window_health)
            {
                (Some(now), Some(prev)) => (
                    now.damaged.saturating_sub(prev.damaged) as u32,
                    now.failed.saturating_sub(prev.failed) as u32,
                    now.refused.saturating_sub(prev.refused) as u32,
                ),
                // A lane that could not answer at the last window and can now.
                // Unreachable today — the cursor is seeded from the decoder before
                // the first AU and the ladder only ever demotes AWAY from the
                // native rung, never back onto it — so this exists to keep the
                // match total with a defensible answer (the cumulative figure)
                // instead of an `unwrap` that would be a panic if that ever
                // changed.
                (Some(now), None) => (now.damaged as u32, now.failed as u32, now.refused as u32),
                (None, _) => (0, 0, 0),
            };
            window_health = health_now;
            tracing::debug!(
                fps = frames_n,
                hostnet_p50_us = hn_p50,
                host_p50_us = host_p50,
                net_p50_us = net_p50,
                queue_p50_us = queue_p50,
                encode_p50_us = enc_p50,
                xfer_p50_us = xfer_p50,
                pace_p50_us = pace_p50,
                decode_p50_us = dec_p50,
                lost,
                mic_sent,
                mic_dropped,
                decode_damaged,
                decode_failed,
                decode_refused,
                concealed_run = health_now.map(|h| h.run).unwrap_or(0),
                worst_concealed_run = health_now.map(|h| h.worst_run).unwrap_or(0),
                decode_status_queries = health_now.map(|h| h.status_queries).unwrap_or(false),
                total_frames,
                "stream window"
            );
            let _ = ev_tx.try_send(SessionEvent::Stats(Stats {
                fps: frames_n as f32 / secs,
                mbps: bytes_n as f32 * 8.0 / 1e6 / secs,
                host_net_ms: hn_p50 as f32 / 1000.0,
                host_ms: host_p50 as f32 / 1000.0,
                net_ms: net_p50 as f32 / 1000.0,
                split,
                host_queue_ms: queue_p50 as f32 / 1000.0,
                host_encode_ms: enc_p50 as f32 / 1000.0,
                host_xfer_ms: xfer_p50 as f32 / 1000.0,
                host_pace_ms: pace_p50 as f32 / 1000.0,
                staged,
                decode_ms: dec_p50 as f32 / 1000.0,
                decode_overlaps_display: decode_overlaps,
                lost,
                lost_pct: if lost > 0 {
                    lost as f32 * 100.0 / (frames_n + lost) as f32
                } else {
                    0.0
                },
                mic_sent,
                mic_dropped,
                audio_buffer_ms: connector.audio_buffer_ms(),
                audio_av_offset_ms: connector.audio_av_offset_ms() as i32,
                // Read off the connector, not off `params`: these three are the Welcome's answer,
                // and the request lives one struct away precisely so they cannot be confused.
                audio_lossless: connector.audio_codec == punktfunk_core::quic::AUDIO_CODEC_PCM,
                audio_rate_hz: connector.audio_sample_rate_hz,
                audio_bits: connector.audio_bits,
                decoder: dec_path,
                target_kbps: connector.current_bitrate_kbps(),
                auto_rate,
                chroma_444,
                asked_444,
                decode_integrity: health_now.is_some(),
                decode_damaged,
                decode_failed,
                decode_refused,
                concealed_run: health_now.map(|h| h.run).unwrap_or(0),
                worst_concealed_run: health_now.map(|h| h.worst_run).unwrap_or(0),
                decode_status_queries: health_now.is_some_and(|h| h.status_queries),
            }));
            window_start = Instant::now();
            frames_n = 0;
            bytes_n = 0;
            hostnet_us.clear();
            decode_us.clear();
            decode_overlaps = false;
            host_us_win.clear();
            net_us_win.clear();
            queue_us_win.clear();
            enc_us_win.clear();
            xfer_us_win.clear();
            pace_us_win.clear();
        }
    };

    tracing::info!(
        total_frames,
        reason = end.as_deref().unwrap_or("user"),
        "session ended"
    );
    stop.store(true, Ordering::SeqCst);
    // The uplink is about to be dropped with the rest of this frame — stop claiming a mute
    // surface, so an embedder still holding the handle through its end path (browse mode
    // returns to the console with it) can't draw a muted mic that no longer exists.
    mic.set_live(false);
    if let Some(t) = audio_thread {
        let _ = t.join(); // exits within its 100 ms pull timeout once `stop` is set
    }
    if let Some(t) = pad_audio_thread {
        let _ = t.join(); // exits within its 10 ms pull timeout once `stop` is set
    }
    if let Some(t) = clipboard_thread {
        let _ = t.join(); // exits within its next_clip wait once `stop` is set
    }
    // The codec-exhaustion end has its own terminal event — sent HERE, after the audio /
    // pad / clipboard threads have joined, so an embedder that reconnects on receipt
    // never has two sessions' worth of threads on the same connector.
    let _ = ev_tx.send_blocking(codec_fallback.unwrap_or(SessionEvent::Ended(end)));
}

/// Build the terminal event for a session whose codec exhausted the decode ladder, and
/// bump the telemetry counter.
///
/// One place, called from both refusal sites (decoder construction and the mid-stream
/// demotion), because the two must produce the SAME retry — a construction-time refusal
/// that reconnected onto a different codec set than the mid-stream one would make field
/// reports unreadable.
fn codec_fallback_event(
    negotiated: u8,
    advertised: u8,
    loss: crate::video::RungLoss,
    detail: &str,
) -> SessionEvent {
    use crate::video::{last_rung_verdict, wire_codec_name, LastRungVerdict};
    CODEC_FALLBACKS.fetch_add(1, Ordering::Relaxed);
    let codec = wire_codec_name(negotiated);
    match last_rung_verdict(negotiated, advertised, loss) {
        LastRungVerdict::Retry { caps } => {
            tracing::warn!(
                codec,
                retry_caps = caps,
                detail,
                "video decode ran out of rungs — reconnecting without this codec"
            );
            SessionEvent::CodecFallback {
                // DERIVED from the verdict, never from the failed codec alone: the retry
                // then advertises exactly `caps` (`decodable_codecs_for & !exclude`
                // re-intersects to it), so the wire and the rule cannot disagree. They
                // did before the M8 review — the rule dropped PyroWave and the wire
                // re-offered it.
                exclude_codecs: advertised & !caps,
                retry_caps: caps,
                msg: format!("{codec} decoding failed on this device — reconnecting"),
            }
        }
        // Nothing left to advertise: reconnecting would negotiate the same dead end. End
        // the session and say what actually happened, rather than loop.
        LastRungVerdict::Dead => {
            tracing::error!(codec, detail, "video decode ran out of rungs and of codecs");
            SessionEvent::Ended(Some(format!(
                "{codec} can't be decoded on this device, and no other codec is available"
            )))
        }
    }
}

/// The dedicated audio thread: owns the decoder, the sample scratch, and the PipeWire
/// player, and blocks on `next_audio` (the plane's single consumer — packets land every
/// frame). Decoded chunks are pushed in Vecs recycled from the player's pool, so the
/// steady state allocates nothing. Best-effort like before: any setup failure logs and
/// the session streams video-only. Exits on the stop flag or a closed plane.
fn spawn_audio(
    connector: Arc<NativeClient>,
    stop: Arc<AtomicBool>,
) -> Option<std::thread::JoinHandle<()>> {
    // Decoder + playback are built from the host-RESOLVED format (never the request), so an
    // older/clamping host that resolves stereo Opus at 48 kHz is decoded and played exactly that
    // way — and a host that granted less than was asked for is honoured rather than argued with.
    // Opening the device from the REQUEST instead is the failure `hi-res-audio.md` §4.3 is written
    // around, one end further along.
    let channels = connector.audio_channels;
    // A codec this client does not speak is refused OUT LOUD, not guessed at. `Welcome::decode`
    // takes `audio_codec` VERBATIM — it deliberately does not fold an unknown id onto Opus,
    // because that is the one field that selects the plane — so this decision lands here, and it
    // has exactly two wrong answers: Opus-decoding a `0xD3` payload is noise, and waiting for
    // `0xC9` frames that a `0xD3` session never sends is silence with no explanation. (`1` is
    // reserved for FLAC and emitted by nothing today; anything else is a future or corrupt wire.)
    if !matches!(
        connector.audio_codec,
        punktfunk_core::quic::AUDIO_CODEC_OPUS | punktfunk_core::quic::AUDIO_CODEC_PCM
    ) {
        tracing::warn!(
            codec = connector.audio_codec,
            "the host resolved an audio plane this client cannot decode — streaming video-only"
        );
        return None;
    }
    let lossless = connector.audio_codec == punktfunk_core::quic::AUDIO_CODEC_PCM;
    // A zero rate is inexpressible off the wire — `Welcome::decode` folds both absence and a
    // literal `0` to the legacy rate — but everything below divides by it (the ring's ms
    // reporting, the graph quantum, the jitter policy), and libopus refuses it outright. Core's
    // own C surface makes exactly this argument in `AudioFormat::of`: this is the one value that
    // must not depend on a peer's honesty.
    let rate_hz = match connector.audio_sample_rate_hz {
        0 => punktfunk_core::audio::SAMPLE_RATE_HZ,
        hz => hz,
    };
    // One protocol frame. The Opus plane's is the fixed 5 ms every build has spoken; the lossless
    // plane NEGOTIATES it from the path MTU (§4.2) — 4 ms at 48/24, 2 ms at 96/24 under the default
    // ceiling — so it must be read, never assumed.
    let frame_us = if lossless {
        // Floored at the ladder's shortest rung. A host that resolved the plane always states a
        // duration; `0` could only come from one that did not, and sizing a graph quantum, a poll
        // timeout and a scratch buffer from zero is a worse answer than the shortest real frame.
        (connector.audio_frame_us as u32).max(1_000)
    } else {
        punktfunk_core::audio::FRAME_MS * 1000
    };
    tracing::info!(
        codec = if lossless { "pcm" } else { "opus" },
        channels,
        rate_hz,
        bits = connector.audio_bits,
        frame_us,
        "negotiated audio format"
    );
    let player = audio::AudioPlayer::spawn(audio::PlaybackFormat {
        channels: channels as u32,
        rate_hz,
        frame_us,
    })
    .map_err(|e| tracing::warn!(error = %e, "audio disabled"))
    .ok()?;
    let mut dec = AudioDec::new(
        connector.audio_codec,
        channels,
        rate_hz,
        connector.audio_bits,
    )
    .map_err(|e| tracing::warn!(error = %e, "opus decoder failed — audio disabled"))
    .ok()?;
    // A/V sync (audio latency overhaul). This thread is the only place that holds all three
    // ingredients at once: the packet's host capture `pts_ns`, the ring depth (via the sync cell)
    // and the video plane's end-to-end figure. `pts_ns` was decoded into `AudioPacket` and then
    // dropped on the floor here for the plane's entire existence, which is why audio ran at
    // whatever depth its jitter ring happened to settle at and nothing ever placed it against the
    // picture.
    //
    // The escape hatch is deliberate: a field regression in a loop that steers PLAYBACK should be
    // bisectable without a rebuild, the same way `PUNKTFUNK_MIC_LEGACY_BUFFER` covers the uplink.
    let av_sync_enabled = !matches!(
        std::env::var("PUNKTFUNK_NO_AV_SYNC").as_deref(),
        Ok("1") | Ok("true")
    );
    let sync_cell = player.sync_cell();
    // The device callback's counters. Logged from THIS thread, on wall clock — the PipeWire
    // callback runs on the graph's realtime loop and formats nothing (`crate::audio_vitals`).
    let vitals = player.vitals();
    let video_e2e = connector.video_e2e_shared();
    let av_offset_out = connector.audio_av_offset_shared();
    let buffer_ms_out = connector.audio_buffer_ms_shared();
    // Interleaved samples per ms, to report the ring depth in the unit a human reads. Denominated
    // in the RESOLVED rate: 48 × channels at the protocol default, 96 × channels on a 96 kHz
    // lossless session — where the old constant would have halved every `buffer_ms` this thread
    // publishes, silently, in the direction that looks healthy.
    let per_ms = (rate_hz / 1000).max(1) as usize * channels.max(1) as usize;
    // Decode scratch, sized for whichever plane this session actually runs — the two have very
    // different worst cases, and sizing for the wrong one is either waste or an overrun:
    //
    // * **Opus (`0xC9`)**: a packet may carry up to 120 ms, which is what the old `5760 × channels`
    //   was — 120 ms at 48 kHz. Derived from the rate rather than restated as a literal so the
    //   figure cannot quietly become 60 ms if this plane ever runs anywhere but 48 kHz. This arm
    //   is a HARD BOUND: libopus decodes into a fixed slice.
    // * **PCM (`0xD3`)**: exactly one negotiated frame, 1–5 ms — two orders of magnitude smaller,
    //   and the only size a `0xD3` datagram can carry (one frame per datagram, never fragmented).
    //   Here it is only a capacity hint: `pcm::to_f32` grows the Vec itself, so an oversized
    //   datagram reallocates rather than overruns.
    let scratch = if lossless {
        punktfunk_core::audio::pcm::samples_per_frame(rate_hz, frame_us, channels)
    } else {
        120 * per_ms
    };
    // The pull loop's tick, one protocol frame. 5 ms on the Opus plane; as short as 1 ms on a
    // lossless one, where a fixed 5 ms wait would make the drought decision on the wrong schedule
    // and let the ring drain two frames between looks. Rounded UP so a sub-millisecond rung can
    // never round to a zero-length timeout and spin.
    let frame_ms = (frame_us as u64).div_ceil(1000).max(1);
    std::thread::Builder::new()
        .name("punktfunk-audio-rx".into())
        .spawn(move || {
            // Best-effort priority for the decode leg. This thread's lateness is absorbed by
            // the ring (target 15 ms and up), so it is not the callback's problem in kind — but
            // on a Steam Deck the same four cores decode 1440p120 and present it, and a decode
            // thread descheduled past the ring depth is a drought the callback then has to
            // conceal. `setpriority` where RLIMIT_NICE allows, else the Realtime portal (in a
            // flatpak) or rtkit — the sanctioned unprivileged paths; a refusal leaves the thread
            // exactly as it was. See `audio_rt`.
            crate::audio_rt::boost_and_log("punktfunk-audio-rx");
            let mut pcm = vec![0f32; scratch];
            let mut gaps = punktfunk_core::audio::AudioGapTracker::new();
            // Interleaved samples in the last decoded frame — the unit concealment is produced in.
            let mut frame_samples = 0usize;
            let mut av = punktfunk_core::audio::AvSync::new_at_rate(channels, rate_hz);
            if !av_sync_enabled {
                tracing::info!("A/V sync disabled by PUNKTFUNK_NO_AV_SYNC");
            }
            // WP-C1 — the drought half of concealment. The loop below already conceals a SEQ GAP,
            // but only when a later packet arrives to reveal it; when the wire simply goes quiet
            // nothing arrives to reveal anything, and the ring drains into an underrun and a
            // de-prime whose re-prime is a longer artifact than the audio that was missing.
            // Told the plane's real frame, so its wall-clock fuse and its `plc_ms` are spent at
            // the rate this session actually paces. It used to assume 5 ms, which on a 2 ms
            // lossless frame blew the fuse after two fifths of the time the tuning intends and
            // over-reported concealment by the same factor.
            let mut drought = punktfunk_core::audio::DroughtConceal::new_at_frame_us(
                audio::TUNING.plc_max_ms(),
                frame_us,
            );
            let mut last_packet = std::time::Instant::now();
            // The playback vitals line, ~every 10 s on wall clock (it used to be every 2 000
            // device callbacks from inside the callback — same fields, same name, so a field-log
            // grep keeps working), plus the one-shot quantum line the first time the callback
            // has published one.
            let mut last_vitals = std::time::Instant::now();
            let mut quantum_logged = false;
            while !stop.load(Ordering::SeqCst) {
                if !quantum_logged && vitals.quantum_known() {
                    quantum_logged = true;
                    let v = vitals.snapshot();
                    tracing::info!(
                        requested_frames = v.requested_frames,
                        capacity_frames = v.capacity_frames,
                        write_frames = v.write_frames,
                        // From the session's rate, not from 48: a 96 kHz quantum divided by 48
                        // reads as twice the latency it is, in the one line an on-glass latency
                        // report is triaged from.
                        write_ms = v.write_frames / (rate_hz / 1000).max(1),
                        rate_hz,
                        "audio playback quantum"
                    );
                }
                if last_vitals.elapsed() >= Duration::from_secs(10) {
                    last_vitals = std::time::Instant::now();
                    let v = vitals.snapshot();
                    tracing::debug!(
                        buffer_ms = v.buffer_ms,
                        target_ms = v.target_ms,
                        underruns = v.underruns,
                        drift_sheds = v.sheds,
                        // The other direction of the same correction: sync-driven deepening,
                        // one duplicated crossfaded frame each. Concealment must stay visible.
                        drift_inserts = v.inserts,
                        callbacks = v.callbacks,
                        // Concealment must be visible next to the underruns it prevented: a
                        // healthy `underruns` bought with a climbing `plc_ms` is a link in
                        // trouble, not a link that is fine.
                        plc_ms = sync_cell.plc_ms(),
                        "audio playback"
                    );
                }
                // Wait at most one frame WHILE there is a stream to protect: the drought decision
                // has to be made on the wire's schedule, not whenever the next packet happens to
                // turn up. Before anything has decoded there is no state to conceal from and
                // nothing to conceal for, so a session whose host never sends audio keeps the old
                // long timeout rather than waking two hundred times a second to do nothing.
                let wait_ms = if frame_samples > 0 { frame_ms } else { 100 };
                match connector.next_audio(Duration::from_millis(wait_ms)) {
                    Ok(pkt) => {
                        // Place this frame against the picture it belongs with, BEFORE it is
                        // queued: `buffered_ahead` is everything that must still play first, so
                        // the depth read here is exactly what delays it.
                        let depth = sync_cell.depth();
                        // Published unconditionally — the ring's depth is worth seeing even with
                        // sync off, and it is what makes a "too much latency" report triageable.
                        buffer_ms_out.store((depth / per_ms) as u32, Ordering::Relaxed);
                        if av_sync_enabled {
                            let ve2e = video_e2e.load(Ordering::Relaxed);
                            let o = punktfunk_core::audio::AvSyncObservation {
                                pts_ns: pkt.pts_ns,
                                now_local_ns: punktfunk_core::client::now_realtime_ns(),
                                clock_offset_ns: connector.clock_offset_now_ns(),
                                buffered_ahead: depth,
                                // 0 = nothing on the glass yet; no reference, no correction.
                                video_e2e_ns: (ve2e > 0).then_some(ve2e),
                            };
                            av.observe(o);
                            sync_cell.set_target(av.desired_depth(depth));
                            av_offset_out.store(av.offset_ms() as i64, Ordering::Relaxed);
                        }
                        last_packet = std::time::Instant::now();
                        // Anything the drought path already covered is audio the stream now has;
                        // concealing it a second time here would insert samples it never carried
                        // and push everything after them later.
                        let already = drought.packet();
                        // Conceal lost packets (a seq gap) before decoding the one that arrived.
                        // Which concealment that is, is the plane's business: libopus PLC
                        // interpolates from its own decoder state on `0xC9`, and `PcmConceal`
                        // repeats-and-fades on `0xD3`, because a lossless format has nothing to
                        // interpolate FROM (§4.5). The gap ARITHMETIC is codec-independent —
                        // both planes carry one frame per datagram under the same header, which
                        // is exactly why `AudioGapTracker` needed no second implementation.
                        for _ in 0..gaps.missing_before(pkt.seq).saturating_sub(already) {
                            if frame_samples == 0 {
                                break; // no decoded frame yet to conceal from
                            }
                            if let Some(n) = dec.conceal(frame_samples, &mut pcm) {
                                let mut buf = player.take_buffer();
                                buf.extend_from_slice(&pcm[..n]);
                                player.push(buf);
                            }
                        }
                        match dec.decode(&pkt.data, &mut pcm) {
                            // Interleaved, on both planes — see `AudioDec::decode`.
                            Some(n) => {
                                frame_samples = n;
                                let mut buf = player.take_buffer();
                                buf.extend_from_slice(&pcm[..n]);
                                player.push(buf);
                            }
                            // Opus: a corrupt packet. PCM: a datagram that is not a whole number
                            // of samples at the negotiated depth, which core refuses rather than
                            // decode as a shifted frame. Either way the frame is lost, and the
                            // next arrival's seq gap conceals it.
                            None => tracing::debug!(bytes = pkt.data.len(), "audio decode failed"),
                        }
                    }
                    Err(PunktfunkError::NoFrame) => {
                        // Nothing on the wire. If the ring is draining with it, conceal with the
                        // same machinery the loss path uses, bounded by this backend's de-prime
                        // fuse so a genuinely dead stream is not papered over. `frame_samples` is
                        // 0 until something has decoded: there is no state to extrapolate from
                        // before then.
                        //
                        // ONE frame per tick, not a burst: this arm fires every frame time, which
                        // is exactly the rate the callback drains at, so concealment keeps pace
                        // with playout instead of racing ahead of a depth reading it has already
                        // invalidated.
                        let depth_ms = (sync_cell.depth() / per_ms) as u32;
                        if frame_samples > 0 && drought.conceal(last_packet.elapsed(), depth_ms) {
                            if let Some(n) = dec.conceal(frame_samples, &mut pcm) {
                                let mut buf = player.take_buffer();
                                buf.extend_from_slice(&pcm[..n]);
                                player.push(buf);
                            }
                            sync_cell.publish_plc_ms(drought.total_ms());
                        }
                    }
                    Err(_) => break, // plane closed — the session is ending
                }
            }
            tracing::debug!("audio pull thread exited");
        })
        .map_err(|e| tracing::warn!(error = %e, "audio thread failed to start — audio disabled"))
        .ok()
}

/// Parse the `PUNKTFUNK_DEBUG_RECONFIGURE` lab lever: `WxH@HZ:SECS` → request that mode
/// SECS seconds into the stream (e.g. `1280x720@60:5`).
fn parse_debug_reconfigure(s: &str) -> Option<(Mode, Duration)> {
    let (mode_s, secs_s) = s.split_once(':')?;
    let (res, hz) = mode_s.split_once('@')?;
    let (w, h) = res.split_once('x')?;
    let mode = Mode {
        width: w.trim().parse().ok()?,
        height: h.trim().parse().ok()?,
        refresh_hz: hz.trim().parse().ok()?,
    };
    Some((mode, Duration::from_secs(secs_s.trim().parse().ok()?)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The opt-in's whole job is to be the difference between `CLIENT_CAP_AUDIO_HIRES` set and
    /// unset, so every spelling the doc comment promises has to land on the right side of it.
    #[test]
    fn the_hires_opt_in_parses_the_spellings_it_documents() {
        use punktfunk_core::audio::pcm::{BITS_16, BITS_24};
        // Off, in every shape a user might write it.
        for off in ["", "0", "off", "false", "no", "  Off  "] {
            assert_eq!(parse_audio_format(off), AudioRequest::Legacy, "{off:?}");
        }
        // On → the flagship rung. 24-bit, because 16-bit PCM spends 1.5 Mbps to sound like
        // transparent Opus.
        for on in ["1", "on", "true", "YES"] {
            assert_eq!(
                parse_audio_format(on),
                AudioRequest::Hires(96_000, BITS_24),
                "{on:?}"
            );
        }
        assert_eq!(
            parse_audio_format("96000"),
            AudioRequest::Hires(96_000, BITS_24)
        );
        assert_eq!(
            parse_audio_format("48000/24"),
            AudioRequest::Hires(48_000, BITS_24)
        );
        assert_eq!(
            parse_audio_format("96000/16"),
            AudioRequest::Hires(96_000, BITS_16)
        );
        // 48 kHz/16-bit is a REQUEST, not an "off" — the cheapest lossless rung, and the one a
        // "differs from the default" rule would have made unaskable. The connect turns this into
        // an explicit `48000`/`16` on the wire and `Legacy` into the unspecified `0`/`0`, which is
        // the only thing that tells the two apart.
        assert_eq!(
            parse_audio_format("48000/16"),
            AudioRequest::Hires(48_000, BITS_16)
        );
        assert_ne!(parse_audio_format("48000/16"), AudioRequest::Legacy);
        // …and "not asking" must never reach the wire as a format, or every ordinary session
        // would advertise hi-res.
        assert_eq!(AUDIO_FORMAT_UNSPECIFIED, (0, 0));
    }

    /// Every rung the plane cannot carry must be REFUSED here, where the user can be told, rather
    /// than sent to a host that will decline it silently from the other machine. 44.1 kHz is the
    /// one that looks reasonable: it is absent because it truncates `JitterPolicy`'s integer
    /// samples-per-millisecond arithmetic (§4.1), not because the wire could not carry it.
    #[test]
    fn the_hires_opt_in_refuses_what_the_plane_cannot_carry() {
        for bad in [
            "44100",
            "44100/24",
            "88200/24",
            "192000/24",
            "48000/32",
            "96000/8",
            "96000/",
            "/24",
            "96 kHz",
            "yes please",
            "-96000/24",
        ] {
            assert_eq!(
                parse_audio_format(bad),
                AudioRequest::Unsupported,
                "{bad:?} should not parse"
            );
        }
    }

    /// The Settings choice's stored values and the pair each asks for. The SPELLINGS are the
    /// point: they are shared verbatim with the Apple `AudioFormatChoice` raw values and the
    /// Android `AUDIO_FORMAT_*`, so one profile catalog round-trips through all four clients. A
    /// typo here fails silently — the key survives a load→save (it lands in `SettingsOverlay`'s
    /// `extra`), so the profile keeps working on the other clients and only this one ignores it.
    #[test]
    fn the_audio_format_setting_speaks_the_cross_client_spellings() {
        use punktfunk_core::audio::pcm::BITS_24;
        assert_eq!(AUDIO_FORMAT_OPUS, "opus");
        assert_eq!(AUDIO_FORMAT_LOSSLESS_48, "lossless48");
        assert_eq!(AUDIO_FORMAT_LOSSLESS_96, "lossless96");
        // The menu order every client shows, defaulting to the Opus row.
        assert_eq!(
            AUDIO_FORMATS.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
            [
                AUDIO_FORMAT_OPUS,
                AUDIO_FORMAT_LOSSLESS_48,
                AUDIO_FORMAT_LOSSLESS_96
            ]
        );

        assert_eq!(audio_format_wire(AUDIO_FORMAT_OPUS), None);
        // Both lossless rows are 24-bit: 16-bit PCM would spend 1.5 Mbps to sound like the
        // transparent 256 kbps Opus it replaces, which is why no row offers it.
        assert_eq!(
            audio_format_wire(AUDIO_FORMAT_LOSSLESS_48),
            Some((48_000, BITS_24))
        );
        assert_eq!(
            audio_format_wire(AUDIO_FORMAT_LOSSLESS_96),
            Some((96_000, BITS_24))
        );
        // A newer client's row, and a corrupted store: Opus, never a refused connect.
        assert_eq!(audio_format_wire("lossless192"), None);
        assert_eq!(audio_format_wire(""), None);
    }

    /// Precedence: `PUNKTFUNK_AUDIO_HIRES` overrides the setting in BOTH directions, an unset var
    /// leaves the setting alone, and a typo is ignored rather than being read as "off".
    ///
    /// The last one is the case that changed when the setting arrived. Before it, garbage meant
    /// off, which was the honest answer when the var was the only switch there was; now it would
    /// silently defeat a choice the user made in the UI, so the var stands down instead.
    #[test]
    fn the_env_override_beats_the_setting_in_both_directions() {
        use punktfunk_core::audio::pcm::{BITS_16, BITS_24};

        // Unset: the setting decides, which is the ordinary path on every desktop.
        assert_eq!(resolve_audio_format(None, AUDIO_FORMAT_OPUS), None);
        assert_eq!(
            resolve_audio_format(None, AUDIO_FORMAT_LOSSLESS_96),
            Some((96_000, BITS_24))
        );

        // Set: it wins, including OVER a lossless setting and including turning it off — a lever
        // that could only ever switch the feature on would be half a lever.
        assert_eq!(
            resolve_audio_format(Some("1"), AUDIO_FORMAT_OPUS),
            Some((96_000, BITS_24))
        );
        assert_eq!(
            resolve_audio_format(Some("48000/16"), AUDIO_FORMAT_LOSSLESS_96),
            Some((48_000, BITS_16)),
            "the env rung the menu does not offer is still reachable"
        );
        for off in ["0", "off", "false"] {
            assert_eq!(
                resolve_audio_format(Some(off), AUDIO_FORMAT_LOSSLESS_96),
                None,
                "{off:?} must force Opus over a lossless setting"
            );
        }

        // A typo is not an instruction: warned about and ignored, so the setting still decides.
        assert_eq!(
            resolve_audio_format(Some("96 kHz"), AUDIO_FORMAT_LOSSLESS_48),
            Some((48_000, BITS_24))
        );
        assert_eq!(resolve_audio_format(Some("44100"), AUDIO_FORMAT_OPUS), None);
    }

    /// The lossless arm's contract: interleaved counts (not per-channel), concealment that says
    /// no before it has anything to repeat, and a truncated datagram refused outright.
    ///
    /// A per-channel/interleaved mix-up here would halve every push into the ring — audible as a
    /// permanently starving ring rather than as an obvious failure, which is why it is pinned.
    #[test]
    fn the_lossless_plane_decodes_and_conceals_in_interleaved_samples() {
        use punktfunk_core::audio::pcm;
        let mut dec = AudioDec::new(
            punktfunk_core::quic::AUDIO_CODEC_PCM,
            2,
            96_000,
            pcm::BITS_24,
        )
        .expect("the PCM arm builds no codec and cannot fail");
        let mut out = Vec::new();
        // Nothing has arrived yet: saying so is what makes the caller emit silence and let the
        // ring re-prime, instead of playing an uninitialised buffer.
        assert_eq!(dec.conceal(384, &mut out), None);

        // One 2 ms frame at 96 kHz/24-bit stereo — the rung the default MTU ceiling lands on.
        let frame = pcm::samples_per_frame(96_000, 2_000, 2);
        assert_eq!(frame, 384, "192 samples per channel, interleaved");
        let mut wire = Vec::new();
        pcm::from_f32(&vec![0.5f32; frame], pcm::BITS_24, &mut wire);
        assert_eq!(
            dec.decode(&wire, &mut out),
            Some(frame),
            "interleaved count"
        );
        assert!(out[..frame].iter().all(|s| (s - 0.5).abs() < 1e-3));

        // …and now there IS something to conceal from — at the frame's own length, whatever hint
        // is passed, because `PcmConceal` holds the frame it repeats.
        assert_eq!(dec.conceal(0, &mut out), Some(frame));

        // A datagram that is not a whole number of samples at the negotiated depth is refused
        // rather than decoded as a shifted frame, which would desync every sample after it.
        assert_eq!(dec.decode(&wire[..wire.len() - 1], &mut out), None);
    }

    /// The Opus arm through the same two methods, because they now return INTERLEAVED counts
    /// where libopus itself counts per channel — the one place this refactor could have halved a
    /// working plane.
    #[test]
    fn the_opus_plane_reports_interleaved_samples_too() {
        let mut enc = opus::Encoder::new(48_000, opus::Channels::Stereo, opus::Application::Audio)
            .expect("opus encoder");
        let mut packet = [0u8; 4_000];
        let silence = [0.0f32; 240 * 2];
        let n = enc
            .encode_float(&silence, &mut packet)
            .expect("encode one 5 ms stereo frame");
        let mut dec = AudioDec::new(punktfunk_core::quic::AUDIO_CODEC_OPUS, 2, 48_000, 16)
            .expect("opus decoder");
        // The pump's scratch: 120 ms — the biggest frame the Opus plane can carry.
        let mut out = vec![0f32; 120 * 48 * 2];
        assert_eq!(dec.decode(&packet[..n], &mut out), Some(240 * 2));
        // PLC is asked for, and answered, in the same unit.
        assert_eq!(dec.conceal(240 * 2, &mut out), Some(240 * 2));
        // Nothing to size PLC from is a `None`, not a panic on an empty slice.
        let mut empty = Vec::new();
        assert_eq!(dec.conceal(0, &mut empty), None);
    }

    #[test]
    fn debug_reconfigure_parses_the_documented_shape() {
        let (mode, delay) = parse_debug_reconfigure("1280x720@60:5").unwrap();
        assert_eq!((mode.width, mode.height, mode.refresh_hz), (1280, 720, 60));
        assert_eq!(delay, Duration::from_secs(5));
    }

    #[test]
    fn debug_reconfigure_rejects_garbage() {
        for bad in [
            "",
            "1280x720",
            "1280x720@60",
            "x@:",
            "ax b@c:d",
            "1280x720@60:x",
        ] {
            assert!(parse_debug_reconfigure(bad).is_none(), "{bad:?} parsed");
        }
    }

    /// The mute is inert until the pump reports a live uplink — a session without a mic must
    /// answer "nothing to mute" rather than latching a mute and drawing the indicator.
    #[test]
    fn mic_mute_is_a_no_op_without_an_uplink() {
        let mic = MicControl::default();
        assert!(!mic.live());
        assert_eq!(mic.toggle(), None, "no uplink, nothing to toggle");
        assert!(!mic.muted(), "and nothing to show");

        mic.set_live(true);
        assert_eq!(mic.toggle(), Some(true));
        assert!(mic.muted());
        // The capture side reads the same flag the toggle writes.
        assert!(mic.flag().load(Ordering::Relaxed));
        assert_eq!(mic.toggle(), Some(false));
        assert!(!mic.muted());

        // A mute that outlives its uplink stops being shown (session end clears `live`).
        assert_eq!(mic.toggle(), Some(true));
        mic.set_live(false);
        assert!(!mic.muted());
        assert_eq!(mic.toggle(), None);
    }

    /// M8's HEVC reconnect, as the terminal event both refusal sites produce.
    ///
    /// This is the "reconnect flow tested as a first-class path" the plan's risk register
    /// asks for, at the layer where it can be tested without a host: the pump's two
    /// call sites (decoder construction and the mid-stream demotion) both go through
    /// `codec_fallback_event`, so pinning its output pins the flow — the retry never
    /// re-offers the codec that just failed, the message is user-facing, and the
    /// telemetry counter moves exactly once per occurrence.
    /// `CODEC_FALLBACKS` is process-global and `codec_fallback_event` bumps it, so the
    /// test that asserts "counted exactly once" cannot run beside another that calls the
    /// same builder. Both take this.
    static FALLBACK_COUNTER: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn an_exhausted_codec_produces_a_retry_event_and_moves_the_counter() {
        use crate::video::RungLoss;
        use punktfunk_core::quic::{CODEC_AV1, CODEC_H264, CODEC_HEVC};
        let _guard = FALLBACK_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
        let before = codec_fallbacks();

        // The shipping shape: HEVC negotiated, H.264 also advertised.
        let ev = codec_fallback_event(
            CODEC_HEVC,
            CODEC_H264 | CODEC_HEVC,
            RungLoss::Codec,
            "no software HEVC",
        );
        match ev {
            SessionEvent::CodecFallback {
                exclude_codecs,
                retry_caps,
                ref msg,
            } => {
                assert_eq!(exclude_codecs, CODEC_HEVC, "the retry must drop HEVC");
                assert_eq!(retry_caps, CODEC_H264);
                // The toast is for a person: it names the codec and says what happens
                // next, and does NOT read as an error the user has to act on.
                assert!(msg.contains("HEVC"), "{msg}");
                assert!(msg.contains("reconnect"), "{msg}");
            }
            _ => panic!("expected a CodecFallback"),
        }
        assert_eq!(codec_fallbacks(), before + 1, "counted exactly once");

        // Hardware AV1 advertised too: both survivors stay on the table.
        match codec_fallback_event(
            CODEC_HEVC,
            CODEC_H264 | CODEC_HEVC | CODEC_AV1,
            RungLoss::Codec,
            "x",
        ) {
            SessionEvent::CodecFallback { retry_caps, .. } => {
                assert_eq!(retry_caps, CODEC_H264 | CODEC_AV1);
            }
            _ => panic!("expected a CodecFallback"),
        }

        // Nothing left to offer: end honestly instead of a reconnect loop. Still counted
        // — the failure happened, and its frequency is exactly what the counter is for.
        let before = codec_fallbacks();
        match codec_fallback_event(CODEC_HEVC, CODEC_HEVC, RungLoss::Codec, "x") {
            SessionEvent::Ended(Some(msg)) => {
                assert!(msg.contains("HEVC"), "{msg}");
                assert!(msg.contains("no other codec"), "{msg}");
            }
            _ => panic!("expected a plain Ended"),
        }
        assert_eq!(codec_fallbacks(), before + 1);
    }

    /// `exclude_codecs` and `retry_caps` describe the SAME retry — the review found them
    /// disagreeing, and the wire follows `exclude_codecs`, so a mismatch means the tested
    /// rule is not the shipped one.
    ///
    /// The property is exact, not approximate: the retry advertises
    /// `decodable_codecs_for(vk) & !exclude_codecs`, and this session already advertised
    /// `decodable_codecs_for(vk) & !old_exclude` — so re-intersecting with the derived
    /// mask must land on `retry_caps` itself.
    #[test]
    fn the_retrys_exclusion_resolves_to_exactly_its_advertised_caps() {
        use crate::video::RungLoss;
        use punktfunk_core::quic::{CODEC_AV1, CODEC_H264, CODEC_HEVC, CODEC_PYROWAVE};
        let _guard = FALLBACK_COUNTER.lock().unwrap_or_else(|e| e.into_inner());
        for advertised in 0u8..16 {
            for negotiated in [CODEC_H264, CODEC_HEVC, CODEC_AV1, CODEC_PYROWAVE] {
                for loss in [RungLoss::Codec, RungLoss::Shape] {
                    let SessionEvent::CodecFallback {
                        exclude_codecs,
                        retry_caps,
                        ..
                    } = codec_fallback_event(negotiated, advertised, loss, "x")
                    else {
                        continue; // Dead — nothing is advertised at all
                    };
                    assert_eq!(
                        advertised & !exclude_codecs,
                        retry_caps,
                        "advertised {advertised:#x} negotiated {negotiated:#x} {loss:?}"
                    );
                    assert_eq!(retry_caps & negotiated, 0, "the failed codec came back");
                }
            }
        }
        // Excluding twice is idempotent — a second fallback in the same run widens the
        // set rather than resetting it (`run.rs` ORs into the existing value).
        let full = CODEC_H264 | CODEC_HEVC | CODEC_AV1;
        assert_eq!((full & !CODEC_HEVC) & !CODEC_HEVC, CODEC_H264 | CODEC_AV1);
    }
}
