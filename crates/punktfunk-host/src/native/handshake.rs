//! The native `punktfunk/1` handshake negotiation (plan §W1 — carved out of the [`super`] module).
//! After the pairing gate (which stays in `serve_session`, since its delegated-approval wait must
//! outlive the short handshake timeout and release the session permit), this decodes the client's
//! [`Hello`], runs mode-conflict admission, negotiates codec / compositor / gamepad / bitrate /
//! audio channels / bit-depth / chroma, reserves the data-plane UDP socket, sends the [`Welcome`],
//! and reads the client's [`Start`] — returning everything `serve_session` needs to stand the
//! session up.

use super::*;

/// Whether this session forwards the cursor out-of-band (design/remote-desktop-sweep.md M2):
/// the client asked ([`CLIENT_CAP_CURSOR`](punktfunk_core::quic::CLIENT_CAP_CURSOR)) AND the
/// capture path can deliver cursor metadata separately from the frame — the Linux portal
/// `SPA_META_Cursor` path (not gamescope, whose capture paints no cursor at all), or Windows
/// with a proto-v5 pf-vdisplay driver (the IddCx hardware-cursor channel, M2c) — AND, on
/// Linux, the encode backend this session resolves to can composite the pointer on demand
/// (`encode::cursor_blend_capable`): the channel's capture-mouse flip (`CursorRenderMode`,
/// `client_draws = false`) makes the HOST draw the pointer, and on Linux the encoder is that
/// compositing stage — granting the channel over a backend that can't blend (libav
/// VAAPI/NVENC, software) shipped a cursorless stream on every capture-mode flip. Denied — or
/// never asked for (a capture-latched client, `console.rs` `latched_mouse`) — the session
/// composites host-side anyway wherever the backend can blend
/// (`session_plan::cursor_blend_for`'s no-channel arm; the compositor-EMBEDS fallback never
/// paints on a Mutter virtual stream), and only a can't-blend backend falls back to the
/// compositor EMBED. THE single predicate: the Welcome's `HOST_CAP_CURSOR` bit is computed
/// from it, and the session wiring reads that bit back.
/// THE single audio-plane decision for a session: the encode tier AND whether the redundant
/// `0xD2` plane is sent. The Welcome's `HOST_CAP_AUDIO_RED` bit is computed from it, and
/// `serve_session` reads that bit back to configure the audio thread — so the wire the client is
/// promised and the wire we send cannot disagree.
///
/// Capable-and-agreed for redundancy: the client must have advertised `CLIENT_CAP_AUDIO_RED`, so a
/// session with an older client keeps the plain `0xC9` wire byte-for-byte.
///
/// **Both halves are then BUDGETED against the session's video bitrate**
/// ([`plan_audio_budget`](punktfunk_core::audio::plan_audio_budget)). Tier `High` and redundancy
/// were introduced separately, each costed as "~1 % of the video budget", and they multiply:
/// 256 kbps stereo sent twice is 512 kbps — ~10 % of a 5 Mbps session. Audio rides QUIC datagrams,
/// outside the ABR loop, so ABR can neither see that nor reclaim it. The budget is what stops a
/// constrained link silently handing a tenth of its bandwidth to audio.
///
/// The operator's `audio.quality` / `audio.redundancy` settings are the REQUEST; the budget may
/// lower them, never raise them.
///
/// NB the plan's "only while the link is actually losing packets" gate is deliberately not here:
/// turning redundancy on and off mid-session changes the wire tag, and the client's decoder would
/// have to re-derive which plane it is on from every datagram. Deciding once, at handshake, against
/// a bitrate we already know is both cheaper and more predictable.
/// `wants_redundancy` is the caller's answer to "is `0xD2` even on the table" — at handshake that
/// is the client's cap AND the operator's setting; afterwards it is the GRANTED
/// `HOST_CAP_AUDIO_RED` bit, so the audio thread re-derives the same rung of the same ladder.
pub(super) fn audio_budget(
    wants_redundancy: bool,
    video_kbps: u32,
    channels: u8,
) -> punktfunk_core::audio::AudioBudget {
    let configured = pf_host_config::config().audio_quality.as_deref();
    let requested = match configured {
        None => punktfunk_core::audio::AudioTier::default(),
        Some(s) => punktfunk_core::audio::AudioTier::parse(s).unwrap_or_else(|| {
            // Once per process: this runs per session, and an operator with a typo in host.env
            // does not need it on every connect. Never silently downgrade someone's audio.
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    value = %s,
                    "audio.quality (PUNKTFUNK_AUDIO_QUALITY) is not one of low/standard/high — \
                     using the default"
                );
            });
            punktfunk_core::audio::AudioTier::default()
        }),
    };
    punktfunk_core::audio::plan_audio_budget(video_kbps, channels, requested, wants_redundancy)
}

/// The operator's answer to "may this session use redundancy at all", before the budget is
/// consulted: the client must be able to decode it and the operator must not have forced it off.
pub(super) fn redundancy_offered(client_caps: u8) -> bool {
    client_caps & punktfunk_core::quic::CLIENT_CAP_AUDIO_RED != 0
        && pf_host_config::config().audio_redundancy.unwrap_or(true)
}

/// THE resolved audio plane for a session — the four values the `Welcome` states and the audio
/// thread is built from, produced together by [`resolve_audio_plane`] so they cannot disagree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct AudioPlane {
    /// [`AUDIO_CODEC_OPUS`](punktfunk_core::quic::AUDIO_CODEC_OPUS) (the `0xC9` plane) or
    /// [`AUDIO_CODEC_PCM`](punktfunk_core::quic::AUDIO_CODEC_PCM) (the lossless `0xD3` plane).
    pub codec: u8,
    pub rate_hz: u32,
    pub bits: u8,
    /// Frame duration in µs on the `0xD3` plane; `0` on the Opus plane, whose frame length is
    /// the fixed 5 ms of `0xC9`.
    pub frame_us: u16,
}

impl AudioPlane {
    /// Today's plane, and the answer to every failed gate below: Opus, 48 kHz, 16-bit.
    ///
    /// A fallback to this is NOT a defeat — it is a 256 kbps stereo Opus stream that is
    /// effectively transparent on game content (`design/hi-res-audio.md` §12). The only
    /// unacceptable outcome is an *unexplained* one, which is why every caller of this in the
    /// resolve gate logs its reason.
    fn opus() -> AudioPlane {
        AudioPlane {
            codec: punktfunk_core::quic::AUDIO_CODEC_OPUS,
            rate_hz: punktfunk_core::audio::SAMPLE_RATE_HZ,
            bits: punktfunk_core::audio::pcm::BITS_16,
            frame_us: 0,
        }
    }

    /// Whether this session runs the lossless `0xD3` plane rather than Opus on `0xC9`.
    pub fn is_pcm(self) -> bool {
        self.codec == punktfunk_core::quic::AUDIO_CODEC_PCM
    }

    /// Recover the resolved plane from the [`Welcome`] that was actually sent.
    ///
    /// Deliberately read BACK off the wire rather than passed forward from the gate — the same
    /// discipline `serve_session` already uses for `audio_channels` and the granted `HOST_CAP_*`
    /// bits. The client builds its decoder and opens its output device from these four values,
    /// so the encoder has to be built from the identical ones; recomputing them would leave two
    /// places that can drift, and a drift here is a session that sounds like noise.
    pub(super) fn from_welcome(w: &Welcome) -> AudioPlane {
        AudioPlane {
            codec: w.audio_codec,
            rate_hz: w.audio_rate_hz,
            bits: w.audio_bits,
            frame_us: w.audio_frame_us,
        }
    }
}

/// The largest share of the session's VIDEO bitrate the hi-res audio plane may take before the
/// request is declined (§8.4 condition 5).
///
/// Deliberately far above [`plan_audio_budget`](punktfunk_core::audio::plan_audio_budget)'s 5 %
/// ladder, and deliberately a separate number rather than a new rung on it: §4.6 is explicit that
/// hi-res must **never** be selected by that ladder — it is chosen only by an explicit opt-in on
/// both ends, and its cost has to be *visible* rather than smuggled past a budget written for
/// 96–512 kbps of Opus. Two ends asking for it earns a bigger allowance than the automatic
/// ladder's; it does not earn an unbounded one.
///
/// The reason a ceiling is needed at all is that audio rides QUIC datagrams **outside the ABR
/// loop**: whatever this plane takes is taken off the top, and ABR can neither see it nor reclaim
/// it when the link tightens. So this is not "audio gets 25 % and video adapts around it" — it is
/// "video permanently loses 25 % of a number it was already told to fit inside".
///
/// What 25 % buys, against `pcm::bitrate_kbps` **in stereo**: 48/16 (1 536 kbps) needs ≥ 6.1 Mbps
/// of video, 48/24 (2 304) needs ≥ 9.2, 96/16 (3 072) needs ≥ 12.3, 96/24 (4 608) needs ≥ 18.4.
/// A 5 Mbps session affords none of it, which is the §4.6 case ("more than half of a 5 Mbps
/// session") landing where it should.
///
/// ⚠ A 20 Mbps session no longer affords the whole stereo ladder, and this line used to say it
/// did. The 44.1 kHz family being admitted brought 176 400 Hz with it: 176.4/24 is 8 467 kbps and
/// wants ≥ 33.9 Mbps, 176.4/16 (5 644) wants ≥ 22.6. The cheap end moved too — 44.1/16 is
/// 1 411 kbps and needs only ≥ 5.6 Mbps, the first rung a modest link can actually reach.
///
/// Surround multiplies all of that by the channel count, and it is this gate rather than the frame
/// ladder that keeps it honest: 48/24 5.1 is 6 912 kbps and needs ≥ 27.6 Mbps of video, 7.1 is
/// 9 216 and needs ≥ 36.9. Both FIT a datagram comfortably — what they do not fit is an ordinary
/// link, and saying so in bits is the statement that survives a change of MTU.
const HIRES_MAX_VIDEO_SHARE_PCT: u32 = 25;

/// The §8.4 gate: resolve the session's audio plane. Returns [`AudioPlane::opus`] — today's
/// wire, byte for byte — unless **all four** policy conditions hold, and says out loud which one
/// lost.
///
/// 1. `client_asked` — the client set `CLIENT_CAP_AUDIO_HIRES`. Capable **and** the user turned
///    it on, the `VIDEO_CAP_444` precedent: a client that cannot open a 96 kHz output, or whose
///    user never asked, must not set the bit.
/// 2. `operator_allows` — `PUNKTFUNK_AUDIO_HIRES`, **default ON since 2026-08-17**; the operator
///    opts OUT with `=0`. It was default off, on the argument that this spends bandwidth the
///    host's owner never agreed to — but the operator is not who spends it, the client's user is,
///    and condition 1 is already that user's explicit choice. What a default-off operator gate
///    actually produced was a user picking "Lossless 96 kHz / 24-bit" in the client, silently
///    getting Opus, and the reason living in one `INFO` line of the host's journal. Conditions
///    3 and 4 are what keep a link safe, and they are mechanical rather than consent-based.
/// 3. `capture_rate` — the capture path can GENUINELY deliver the requested rate (§8.2 / §8.3).
///    Not "did the open succeed": both backends accept a rate their endpoint does not run at and
///    resample to it without an error, so the question has to be put to the DEVICE before the
///    `Welcome` is built. See [`CaptureRate`](crate::audio::CaptureRate) for what each OS can
///    honestly answer and why an unknown answer declines.
/// 4. The link can afford it — see [`HIRES_MAX_VIDEO_SHARE_PCT`].
///
/// …plus two that are not policies at all. The requested format must be one the plane can carry:
/// a supported depth, and a rate in [`pcm::rate_is_supported`]'s set — **both** families now,
/// 44 100 / 48 000 / 88 200 / 96 000 / 176 400. The 44.1 kHz family was deferred rather than
/// refused (§4.1: `JitterPolicy` divided by 1 000 before it multiplied, so 44 100 Hz became 44
/// samples/ms and everything derived from it came out 2.3 % low); core fixed that arithmetic, so
/// this gate asks core for the set instead of restating it — a second expression of a rate set is
/// a second thing to forget to update, and a host and a client disagreeing about it is a session
/// that negotiates a format one end cannot open.
///
/// And a frame duration must EXIST for the negotiated format at this connection's datagram size;
/// `max_datagram` is `None` when the peer does not do datagrams (in which case there is no audio
/// plane of any kind to argue about). That test is also **where the channel count is decided** —
/// there is no separate stereo-only rule, and there deliberately never was a correct one; see the
/// note at the `frame_us_for` call.
///
/// **Not a downgrade ladder, on purpose.** A client asking for 96/24 on a link that only affords
/// 48/24 is declined rather than quietly handed the cheaper rung. The wire would carry it
/// perfectly well — the client opens its device from the `Welcome`, not from its request — but
/// choosing a *different* quality on the user's behalf is a product decision, and this pass makes
/// only the mechanical one. The log line names the cost, so the operator can see what to change.
///
/// Pure, so the whole gate is unit-testable: the operator policy AND the capture probe are passed
/// in rather than read from the process environment or the audio subsystem.
#[allow(clippy::too_many_arguments)] // one parameter per §8.4 condition; a struct would only rename them
pub(super) fn resolve_audio_plane(
    client_asked: bool,
    operator_allows: bool,
    requested_rate_hz: u32,
    requested_bits: u8,
    channels: u8,
    capture_rate: crate::audio::CaptureRate,
    video_kbps: u32,
    max_datagram: Option<usize>,
) -> AudioPlane {
    use punktfunk_core::audio::pcm;
    // Silent unless the client asked. Not logged: an ordinary session with an ordinary client is
    // the overwhelming majority, and "this session did not use a feature nobody requested" is
    // noise, not diagnosis.
    if !client_asked {
        return AudioPlane::opus();
    }
    if !operator_allows {
        tracing::info!(
            // ⚠ The range is the OPERATOR's decision criterion, so it has to keep up with what
            // the plane can now negotiate: 1.4 Mbps at 44.1/16 stereo up to 8.5 at 176.4/24, and
            // up to 33.9 for 176.4/24 7.1. It read "1.5–4.6" while the plane was 48/96 stereo.
            //
            // ⚠ This is now the DELIBERATE-OPT-OUT message, not the forgot-to-opt-in one: the gate
            // defaults ON, so reaching this line means someone set the variable to `0` on this
            // host. Naming the variable AND the value it must have is the difference between an
            // operator finding their own `host.env` line and re-reading the docs for a switch they
            // never set. The old wording sent people looking for something to enable.
            "hi-res audio requested by the client but it is disabled on this host by \
             PUNKTFUNK_AUDIO_HIRES=0 — the session uses Opus 48 kHz (remove that line, or set it \
             to 1, to allow the lossless plane; it costs 1.4–8.5 Mbps in stereo and up to 33.9 in \
             7.1, off the top of the link and outside the ABR loop)"
        );
        return AudioPlane::opus();
    }
    // ⚠ No channel-count test here, deliberately. This used to hard-decline `channels != 2`
    // BEFORE the frame ladder was consulted, on the strength of §4.2's blanket "surround is out at
    // the default MTU" — which is simply not true below 96 kHz: 48/16 5.1 fits a 2 ms frame and
    // 48/24 7.1 fits a 1 ms one, well inside an ordinary datagram. An early `!= 2` did not
    // *implement* that claim, it OVERRODE the one piece of code that knows the answer.
    // `pcm::frame_us_for` is channel-aware and returns `None` when nothing fits, which is both the
    // honest decline and the one that stays right when the MTU, the ladder or the depth set moves.
    // See the frame-duration gate at the bottom of this function for what surround actually costs.
    if !pcm::depth_is_supported(requested_bits) || !pcm::rate_is_supported(requested_rate_hz) {
        tracing::info!(
            requested_rate_hz,
            requested_bits,
            "hi-res audio was requested at a format this host does not carry (44 100 / 48 000 / \
             88 200 / 96 000 / 176 400 Hz, 16 or 24-bit) — the session uses Opus 48 kHz"
        );
        return AudioPlane::opus();
    }
    // §8.4 condition 4, and the one condition that is about the world rather than about policy.
    // It is checked HERE, before the `Welcome`, rather than left for the audio thread to discover
    // at capture-open: by then the client has been promised a rate and has opened its device at
    // it, and the only remaining move is to end the lossless plane — which is the silence outcome
    // §8.4 calls the one unacceptable one. Declining here costs the session nothing but Opus.
    if !capture_rate.can_deliver(requested_rate_hz) {
        tracing::info!(
            requested_rate_hz,
            requested_bits,
            ?capture_rate,
            "hi-res audio was requested but this host's capture path cannot honestly deliver \
             that rate — the session uses Opus 48 kHz. On Windows the endpoint's own engine rate \
             is authoritative (autoconvert would silently hand us an upsampled copy), so set the \
             rate in that device's Windows properties; on Linux the default stream-sink mode \
             delivers any supported rate, while PUNKTFUNK_STREAM_SINK=0 can only offer the rate \
             the monitored sink itself runs at — and declines outright when that sink is idle or \
             cannot be read"
        );
        return AudioPlane::opus();
    }
    let cost_kbps = pcm::bitrate_kbps(requested_rate_hz, requested_bits, channels);
    let allowance = video_kbps.saturating_mul(HIRES_MAX_VIDEO_SHARE_PCT) / 100;
    if cost_kbps > allowance {
        tracing::info!(
            requested_rate_hz,
            requested_bits,
            cost_kbps,
            video_kbps,
            allowance_kbps = allowance,
            max_share_pct = HIRES_MAX_VIDEO_SHARE_PCT,
            "hi-res audio would take more of this session's bitrate than it can spare — audio \
             rides outside the ABR loop, so its cost comes off the top and ABR can neither see \
             nor reclaim it; the session uses Opus 48 kHz"
        );
        return AudioPlane::opus();
    }
    let Some(max_datagram) = max_datagram else {
        tracing::info!(
            "hi-res audio needs QUIC datagrams and this connection reports none available — the \
             session uses Opus 48 kHz"
        );
        return AudioPlane::opus();
    };
    // THE channel-count decision, and the only one: the ladder is asked whether a frame of this
    // format FITS, and `None` is the decline. Channel count enters exactly here, as the multiplier
    // it is — a 7.1 frame is four times a stereo one, so it needs a rung four times shorter and
    // runs out of ladder four times sooner.
    //
    // At a 1 400-byte datagram that lands as: 5.1 at 48/16 on 2 ms and 48/24 on 1.5 ms
    // (~667 packets/s), 7.1 at 48/16 on 1.5 ms and 48/24 on 1 ms; 16-bit 5.1 still fitting a 1 ms
    // frame at 88.2 and 96 kHz; and **nothing surround above 48 kHz in 24-bit, and no 7.1 above
    // 48 kHz at all** — 96/24 5.1 is 1 728 B of payload per millisecond, over the datagram before
    // the shortest rung is reached. §4.2's blanket "surround is out at the default MTU" is
    // therefore wrong for the whole 48 kHz-and-below half of the table.
    //
    // ⚠ The 44.1 kHz family fits the same rung or a LONGER one than 48 kHz, never a shorter one —
    // 5.1/16 takes 2.5 ms where 48 kHz takes 2 — which is counter-intuitive only until you
    // remember that a rung is a sample count here: 44 100 Hz simply puts fewer samples in the same
    // milliseconds. It is the same floor that makes the rung a label rather than a duration for
    // the pts (`audio.rs`), rounding in the safe direction for a payload and the unsafe one for a
    // clock. The arithmetic is the authority rather than the prose; the gate tests pin the matrix.
    //
    // ⚠ What this does NOT police is packet rate. A 1 ms rung is 1 000 datagrams a second on a
    // plane that rides outside the ABR loop; the affordability gate above is what keeps that from
    // being reached on a link that cannot carry it, and it is stated in bits, not packets.
    let Some(frame_us) =
        pcm::frame_us_for(requested_rate_hz, requested_bits, channels, max_datagram)
    else {
        tracing::info!(
            requested_rate_hz,
            requested_bits,
            channels,
            max_datagram,
            "no hi-res frame duration fits this connection's datagram size — the session uses \
             Opus 48 kHz. This plane is never fragmented, so a frame that would not fit one \
             datagram is not sent at all; surround and the rates above 96 kHz are what reach \
             this, and a jumbo path (PUNKTFUNK_WIRE_MTU) is what would carry them"
        );
        return AudioPlane::opus();
    };
    tracing::info!(
        rate_hz = requested_rate_hz,
        bits = requested_bits,
        frame_us,
        cost_kbps,
        video_kbps,
        max_datagram,
        // The evidence behind condition 4, not just its verdict: `Declared` and `Engine(96000)`
        // are very different grounds for the same "yes", and a field report that claims the rate
        // was padded is answered by which of them this session had.
        ?capture_rate,
        "hi-res audio resolved — the session runs the lossless 0xD3 PCM plane"
    );
    AudioPlane {
        codec: punktfunk_core::quic::AUDIO_CODEC_PCM,
        rate_hz: requested_rate_hz,
        bits: requested_bits,
        frame_us: frame_us as u16,
    }
}

pub(super) fn cursor_forward(
    client_caps: u8,
    compositor: Option<crate::vdisplay::Compositor>,
    codec: crate::encode::Codec,
    bit_depth: u8,
) -> bool {
    if client_caps & punktfunk_core::quic::CLIENT_CAP_CURSOR == 0 {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        // CUDA-payload prediction — the same one `SessionPlan` makes: the NVIDIA resolution
        // plus the zero-copy master switch. It decides direct-SDK NVENC (blends) vs libav
        // NVENC (doesn't) inside the capability mirror.
        let cuda_planned = !crate::encode::linux_zero_copy_is_vaapi() && crate::zerocopy::enabled();
        compositor.is_some_and(|c| c != crate::vdisplay::Compositor::Gamescope)
            && crate::encode::cursor_blend_capable(codec, cuda_planned, bit_depth == 10)
    }
    #[cfg(target_os = "windows")]
    {
        // Windows (M2c): the pf-vdisplay driver must speak the v5 hardware-cursor channel —
        // DWM composites the pointer into the IDD frame otherwise, and forwarding a second
        // copy would double it. The probe latches by opening the control device once. The
        // encoder is deliberately NOT consulted: the IDD capturer itself composites on the
        // capture-mouse flip (`set_cursor_forward`), so no Windows encode backend blends.
        let _ = (compositor, codec, bit_depth);
        crate::vdisplay::manager::hw_cursor_capable()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (compositor, codec, bit_depth);
        false
    }
}

/// Run the Hello→Welcome→Start negotiation. Borrows the control streams (the caller keeps them for
/// mid-stream renegotiation afterwards). `first` is the already-read first control message.
#[allow(clippy::type_complexity, clippy::too_many_arguments)]
pub(super) async fn negotiate(
    conn: &quinn::Connection,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    first: &[u8],
    source: Punktfunk1Source,
    frames: u32,
    data_port: Option<u16>,
    // WireGuard gate mode: bind the data plane on LOOPBACK at the fixed inner port and keep
    // hole-punch semantics, so the host streams back to the gate's observed flow socket.
    wg_mode: bool,
    // Session bring-up trace (latency plan P0.1): `welcome`/`start` stamps land here, and the
    // Welcome-time display prep threads it into the pipeline-build stages.
    bringup: &Arc<crate::bringup::Trace>,
    // The session's quit/stop flags — created BEFORE the handshake so the Welcome-time display
    // prep below can observe a client that vanished mid-handshake (its build retry aborts on
    // `stop`; `quit` rides into the display lease).
    quit: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    // Per-client access (design/per-client-access.md §7): the session's effective grant mask and
    // saturating seconds until its expiry (`0` = permanent), resolved by `serve_session` at
    // admission. Advertised in the Welcome so the client can gate capture / show the
    // "Controller only · ends in…" chip; the host enforces the same mask regardless.
    grants: u32,
    expires_in_secs: u32,
) -> Result<(
    Hello,
    Welcome,
    u16,
    std::net::UdpSocket,
    bool,
    Start,
    Option<crate::vdisplay::Compositor>,
    // This session's resolved gamescope sub-mode — carried to the data plane as a value rather
    // than published to process env, where a concurrent connect could overwrite it.
    Option<crate::vdisplay::GamescopeRoute>,
    Option<super::stream::PrepHandle>,
)> {
    let mut hello = Hello::decode(first).map_err(|e| anyhow!("Hello decode: {e:?}"))?;
    if hello.abi_version != punktfunk_core::WIRE_VERSION {
        close_rejected(
            conn,
            punktfunk_core::reject::RejectReason::WireVersionMismatch,
        );
        anyhow::bail!(
            "wire version mismatch: client {} host {}",
            hello.abi_version,
            punktfunk_core::WIRE_VERSION
        );
    }
    // The pairing gate (require_pairing → paired? else park for delegated approval) ran above,
    // before this future, so a client reaching here is paired (or the host is `--open`).

    // Codec negotiation: pick the one codec this host will emit (its GPU-probed backend
    // capability ∩ the client's advertised codecs, honoring the client's soft preference).
    // A GPU-less software host emits H.264 only, so an HEVC-only client shares nothing with
    // it → refuse honestly rather than send a stream it can't decode.
    let host_codecs = crate::encode::Codec::host_wire_caps();
    let codec_bit =
            punktfunk_core::quic::resolve_codec(hello.video_codecs, host_codecs, hello.preferred_codec)
                .ok_or_else(|| {
                anyhow!(
                    "no shared video codec: client advertised 0x{:02x}, host can emit 0x{:02x} \
                     (a software-encode host produces H.264 — the client must advertise CODEC_H264)",
                    hello.video_codecs,
                    host_codecs
                )
            })?;
    let codec = crate::encode::Codec::from_wire(codec_bit);
    tracing::info!(
        ?codec,
        client_codecs = format_args!("0x{:02x}", hello.video_codecs),
        host_codecs = format_args!("0x{host_codecs:02x}"),
        "video codec negotiated"
    );

    // Mode-conflict ADMISSION (Stage 4): a DIFFERENT client connecting while another client's
    // session is live is resolved by the `mode_conflict` policy BEFORE the Welcome — `separate`
    // (default, no change), `join` (serve at the live mode — an honest downgrade the client
    // renders from the Welcome), `steal` (preempt the victim), or `reject` (refuse the handshake).
    // A same-client reconnect never conflicts. THIS session registers in the live set once its
    // data plane is up (below the handshake), so a later client can see + steal it.
    {
        use crate::vdisplay::admission::{admit, preempt_same_identity, Admission};
        let peer_fp = endpoint::peer_fingerprint(conn);

        // Same-client RECONNECT preempt (design §5.3 "preempts downstream"): if THIS client
        // already has a live session, it's the zombie of an unwanted disconnect whose QUIC idle
        // timer hasn't fired yet (detection lags a drop by up to `max_idle_timeout`). Signal it to
        // stop and give it the release grace so it tears its display down — which, keep-alive on,
        // lingers — and THIS reconnect REUSES that kept display below instead of landing on a
        // fresh SECOND one. Independent of the mode_conflict arm (it's our OWN prior session, not
        // a conflict with a different client), and it runs before we register ourselves so we
        // never signal our own stop flag.
        let own_zombies = preempt_same_identity(peer_fp);
        if !own_zombies.is_empty() {
            tracing::info!(
                    count = own_zombies.len(),
                    "reconnect: preempting this client's own zombie session(s) so the kept display is reused"
                );
            for z in &own_zombies {
                z.store(true, Ordering::SeqCst);
            }
            // Same blind release grace the steal path uses — lets the zombie's loops notice the
            // stop flag and drop its display (→ Lingering) before we acquire below.
            tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        }

        match admit(peer_fp) {
            Admission::Separate => {}
            Admission::Join(m) => {
                tracing::info!(
                    requested =
                        %format_args!("{}x{}@{}", hello.mode.width, hello.mode.height, hello.mode.refresh_hz),
                    live = %format_args!("{}x{}@{}", m.0, m.1, m.2),
                    "mode-conflict: JOIN — admitting at the live display's mode"
                );
                hello.mode.width = m.0;
                hello.mode.height = m.1;
                hello.mode.refresh_hz = m.2;
            }
            Admission::Steal(victims) => {
                tracing::info!(
                    victims = victims.len(),
                    "mode-conflict: STEAL — preempting the live session(s)"
                );
                for v in &victims {
                    v.store(true, Ordering::SeqCst);
                }
                // Give the victims the release grace to tear their display down before we acquire.
                tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
            }
            Admission::Reject(reason) => {
                tracing::warn!("mode-conflict: REJECT — {reason}");
                // Deliver the reason to the client as a TYPED refusal: close the QUIC connection
                // with the BUSY application code + the reason bytes, which the client reads from
                // the `ApplicationClosed` error (so its UI can say "host is streaming X to <name>")
                // instead of seeing a bare connection drop. Then end the handshake.
                conn.close(REJECT_BUSY_CODE.into(), reason.as_bytes());
                anyhow::bail!("{reason}");
            }
        }
    }

    crate::encode::validate_dimensions(codec, hello.mode.width, hello.mode.height)
        .context("client-requested mode")?;

    // Resolve the client's compositor preference to a concrete backend *now*, so the Welcome
    // can report what we'll actually drive. Only the Virtual source has a compositor; the
    // synthetic source has no virtual output. Blocking probes → spawn_blocking.
    let compositor = match source {
        Punktfunk1Source::Virtual => {
            let pref = hello.compositor;
            // Dedicated game session (B0): a launching client under `game_session=dedicated`
            // (gamescope available) gets its own headless gamescope spawn at the client mode. Gate on
            // whether the launch id actually RESOLVES to a command in the host's library — an unknown
            // id must fall back to normal auto routing, not a blank "sleep infinity" gamescope
            // (review #9). (dedicated is Linux-only, and only there does `resolve_launch` carry a
            // command — on Windows the concrete process is resolved at launch time instead.)
            // `launch_is_resolvable`, not a full `resolve_launch`: a `plugin`-kind entry's command
            // is fetched from the owning plugin over loopback, and this runs on the async path. The
            // cheap check answers the only question asked here (does this tile launch anything?)
            // without a blocking call — see `library::launch_is_resolvable`.
            #[cfg(not(target_os = "windows"))]
            let has_resolvable_launch = hello
                .launch
                .as_deref()
                .is_some_and(crate::library::launch_is_resolvable);
            #[cfg(target_os = "windows")]
            let has_resolvable_launch = false;
            let dedicated = crate::vdisplay::wants_dedicated_game_session(has_resolvable_launch);
            Some(
                tokio::task::spawn_blocking(move || resolve_compositor(pref, dedicated))
                    .await
                    .context("resolve compositor task")??,
            )
        }
        Punktfunk1Source::Synthetic => None,
    };
    // Split the pair immediately: `compositor` keeps its old meaning for the Welcome and the
    // cursor-forward decision, while the gamescope sub-mode travels separately to the data plane
    // (SessionContext → `vd.set_gamescope_route`) instead of through process env.
    let gamescope_route = compositor.as_ref().and_then(|(_, r)| r.clone());
    let compositor = compositor.map(|(c, _)| c);

    // A requested library launch (the client sends only the store-qualified id; we look it up
    // in OUR library so a client can't inject a command) is resolved below — after the Welcome,
    // where it's threaded per-session into the data plane as `SessionContext.launch` (no
    // process-global env: the old `PUNKTFUNK_GAMESCOPE_APP` write leaked across sessions, and
    // only gamescope's bare-spawn path ever read it, so launches on every other backend were
    // silently dropped).

    // Resolve the client's gamepad-backend preference (pure env/cfg check — no probing
    // needed; the actual pads are created lazily by the input thread).
    let gamepad = resolve_gamepad(hello.gamepad);

    // (The encoder bitrate is resolved below, AFTER bit depth + chroma: PyroWave's automatic
    // ~bpp pin scales with both — design/pyrowave-444-hdr.md §2.5.)

    // Resolve the audio channel count (client request → stereo / 5.1 / 7.1). The capturer opens
    // at this count: PipeWire synthesizes the requested positions (padding with silence when the
    // sink has fewer), WASAPI loopback up/downmixes via AUTOCONVERTPCM — so a client always gets
    // the channels it asked for, and the Welcome echoes the value the audio thread will encode.
    let audio_channels = resolve_audio_channels(hello.audio_channels);
    tracing::info!(
        requested = hello.audio_channels,
        resolved = audio_channels,
        "audio channels"
    );

    // Resolve the encode bit depth: 10-bit (HEVC Main10 / AV1 10-bit) only when ALL of — the
    // host allows it (PUNKTFUNK_10BIT, default ON with explicit-off grammar; the CLIENT's HDR
    // setting behind VIDEO_CAP_10BIT is the per-session policy switch), the client advertised
    // VIDEO_CAP_10BIT (a client that can't decode 10-bit, or an older client, always gets the
    // 8-bit stream), the codec has a 10-bit path (HEVC/AV1 — H.264 never), and the active
    // GPU/backend actually encodes 10-bit for that codec (probed, cached). Resolved BEFORE the
    // Welcome, exactly like the 4:4:4 gate below, so `color` reflects what we'll really emit —
    // the honest-downgrade channel: a GPU/backend that can't 10-bit yields 8-bit AND an SDR
    // label that matches the stream.
    let host_wants_10bit = pf_host_config::config().ten_bit;
    let client_supports_10bit = hello.video_caps & punktfunk_core::quic::VIDEO_CAP_10BIT != 0;
    // The capture side must be able to deliver a 10-bit HDR source for the NATIVE plane's
    // virtual-output capture — the honest-downgrade gate, mirroring `capturer_supports_444`.
    // SOURCE-AWARE, because on Linux the answer depends on which compositor we just resolved:
    // Windows IDD-push always can (it proactively enables advanced colour); a gamescope output
    // can when the host runs our `pipewire-hdr` gamescope build and the knob allows it; every
    // other Linux virtual output is 8-bit upstream (Mutter's RecordVirtual streams, KWin's and
    // wlroots' virtual outputs alike — GNOME 50 added HDR for *monitor* streams only, which is
    // the GameStream portal-mirror path, see `gamestream::host_hdr_capable`).
    //
    // The gamescope arm folds in its own downgrade latch
    // (`pf_capture::hdr_capture_failed(VirtualOutput)`), which is why the check the GameStream
    // path makes separately in rtsp.rs has no twin here: that latch is per-source, and this gate
    // already consulted the one belonging to the source this session will drive.
    let capture_supports_hdr = crate::capture::capturer_supports_hdr_for(compositor);
    // The GPU probe may open a tiny encoder on first use, so run it off the reactor like the
    // 4:4:4 probe below (blocking probes → spawn_blocking), short-circuited behind the cheap
    // gates. The result is cached process-wide per (GPU, codec).
    let gpu_can_10bit = if host_wants_10bit
        && client_supports_10bit
        && codec.supports_10bit()
        && capture_supports_hdr
    {
        tokio::task::spawn_blocking(move || crate::encode::can_encode_10bit(codec))
            .await
            .context("10-bit capability probe task")?
    } else {
        false
    };
    let bit_depth: u8 = if gpu_can_10bit { 10 } else { 8 };
    tracing::info!(
        bit_depth,
        host_wants_10bit,
        client_supports_10bit,
        capture_supports_hdr,
        codec = ?codec,
        gpu_can_10bit,
        client_video_caps = hello.video_caps,
        "encode bit depth"
    );

    // Resolve the chroma subsampling: full-chroma HEVC 4:4:4 only when ALL of — the host
    // allows it (PUNKTFUNK_444, default ON; the CLIENT's 4:4:4 setting — default OFF — is the
    // per-session policy switch behind VIDEO_CAP_444), the client advertised VIDEO_CAP_444,
    // the session is single-process (the two-process WGC relay encodes 4:2:0 in v1), and the
    // active GPU/driver actually supports a 4:4:4 encode (probed, cached). The native path
    // always encodes HEVC. We resolve this BEFORE the Welcome so `chroma_format` reflects
    // what we'll really emit — the honest-downgrade channel: if any gate fails the client is
    // told 4:2:0 before it builds its decoder. The probe opens a tiny encoder; it runs only
    // when the earlier gates pass and is cached after the first.
    let host_wants_444 = pf_host_config::config().four_four_four;
    let client_supports_444 = hello.video_caps & punktfunk_core::quic::VIDEO_CAP_444 != 0;
    // The active capturer must be able to deliver a full-chroma (RGB) source — the honest-downgrade
    // gate. Linux's portal capturer always can (`capturer_supports_444` returns `true`
    // unconditionally). On WINDOWS the IDD-push path CAN too, at either depth: an SDR session
    // passes the BGRA ring slot straight through and an HDR one converts the FP16 desktop to
    // packed 10-bit BT.2020 PQ RGB — both skip the subsampling converters. Only a backend that
    // ingests RGB and CSCs it to 4:4:4 itself can consume that, so the Windows arm forwards
    // `resolved_backend_ingests_rgb_444()` (today: direct-NVENC only; AMF can't 4:4:4 at all and
    // the QSV/ffmpeg path has no RGB-input 4:4:4 wiring). HDR no longer costs the chroma: 10-bit
    // 4:4:4 is HEVC Main 4:4:4 10, which is what this resolves to. (Replaces the old
    // `single_process` gate — single-process is now the only topology, and 4:4:4 routed to DDA,
    // which was removed.)
    // PyroWave does its own RGB→YCbCr CSC and its capture mode always delivers a full-chroma
    // (RGB/BGRA) source on both OSes — the capturer gate is inherently satisfied; the real
    // gate is `can_encode_444` (the full-res-chroma CSC variant existing on this OS).
    // Named for the whole capture→encoder INGEST chain, not the capturer: on Windows the
    // deciding fact is the encoder backend (direct NVENC only), and a field report burned
    // real time hunting a capture problem because the old `capture_supports_444` key said so.
    let ingest_chain_supports_444 = codec == crate::encode::Codec::PyroWave
        || crate::capture::capturer_supports_444(crate::encode::resolved_backend_ingests_rgb_444());
    // The GPU probe opens a real (tiny) encoder on first use, so run it off the reactor like the
    // compositor probe above (blocking probes → spawn_blocking). Short-circuit so it only runs when
    // the cheap gates already pass. The result is cached process-wide (a negative latches until
    // restart — acceptable: a GPU either supports HEVC 4:4:4 or it doesn't, and a transient open
    // failure here is rare since the session's own encoder isn't open yet).
    let gpu_supports_444 = if matches!(
        codec,
        crate::encode::Codec::H265 | crate::encode::Codec::PyroWave
    ) && host_wants_444
        && client_supports_444
        && ingest_chain_supports_444
    {
        tokio::task::spawn_blocking(move || crate::encode::can_encode_444(codec))
            .await
            .context("4:4:4 capability probe task")?
    } else {
        false
    };
    // The client's 4:4:4 setting IS the VIDEO_CAP_444 bit — when the user flipped it on and
    // the session still resolves 4:2:0, name the losing gate. (The PyroWave mode-size gate
    // below warns for itself.)
    if host_wants_444 && client_supports_444 && !gpu_supports_444 {
        let reason = if !matches!(
            codec,
            crate::encode::Codec::H265 | crate::encode::Codec::PyroWave
        ) {
            "the negotiated codec only carries 4:2:0 — 4:4:4 needs HEVC or PyroWave"
        } else if !ingest_chain_supports_444 {
            "this host's encoder backend can't ingest full chroma — 4:4:4 needs direct \
             NVENC (NVIDIA) or the PyroWave codec"
        } else {
            "the GPU declined the 4:4:4 encode profile probe"
        };
        tracing::info!(reason, "4:4:4 requested but the session negotiates 4:2:0");
    }
    let chroma = if gpu_supports_444 {
        crate::encode::ChromaFormat::Yuv444
    } else {
        crate::encode::ChromaFormat::Yuv420
    };
    // PyroWave-only mode-size gate: the vendored rate controller packs its block index into
    // 16 bits (pyrowave-sys patches/0002 note), which ≈8K-class 4:4:4 overflows — downgrade
    // to 4:2:0 BEFORE the Welcome (the honest-downgrade channel), like every gate above.
    let chroma = if codec == crate::encode::Codec::PyroWave
        && chroma.is_444()
        && !crate::encode::pyrowave_mode_fits_rdo(hello.mode.width, hello.mode.height, true)
    {
        tracing::warn!(
            mode = %format_args!("{}x{}", hello.mode.width, hello.mode.height),
            "PyroWave 4:4:4 at this mode exceeds the rate controller's block-index range — \
             negotiating 4:2:0"
        );
        crate::encode::ChromaFormat::Yuv420
    } else {
        chroma
    };
    tracing::info!(
        chroma = ?chroma,
        host_wants_444,
        client_supports_444,
        ingest_chain_supports_444,
        "encode chroma"
    );

    // Linux 4:4:4 rides the CPU swscale → 8-bit `YUV444P` path (see `encode/linux`) — there
    // is no 10-bit 4:4:4 input there, so a 10-bit-negotiated session would silently encode
    // 8-bit. Resolve the depth DOWN before the Welcome so the wire never overstates what the
    // stream carries. (Windows NVENC composes Main 4:4:4 10 from an RGB input, so it keeps
    // the resolved depth — this clamp is Linux-only.)
    #[cfg(target_os = "linux")]
    let bit_depth: u8 = if chroma.is_444() && bit_depth == 10 {
        tracing::info!("4:4:4 on the Linux path encodes 8-bit YUV444P — resolving bit depth 8");
        8
    } else {
        bit_depth
    };

    // Resolve the encoder bitrate (client request clamped to a sane range, or a codec-aware
    // host default). Resolved AFTER depth + chroma: PyroWave's Automatic rate is a ~bpp pin
    // for the negotiated mode that scales with both (design/pyrowave-444-hdr.md §2.5).
    let bitrate_kbps =
        resolve_bitrate_kbps_for(codec, hello.bitrate_kbps, &hello.mode, chroma, bit_depth);
    tracing::info!(
        requested_kbps = hello.bitrate_kbps,
        resolved_kbps = bitrate_kbps,
        "encoder bitrate"
    );

    // Reserve the data-plane UDP socket up front and HOLD it through streaming (no
    // bind→read→drop→rebind window a concurrent session could race for a fixed port). A fixed
    // `--data-port` yields `direct = true` (stream straight to the client's reported address,
    // no punch-wait); otherwise a random ephemeral port + hole-punch.
    //
    // WireGuard gate mode is different on BOTH axes: the socket binds the fixed inner port on
    // LOOPBACK (the gate relays tunnel traffic to it), and `direct` stays false — the client's
    // "reported address" (127.0.0.1:<its local port>) only exists on the far side of the tunnel,
    // so the host must stream to the gate flow socket it actually observes a punch from.
    let (data_sock, direct) = if wg_mode {
        let port = data_port
            .filter(|p| *p != 0)
            .unwrap_or(super::WG_DATA_PORT);
        let sock = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, port)).map_err(|e| {
            anyhow::anyhow!(
                "WireGuard data plane: bind 127.0.0.1:{port}: {e} \
                 (a concurrent WG session already holds the fixed inner data port?)"
            )
        })?;
        (sock, false)
    } else {
        bind_data_socket(data_port)?
    };
    let udp_port = data_sock.local_addr()?.port();

    // The session's video geometry (see the `shard_payload` field below). Resolved before the
    // Welcome struct because a path a previous session proved jumbo is given a bounded moment
    // to re-prove itself live on THIS connection — the awaited part of `negotiated_shard_payload`.
    let shard_payload = wire_mtu::negotiated_shard_payload(conn, hello.max_shard_payload).await;

    let mut key = [0u8; 16];
    rand::rng().fill_bytes(&mut key);
    // Fresh per-session salt alongside the fresh key. GCM nonce uniqueness only *requires* one
    // of the two to be unique per session (the nonce is salt || sequence under the session
    // key), but a constant salt would make a key-reuse bug catastrophic instead of merely
    // wrong — this keeps the second line of defense real. Negotiated via Welcome, so clients
    // just follow.
    let mut salt = [0u8; 4];
    rand::rng().fill_bytes(&mut salt);
    // Session AEAD: ChaCha20-Poly1305 when the client asked for it (VIDEO_CAP_CHACHA20 — the
    // soft-AES armv7 targets, whose GCM decrypt caps at ~100 Mbps) and the operator
    // kill-switch allows (PUNKTFUNK_CHACHA20, default on — pure rollout safety; perf-only,
    // both AEADs are full-strength). The fresh-per-session discipline above applies to this
    // key identically; the legacy 16-byte `key` stays independently random so nothing
    // downstream ever observes an all-zero key.
    let client_wants_chacha = hello.video_caps & punktfunk_core::quic::VIDEO_CAP_CHACHA20 != 0;
    let chacha = client_wants_chacha && pf_host_config::config().chacha20;
    let key_chacha = chacha.then(|| {
        let mut k = [0u8; 32];
        rand::rng().fill_bytes(&mut k);
        k
    });
    tracing::info!(
        cipher = if chacha {
            "chacha20-poly1305"
        } else {
            "aes-128-gcm"
        },
        client_wants_chacha,
        "session cipher"
    );

    // The audio plane (design/hi-res-audio.md §8.4): Opus on `0xC9`, or the lossless PCM `0xD3`
    // plane when all five conditions hold. Every decline path inside logs its reason — the design
    // is explicit that "silence is the one unacceptable outcome", and an unexplained fallback is
    // the shape that produces it.
    //
    // ⚠ `conn.max_datagram_size()` here is quinn's CURRENT value, and QUIC MTU discovery has
    // NOT settled at Welcome time — it starts when the handshake completes and needs an acked
    // probe per binary-search step, which is exactly why `negotiated_shard_payload` above has to
    // *wait* for a jumbo re-proof. §4.2 warns that reading it too early sizes for the
    // conservative initial value, and that is what happens here.
    //
    // It is deliberate, and it is the SAFE direction: the frame duration is a promise made in
    // the `Welcome`, the client sizes its ring and opens its device from it, and this plane has
    // no mechanism to restate it mid-session (§6 — a session runs one plane at one frame length,
    // and switching would mean re-opening the client's device). A frame that fits the initial
    // MTU keeps fitting as the MTU grows; a frame sized for a discovered MTU that then turns out
    // not to hold would not be sent at all. So the cost of reading early is a slightly higher
    // packet rate than the path could carry — never a dropped plane.
    //
    // TODO(hi-res H5): to spend the discovered MTU instead, the frame duration has to be decided
    // AFTER discovery settles, which needs either a `Welcome` sent later than it is today or a
    // wire message that restates `audio_frame_us` before the client opens its output. Both are
    // wire/sequencing changes well beyond this pass; neither is needed for 48 kHz, where the
    // conservative answer already lands on the longest rung.
    let hires_asked = hello.client_caps & punktfunk_core::quic::CLIENT_CAP_AUDIO_HIRES != 0;
    // A `Hello` that names a format but does not set the capability is CONTRADICTORY, and the two
    // halves come from different places in a client — the capability from a settings toggle, the
    // rate and depth from whatever that toggle resolved to. Condition 1 below is deliberately not
    // logged, because "no capability" is every ordinary session with every shipping client and
    // would drown the log. This case is not ordinary: something asked, and is being ignored.
    //
    // Worth the line because it is the exact shape that cost an on-glass session its first run —
    // the host resolved Opus while every visible condition looked satisfiable, and the reason was
    // unlogged by design. An embedder hitting this sees nothing at all otherwise.
    if !hires_asked && (hello.audio_rate_hz != 0 || hello.audio_bits != 0) {
        tracing::warn!(
            requested_rate_hz = hello.audio_rate_hz,
            requested_bits = hello.audio_bits,
            "client sent an audio format but not CLIENT_CAP_AUDIO_HIRES — ignoring it and \
             staying on Opus; the capability and the format must be set together"
        );
    }
    let hires_allowed = pf_host_config::config().audio_hires;
    // §8.4 condition 4 — what the capture path can HONESTLY deliver, asked of the device rather
    // than inferred from a successful open (§4.3/§4.4: both backends resample a rate they cannot
    // run at, without an error). Blocking on Windows (an endpoint enumeration plus an
    // `IAudioClient` activation per candidate), so it runs off the reactor like the 10-bit and
    // 4:4:4 probes above.
    //
    // Short-circuited behind the two cheap policy conditions, which is the same discipline those
    // probes use: an ordinary session — every session with every shipping client today — must not
    // pay COM work for a feature nobody asked for. ⚠ Since the operator gate went default-ON that
    // guarantee rests on `hires_asked` ALONE, so keep it first: a client that does not set
    // CLIENT_CAP_AUDIO_HIRES is now the only thing standing between an ordinary Windows session
    // and an endpoint enumeration it has no use for. The value is not merely unused in that case
    // but unreachable, since the gate returns on condition 1 or 2 before it looks at this one;
    // `Unknown` is nonetheless the correct thing to pass, because "we did not ask" and "we asked
    // and could not tell" both mean the same thing to the gate: decline.
    let capture_rate = if hires_asked && hires_allowed {
        tokio::task::spawn_blocking(crate::audio::probe_capture_rate)
            .await
            .context("audio capture-rate probe task")?
    } else {
        crate::audio::CaptureRate::Unknown
    };
    let audio_plane = resolve_audio_plane(
        hires_asked,
        hires_allowed,
        hello.audio_rate_hz,
        hello.audio_bits,
        audio_channels,
        capture_rate,
        bitrate_kbps,
        conn.max_datagram_size(),
    );

    let welcome = Welcome {
        abi_version: punktfunk_core::WIRE_VERSION,
        udp_port,
        mode: hello.mode,
        // The post-GameStream point of punktfunk/1: Leopard GF(2¹⁶) FEC + real encryption.
        fec: FecConfig {
            scheme: FecScheme::Gf16,
            // Static override pins it; otherwise sessions start at the adaptive midpoint and the
            // host re-sizes FEC live from the client's LossReports (adaptive FEC).
            fec_percent: fec_static_override().unwrap_or(FEC_ADAPTIVE_START),
            max_data_per_block: 4096,
        },
        // The largest even payload whose sealed datagram (header + shard + crypto) fits an
        // unfragmented UDP packet on a 1500 MTU for THIS client's address family — 1408 over
        // IPv4 (1472 = the exact ceiling), 1388 over IPv6 (40-byte header, and v6 routers
        // don't fragment: overshooting there blackholes instead of degrading). The data plane
        // dials the same family as this QUIC connection, so the remote decides. The previous
        // hardcoded 1452 overshot the v4 ceiling (its math forgot the header/crypto ride
        // inside the UDP payload) and silently IP-fragmented EVERY video datagram, doubling
        // per-datagram loss on Wi-Fi — the "100 Mbps badly fails on the phone" root cause.
        // Negotiated, so the client follows.
        // Resolution order (wire_mtu.rs): a JUMBO start (≈8900) on a path a previous session
        // proved AND this connection has just re-proved live, then the `PUNKTFUNK_WIRE_MTU`
        // operator override, then a path budget learned from a prior session whose QUIC MTU
        // discovery settled below the video-datagram ceiling (the "VPN on the host blackholes
        // every video packet" field shape — small flows pass, the stream is an endless black
        // screen), then this family default. Healthy paths take the default branch and are
        // byte-identical to before.
        shard_payload: shard_payload as u16,
        encrypt: true,
        key,
        salt,
        frames: match source {
            Punktfunk1Source::Synthetic => frames,
            Punktfunk1Source::Virtual => 0, // unbounded — client streams until we close
        },
        // Report the resolved backends back to the client (compositor: Auto for the
        // synthetic source).
        compositor: compositor
            .map(|c| c.as_pref())
            .unwrap_or(CompositorPref::Auto),
        gamepad,
        bitrate_kbps,
        bit_depth,
        // Colour signalling the client configures its decoder/presenter from. A negotiated
        // 10-bit session is our HDR path (BT.2020 PQ — what the NVENC HEVC VUI emits from a
        // 10-bit capture format); 8-bit stays BT.709 SDR. The mastering metadata (ST.2086 +
        // CLL) rides the 0xCE datagram below. (A future step can refine this to the capturer's
        // actual monitor HDR state and announce a mid-stream flip.)
        color: if bit_depth >= 10 {
            ColorInfo::HDR10_BT2020_PQ
        } else {
            ColorInfo::SDR_BT709
        },
        // The chroma the encoder will actually emit (resolved + GPU-probed above) — 4:4:4 only
        // when every gate passed, else 4:2:0. The client sizes its decoder from this.
        chroma_format: chroma.idc(),
        // The resolved audio channel count the audio thread will capture + Opus-(multi)stream
        // encode (2/6/8). The client builds its decoder from this echoed value.
        audio_channels,
        // The negotiated codec the encoder will emit (client preference ∩ GPU capability;
        // HEVC-precedence tie-break). The client builds its decoder from this instead of
        // assuming HEVC.
        codec: codec_bit,
        // This host applies sequence-gated gamepad-state snapshots (InputKind::GamepadState),
        // so capable clients send those instead of the loss-fragile per-transition events. The
        // clipboard bit is advertised only when the operator policy enables it (design
        // clipboard-and-file-transfer.md §3.1) AND this platform has a backend — see
        // `pf_clipboard::cap_advertised` for the deliberate compositor-lacks-data-control case.
        host_caps: punktfunk_core::quic::HOST_CAP_GAMEPAD_STATE
            | if pf_clipboard::cap_advertised() {
                punktfunk_core::quic::HOST_CAP_CLIPBOARD
            } else {
                0
            }
            // Committed-text injection (InputKind::TextInput): only where the session's inject
            // backend can actually type text — Windows SendInput (KEYEVENTF_UNICODE) and the
            // Linux wlroots virtual keyboard (dynamic Unicode keymap). Clients without the bit
            // keep their VK-synthesis fallback for IME text.
            | if crate::inject::text_input_supported() {
                punktfunk_core::quic::HOST_CAP_TEXT_INPUT
            } else {
                0
            }
            // Cursor channel granted (client asked + this capture path can deliver cursor
            // metadata out of the frame + the resolved encoder can composite on the
            // capture-mouse flip) — the client turns its local renderer on ONLY when it sees
            // this bit, and serve_session wires forwarding by reading the bit back.
            | if cursor_forward(hello.client_caps, compositor, codec, bit_depth) {
                punktfunk_core::quic::HOST_CAP_CURSOR
            } else {
                0
            }
            // Full-fidelity stylus (0xCC/0x05 pen batches → the per-session uinput tablet):
            // Linux with /dev/uinput access, minus the PUNKTFUNK_PEN=0 kill-switch. Clients
            // without the bit keep folding pen into touch/pointer (and NativeClient::send_pen
            // refuses toward us if we don't set it).
            | if crate::inject::pen_supported() {
                punktfunk_core::quic::HOST_CAP_PEN
            } else {
                0
            }
            // Redundant desktop-audio plane (0xD2): the client asked, the operator has not forced
            // it off, AND it fits the session's audio budget. Capable-and-agreed like the cursor
            // bit — a client that did not ask keeps the plain 0xC9 wire byte-for-byte.
            //
            // Never alongside the lossless plane: `0xD2` is not defined for `0xD3` and is never
            // sent with it (§4.5). Doubling a 1.4–33.9 Mbps plane is absurd on its face, and the
            // client has no `0xD2` decoder on the PCM side to receive it — so the two bits are
            // mutually exclusive on the wire, stated here rather than left to the audio thread
            // to discover.
            | if !audio_plane.is_pcm()
                && audio_budget(
                    redundancy_offered(hello.client_caps),
                    bitrate_kbps,
                    audio_channels,
                )
                .redundancy
            {
                punktfunk_core::quic::HOST_CAP_AUDIO_RED
            } else {
                0
            }
            // Per-pad DualSense audio (0xD1 + HidOutput::AudioCtl): granted only when the
            // client asked AND this host can capture it — Windows with the feature enabled
            // and at least one pad endpoint provisioned at startup. A capable client then
            // marks its pads' renderers on their arrivals; the input thread streams toward
            // exactly those pads (`super::pad_audio`).
            | if super::pad_audio::host_cap(hello.client_caps) {
                punktfunk_core::quic::HOST_CAP_PAD_AUDIO
            } else {
                0
            }
            // Lossless desktop audio (0xD3 PCM): set ONLY when the §8.4 gate above actually
            // resolved to PCM — the bit is a statement about the wire this session will carry,
            // not about what the host could do in principle, exactly like HOST_CAP_AUDIO_RED.
            // ⚠ 0x80 is the LAST free host_caps bit; the next host capability needs a second
            // byte and an ABI bump (§4.7).
            | if audio_plane.is_pcm() {
                punktfunk_core::quic::HOST_CAP_AUDIO_HIRES
            } else {
                0
            },
        // Where this host serves its game library, so the client never has to have seen an mDNS
        // advert to find it. `0` on the standalone punktfunk1-host binary (no management API),
        // and the client then keeps its compiled-in default.
        mgmt_port: crate::mgmt::effective_port(),
        // Per-client access (design/per-client-access.md §7): the trust record's effective mask
        // and remaining lifetime, resolved by `serve_session` at admission. A full-control
        // permanent device advertises `GRANT_ALL, 0` — exactly what every pre-grants client assumes.
        grants,
        expires_in_secs,
        // The negotiated session AEAD (resolved above) + its 32-byte key toward a ChaCha
        // client; toward everyone else cipher 0 keeps the Welcome byte-identical to the
        // pre-cipher wire form — unless a mgmt port rides along, which forces the cipher
        // placeholder (see `Welcome::encode`). The host's own data plane picks the cipher up via
        // `welcome.session_config` — no other host change.
        cipher: if chacha {
            punktfunk_core::quic::CIPHER_CHACHA20_POLY1305
        } else {
            punktfunk_core::quic::CIPHER_AES_128_GCM
        },
        key_chacha,
        // The RESOLVED audio plane, from the §8.4 gate above. Opus at 48 kHz / 16-bit — the
        // legacy answer — makes `Welcome::encode` omit all four fields, so an Opus session's
        // Welcome stays byte-identical to the pre-hi-res wire form for every client (the interop
        // property the cipher byte bought and every appended field since has had to keep).
        //
        // These are the values the client opens its output device from; it must never open from
        // what it ASKED for. `audio_frame_us` is `0` on the Opus plane, whose frame length is the
        // fixed 5 ms of 0xC9.
        audio_codec: audio_plane.codec,
        audio_rate_hz: audio_plane.rate_hz,
        audio_bits: audio_plane.bits,
        audio_frame_us: audio_plane.frame_us,
    };
    io::write_msg(send, &welcome.encode()).await?;
    bringup.mark("welcome");

    // P1.1/P1.2 (latency plan): kick the display prep NOW — the negotiated mode is final in
    // the Welcome just sent, and nothing in monitor create → activation → settle → capture
    // attach → encoder open needs the client's Start or the punched socket. The prep thread
    // BECOMES the stream thread: the data plane hands it the post-punch SessionContext and it
    // runs `virtual_stream` on the warm pipeline, so the whole display bring-up hides behind
    // the Start RTT + the (up to 2.5 s) hole-punch wait. If the session dies before its data
    // plane comes up (handshake timeout, client vanished), the channel drops and the prep
    // result is released — the monitor lands in the keep-alive machinery exactly like a
    // normal session end (and `stop`, watched by the caller, aborts a still-running build
    // retry). Windows native path only: the Linux backends bind launch semantics before create
    // (gamescope nests the launch command), which must not run for a client that never sends
    // Start; GameStream has neither a Start gate nor a punch.
    #[cfg(target_os = "windows")]
    let prep: Option<super::stream::PrepHandle> = match (source, compositor) {
        (Punktfunk1Source::Virtual, Some(comp)) => {
            let (ctx_tx, ctx_rx) = std::sync::mpsc::sync_channel::<SessionContext>(1);
            let client_identity = endpoint::peer_fingerprint(conn);
            let client_hdr = hello.display_hdr;
            // The bit the Welcome just advertised — read back rather than recomputed, so the
            // prepared display and the session wiring cannot disagree with it.
            let cursor_fw = welcome.host_caps & punktfunk_core::quic::HOST_CAP_CURSOR != 0;
            // Same bit the data plane's SessionContext reads — the prepared plan and the
            // session wiring must agree on the slicing ceiling (an encoder rebuilt from the
            // prepared plan with a DIFFERENT max_slices would change the wire shape mid-flow).
            let multi_slice = hello.video_caps & punktfunk_core::quic::VIDEO_CAP_MULTI_SLICE != 0;
            let (mode, shard_payload) = (hello.mode, welcome.shard_payload);
            // "Automatic" — `bitrate_kbps` above is the host's own answer for `mode`, so the build
            // may re-resolve it if the source turns out to deliver a different size. Sampled here
            // rather than in the thread body so the closure doesn't have to capture `hello`.
            let bitrate_auto = hello.bitrate_kbps == 0;
            let trace = bringup.clone();
            std::thread::Builder::new()
                .name("punktfunk1-stream".into())
                .spawn(move || -> Result<()> {
                    let prepared = super::stream::prepare_display(
                        comp,
                        mode,
                        client_identity,
                        client_hdr,
                        cursor_fw,
                        multi_slice,
                        bitrate_kbps,
                        bitrate_auto,
                        bit_depth,
                        chroma,
                        codec,
                        shard_payload,
                        &quit,
                        &stop,
                        &trace,
                    );
                    let Ok(ctx) = ctx_rx.recv() else {
                        // No data plane ever came (handshake abort / punch failure): drop
                        // `prepared` — its lease release hands the monitor to keep-alive
                        // policy, exactly like a normal session end.
                        return Ok(());
                    };
                    match prepared {
                        Ok(p) => virtual_stream(ctx, Some(p)),
                        Err(e) => Err(e),
                    }
                })
                .map(|handle| (ctx_tx, handle))
                .map_err(|e| {
                    tracing::warn!(error = %e,
                        "display-prep thread spawn failed — falling back to inline bring-up")
                })
                .ok()
        }
        _ => None,
    };
    #[cfg(not(target_os = "windows"))]
    let prep: Option<super::stream::PrepHandle> = None;
    #[cfg(not(target_os = "windows"))]
    let _ = (quit, stop);

    let start =
        Start::decode(&io::read_msg(recv).await?).map_err(|e| anyhow!("Start decode: {e:?}"))?;
    bringup.mark("start");
    // The wire-MTU watch (`wire_mtu::spawn_watch`) is spawned by `serve_session` after the
    // control-task channels exist — it now also DRIVES the mid-session shard renegotiation
    // (design/shard-payload-reneg.md), which needs the control stream's writer.
    Ok::<_, anyhow::Error>((
        hello,
        welcome,
        udp_port,
        data_sock,
        direct,
        start,
        compositor,
        gamescope_route,
        prep,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use punktfunk_core::audio::pcm;

    /// A usable datagram at the default 1472-byte discovery ceiling, less QUIC header + AEAD
    /// tag. The same number `pcm`'s own ladder test argues from.
    const DGRAM: usize = 1400;
    /// Comfortably above the 25 % allowance for every STEREO rung on the ladder (96/24 needs
    /// 18.4).
    const FAT_LINK_KBPS: u32 = 40_000;
    /// …and enough for every SURROUND rung too — 176.4/24 7.1 is 33 869 kbps and wants ≥ 135 Mbps.
    /// Used only where the frame ladder is the thing under test, so a row that should fail on
    /// arithmetic cannot fail on bandwidth first and look like a pass for the wrong reason.
    const HUGE_LINK_KBPS: u32 = 200_000;
    /// A capture path that can carry anything the plane asks for — Linux stream-sink mode, where
    /// the host declares the format itself (§4.4). The condition-4 tests vary this; every other
    /// test holds it here so it is never the thing that made them pass or fail.
    const HONEST_CAPTURE: crate::audio::CaptureRate = crate::audio::CaptureRate::Declared;

    /// The happy path, so every decline test below is a difference from something that works.
    #[test]
    fn all_five_conditions_met_resolves_to_the_lossless_plane() {
        for (rate, bits) in [
            (48_000u32, pcm::BITS_16),
            (48_000, pcm::BITS_24),
            (96_000, pcm::BITS_16),
            (96_000, pcm::BITS_24),
        ] {
            let p = resolve_audio_plane(
                true,
                true,
                rate,
                bits,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                Some(DGRAM),
            );
            assert!(p.is_pcm(), "{rate}/{bits} should have resolved to PCM");
            assert_eq!(p.rate_hz, rate);
            assert_eq!(p.bits, bits);
            // The negotiated frame must actually fit, or the datagram is never sent at all.
            assert!(
                pcm::frame_payload_bytes(rate, bits, 2, p.frame_us as u32) + pcm::PCM_HEADER_LEN
                    <= DGRAM,
                "{rate}/{bits} chose a {} µs frame that does not fit",
                p.frame_us
            );
        }
    }

    /// §8.4 condition 1 — the client never asked. This is every session with every shipping
    /// client today, so it must be the quietest possible path to the legacy wire.
    #[test]
    fn a_client_that_did_not_ask_gets_opus() {
        let p = resolve_audio_plane(
            false,
            true,
            96_000,
            pcm::BITS_24,
            2,
            HONEST_CAPTURE,
            FAT_LINK_KBPS,
            Some(DGRAM),
        );
        assert_eq!(p, AudioPlane::opus());
    }

    /// §8.4 condition 2 — the operator's `PUNKTFUNK_AUDIO_HIRES` gate. Default ON since
    /// 2026-08-17, so this is now the OPT-OUT path (`=0`) rather than the un-opted-in one: an
    /// operator who has deliberately turned the plane off outranks a client that asks for it, and
    /// still gets today's wire.
    #[test]
    fn the_operator_gate_alone_can_decline() {
        let p = resolve_audio_plane(
            true,
            false,
            48_000,
            pcm::BITS_24,
            2,
            HONEST_CAPTURE,
            FAT_LINK_KBPS,
            Some(DGRAM),
        );
        assert_eq!(p, AudioPlane::opus());
    }

    /// …and the default really is ON, so an operator who has set nothing no longer has to discover
    /// an environment variable before a client's own explicit audio-format choice can be honoured.
    /// (`config()` reads the process environment once; no test in this crate sets the knob.)
    ///
    /// ⚠ This asserts the DEFAULT, not that any session goes lossless: condition 1 still gates
    /// every one of them on the client's `CLIENT_CAP_AUDIO_HIRES`, which ships off. The two
    /// neighbouring tests above are what prove an ordinary session is untouched by this flip.
    #[test]
    fn the_operator_default_is_on() {
        assert!(pf_host_config::config().audio_hires);
    }

    /// Surround, decided by the FRAME LADDER rather than by a stereo-only rule — the whole point
    /// of removing the `channels != 2` decline that used to sit above it.
    ///
    /// ⚠ This runs on [`HUGE_LINK_KBPS`] on purpose: on an ordinary link every declining row here
    /// would decline on BANDWIDTH first (96/24 5.1 is 13.8 Mbps and wants a 55 Mbps session), and
    /// the test would prove the affordability gate while claiming to prove the ladder. The link is
    /// taken out of the argument so the only thing that can move a row is the arithmetic.
    ///
    /// The matrix contradicts the design in both directions, which is why it is written out rather
    /// than summarised: §4.2's blanket "surround is out at the default MTU" is false for the whole
    /// 48 kHz-and-below half, and "above 48 kHz surround fits nothing" is false for 16-bit 5.1,
    /// which still fits a 1 ms frame at 88.2 and 96 kHz.
    #[test]
    fn surround_is_decided_by_the_frame_ladder() {
        // (channels, rate, bits, the rung it must land on — `None` = the honest decline)
        let matrix: [(u8, u32, u8, Option<u16>); 20] = [
            // 5.1 — and note 44.1 kHz fits a LONGER rung than 48 kHz, not a shorter one: a rung
            // is a sample count, and 44 100 Hz puts fewer samples in the same milliseconds.
            (6, 44_100, pcm::BITS_16, Some(2500)),
            (6, 44_100, pcm::BITS_24, Some(1500)),
            (6, 48_000, pcm::BITS_16, Some(2000)),
            (6, 48_000, pcm::BITS_24, Some(1500)), // ~667 packets/s
            (6, 88_200, pcm::BITS_16, Some(1000)),
            (6, 88_200, pcm::BITS_24, None),
            (6, 96_000, pcm::BITS_16, Some(1000)),
            (6, 96_000, pcm::BITS_24, None), // 1 728 B per ms — over before the shortest rung
            (6, 176_400, pcm::BITS_16, None),
            (6, 176_400, pcm::BITS_24, None),
            // 7.1 — four times a stereo frame, so it runs out of ladder four times sooner, and
            // nothing above 48 kHz fits at either depth.
            (8, 44_100, pcm::BITS_16, Some(1500)),
            (8, 44_100, pcm::BITS_24, Some(1000)),
            (8, 48_000, pcm::BITS_16, Some(1500)),
            (8, 48_000, pcm::BITS_24, Some(1000)),
            (8, 88_200, pcm::BITS_16, None),
            (8, 88_200, pcm::BITS_24, None),
            (8, 96_000, pcm::BITS_16, None),
            (8, 96_000, pcm::BITS_24, None),
            (8, 176_400, pcm::BITS_16, None),
            (8, 176_400, pcm::BITS_24, None),
        ];
        for (ch, rate, bits, want_us) in matrix {
            let p = resolve_audio_plane(
                true,
                true,
                rate,
                bits,
                ch,
                HONEST_CAPTURE,
                HUGE_LINK_KBPS,
                Some(DGRAM),
            );
            match want_us {
                Some(us) => {
                    assert!(
                        p.is_pcm(),
                        "{ch}ch {rate}/{bits} should have resolved to PCM"
                    );
                    assert_eq!(p.frame_us, us, "{ch}ch {rate}/{bits} rung");
                    assert_eq!(p.rate_hz, rate);
                    assert_eq!(p.bits, bits);
                    // Whatever the ladder chose, it has to FIT — a datagram over the path MTU is
                    // not sent at all, and this plane is never fragmented.
                    assert!(
                        pcm::frame_payload_bytes(rate, bits, ch, us as u32) + pcm::PCM_HEADER_LEN
                            <= DGRAM,
                        "{ch}ch {rate}/{bits} chose a {us} µs frame that does not fit"
                    );
                }
                None => assert_eq!(
                    p,
                    AudioPlane::opus(),
                    "{ch}ch {rate}/{bits} must decline via the ladder, not be carried"
                ),
            }
        }
    }

    /// …and on an ORDINARY link surround declines on bandwidth long before the ladder is reached,
    /// which is the outcome a real session sees. Stated separately so the two gates can never be
    /// confused for one another: 48/24 5.1 is 6 912 kbps and wants ≥ 27.6 Mbps of video.
    #[test]
    fn surround_still_needs_a_link_that_can_afford_it() {
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                48_000,
                pcm::BITS_24,
                6,
                HONEST_CAPTURE,
                20_000,
                Some(DGRAM)
            ),
            AudioPlane::opus(),
            "5.1 at 48/24 costs 6 912 kbps — more than a 20 Mbps session's 25 % allowance"
        );
        assert!(resolve_audio_plane(
            true,
            true,
            48_000,
            pcm::BITS_24,
            6,
            HONEST_CAPTURE,
            28_000,
            Some(DGRAM)
        )
        .is_pcm());
    }

    /// The 44.1 kHz family, which core has just made reachable — the deferral in §4.1 was
    /// `JitterPolicy` dividing by 1 000 before it multiplied, not anything about the plane. These
    /// used to land in `an_unsupported_format_gets_opus`; a host that still refuses them now
    /// disagrees with `pcm::rate_is_supported` and with every client that has already shipped the
    /// request.
    #[test]
    fn the_44_1_khz_family_resolves_to_the_lossless_plane() {
        for (rate, bits, want_us) in [
            (44_100u32, pcm::BITS_16, 5000u16),
            (44_100, pcm::BITS_24, 5000),
            (88_200, pcm::BITS_16, 3000),
            (88_200, pcm::BITS_24, 2500),
            (176_400, pcm::BITS_16, 1500),
            (176_400, pcm::BITS_24, 1000),
        ] {
            let p = resolve_audio_plane(
                true,
                true,
                rate,
                bits,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                Some(DGRAM),
            );
            assert!(p.is_pcm(), "{rate}/{bits} should have resolved to PCM");
            assert_eq!(p.rate_hz, rate, "the Welcome must state what was ASKED for");
            assert_eq!(p.bits, bits);
            assert_eq!(p.frame_us, want_us, "{rate}/{bits} rung");
            assert!(
                pcm::frame_payload_bytes(rate, bits, 2, p.frame_us as u32) + pcm::PCM_HEADER_LEN
                    <= DGRAM,
                "{rate}/{bits} chose a {} µs frame that does not fit",
                p.frame_us
            );
        }
        // ⚠ The gate must never round 44 100 to 48 000 to make it fit something. That would be the
        // exact "label right, content wrong" lie the feature is built to avoid — and it is now the
        // reachable mistake, where before the whole family was simply refused.
        let p = resolve_audio_plane(
            true,
            true,
            44_100,
            pcm::BITS_24,
            2,
            HONEST_CAPTURE,
            FAT_LINK_KBPS,
            Some(DGRAM),
        );
        assert_eq!(p.rate_hz, 44_100);
    }

    /// A format the plane cannot carry at all — and after the 44.1 kHz family was admitted, that
    /// set is only the rates outside BOTH families. 192 kHz is out by the §3 scope decision rather
    /// than by any arithmetic; 16 kHz is a narrow voice rate this plane never offers.
    #[test]
    fn an_unsupported_format_gets_opus() {
        for rate in [192_000u32, 16_000] {
            let p = resolve_audio_plane(
                true,
                true,
                rate,
                pcm::BITS_24,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                Some(DGRAM),
            );
            assert_eq!(p, AudioPlane::opus(), "{rate} Hz");
        }
        // The gate must read the set off core rather than restate it, so the two cannot drift.
        for rate in [44_100u32, 48_000, 88_200, 96_000, 176_400] {
            assert!(pcm::rate_is_supported(rate), "{rate} Hz");
        }
        for rate in [0u32, 22_050, 32_000, 192_000] {
            assert!(!pcm::rate_is_supported(rate), "{rate} Hz");
        }
        for bits in [8u8, 20, 32] {
            let p = resolve_audio_plane(
                true,
                true,
                48_000,
                bits,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                Some(DGRAM),
            );
            assert_eq!(p, AudioPlane::opus(), "{bits}-bit");
        }
    }

    /// §8.4 condition 4 — the capture path cannot deliver the rate, so the request is declined
    /// BEFORE the `Welcome` states one.
    ///
    /// This is the condition the design cares about most (§4.3, §13 item 2): every other gate
    /// failing produces a session that is merely not hi-res, whereas this one failing *silently*
    /// produces a session that says 96 kHz, spends 4.6 Mbps saying it, and carries interpolated
    /// 48 kHz. Both ends would audit clean.
    #[test]
    fn a_capture_path_that_cannot_deliver_the_rate_gets_opus() {
        use crate::audio::CaptureRate;
        // Windows, §8.2: the endpoint's engine runs at 48 kHz. `AUTOCONVERTPCM` would accept a
        // 96 kHz request and upsample — so 96 declines and 48 is honoured, which is exactly the
        // `requested > engine.rate` rule and not a blanket refusal.
        let engine_48 = CaptureRate::Engine(48_000);
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                96_000,
                pcm::BITS_24,
                2,
                engine_48,
                FAT_LINK_KBPS,
                Some(DGRAM)
            ),
            AudioPlane::opus(),
            "96 kHz on a 48 kHz engine must decline rather than pad"
        );
        assert!(
            resolve_audio_plane(
                true,
                true,
                48_000,
                pcm::BITS_24,
                2,
                engine_48,
                FAT_LINK_KBPS,
                Some(DGRAM)
            )
            .is_pcm(),
            "48 kHz on a 48 kHz engine is bit-exact and must be honoured"
        );
        // An engine ABOVE the request is fine: 96 → 48 is a real resample down to a rate that
        // genuinely carries every sample the client will be told about. §8.2 declines only when
        // the request is higher than the engine.
        assert!(resolve_audio_plane(
            true,
            true,
            48_000,
            pcm::BITS_16,
            2,
            CaptureRate::Engine(96_000),
            FAT_LINK_KBPS,
            Some(DGRAM)
        )
        .is_pcm());
        // A narrow endpoint (a headset's hands-free profile, Steam's voice-carrier sink) cannot
        // even do the base rate.
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                48_000,
                pcm::BITS_16,
                2,
                CaptureRate::Engine(24_000),
                FAT_LINK_KBPS,
                Some(DGRAM)
            ),
            AudioPlane::opus()
        );
        // Unknown — a Linux `PUNKTFUNK_STREAM_SINK=0` monitor capture whose elected sink could
        // not be read (§8.3), or a Windows probe that could not reach the endpoint. Declines
        // every rung: an unprovable claim is not a claim.
        for (rate, bits) in [
            (48_000u32, pcm::BITS_16),
            (48_000, pcm::BITS_24),
            (96_000, pcm::BITS_16),
            (96_000, pcm::BITS_24),
        ] {
            assert_eq!(
                resolve_audio_plane(
                    true,
                    true,
                    rate,
                    bits,
                    2,
                    CaptureRate::Unknown,
                    FAT_LINK_KBPS,
                    Some(DGRAM)
                ),
                AudioPlane::opus(),
                "{rate}/{bits} with an unknowable capture rate"
            );
        }
    }

    /// The probe's own arithmetic, pinned away from the gate so a future backend answering
    /// [`CaptureRate`](crate::audio::CaptureRate) has the contract stated rather than inferred.
    #[test]
    fn capture_rate_answers_only_what_it_can_prove() {
        use crate::audio::CaptureRate;
        // The host owns the sink and declares its format — honest by construction at any rate
        // the plane supports (§4.4).
        assert!(CaptureRate::Declared.can_deliver(48_000));
        assert!(CaptureRate::Declared.can_deliver(96_000));
        // At-or-below the engine only, and the boundary is inclusive: an engine at exactly the
        // requested rate is the *normal* passing case, not an edge to be conservative about.
        assert!(CaptureRate::Engine(96_000).can_deliver(96_000));
        assert!(CaptureRate::Engine(96_000).can_deliver(48_000));
        assert!(!CaptureRate::Engine(48_000).can_deliver(96_000));
        assert!(!CaptureRate::Engine(44_100).can_deliver(48_000));
        // Never yes without evidence.
        assert!(!CaptureRate::Unknown.can_deliver(48_000));
        assert!(!CaptureRate::Unknown.can_deliver(96_000));
    }

    /// §8.4 condition 5 — the link cannot afford it. The plane rides outside the ABR loop, so
    /// its cost is off the top and ABR can neither see nor reclaim it (§4.6).
    #[test]
    fn a_link_that_cannot_afford_it_gets_opus() {
        // 5 Mbps affords nothing on the ladder — the §4.6 case, stated as a test.
        for (rate, bits) in [
            (48_000u32, pcm::BITS_16),
            (48_000, pcm::BITS_24),
            (96_000, pcm::BITS_16),
            (96_000, pcm::BITS_24),
        ] {
            let p = resolve_audio_plane(
                true,
                true,
                rate,
                bits,
                2,
                HONEST_CAPTURE,
                5_000,
                Some(DGRAM),
            );
            assert_eq!(p, AudioPlane::opus(), "{rate}/{bits} on a 5 Mbps session");
        }
        // 10 Mbps affords 48 kHz at either depth and neither 96 kHz rung — and the boundary is
        // the one the constant's doc claims, not one a reader has to re-derive.
        assert!(resolve_audio_plane(
            true,
            true,
            48_000,
            pcm::BITS_24,
            2,
            HONEST_CAPTURE,
            10_000,
            Some(DGRAM)
        )
        .is_pcm());
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                96_000,
                pcm::BITS_16,
                2,
                HONEST_CAPTURE,
                10_000,
                Some(DGRAM)
            ),
            AudioPlane::opus()
        );
        // A session with no video bitrate at all can never afford it, and must not divide by it.
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                48_000,
                pcm::BITS_16,
                2,
                HONEST_CAPTURE,
                0,
                Some(DGRAM)
            ),
            AudioPlane::opus()
        );
    }

    /// The sixth, structural condition: a frame has to FIT. A peer with no datagram support has
    /// no audio plane to negotiate, and a datagram too small for even the shortest rung must
    /// fall back rather than emit a frame that would never be sent.
    #[test]
    fn a_datagram_that_cannot_carry_a_frame_gets_opus() {
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                48_000,
                pcm::BITS_16,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                None
            ),
            AudioPlane::opus()
        );
        // 96/24 at the shortest rung (1000 µs) is 96 × 2 × 3 = 576 B + 13 of header.
        assert_eq!(
            resolve_audio_plane(
                true,
                true,
                96_000,
                pcm::BITS_24,
                2,
                HONEST_CAPTURE,
                FAT_LINK_KBPS,
                Some(200)
            ),
            AudioPlane::opus()
        );
    }

    /// The Opus fallback must be byte-for-byte today's answer, or an Opus session's `Welcome`
    /// stops being byte-identical to the pre-hi-res wire form and every existing client sees a
    /// message it has to have been taught to parse.
    #[test]
    fn the_opus_fallback_is_the_legacy_wire_form() {
        let p = AudioPlane::opus();
        assert_eq!(p.codec, punktfunk_core::quic::AUDIO_CODEC_OPUS);
        assert_eq!(p.rate_hz, punktfunk_core::audio::SAMPLE_RATE_HZ);
        assert_eq!(p.bits, pcm::BITS_16);
        assert_eq!(p.frame_us, 0);
        assert!(!p.is_pcm());
    }
}
