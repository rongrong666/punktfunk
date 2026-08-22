//! Connect + handshake: dial the host (cert-pinned), exchange Hello/Welcome/Start on the
//! control stream, run the wall-clock skew handshake, hole-punch the data port, and stand
//! up the data-plane [`Session`]. A typed application close from the host surfaces as
//! [`PunktfunkError::Rejected`] instead of the generic transport error.

use super::*;

/// Everything [`run_pump`](super::run_pump) needs from a successful connect + handshake.
pub(super) struct HandshakeOut {
    pub(super) conn: quinn::Connection,
    /// The dialing endpoint, kept alive for the session so the pump can FLUSH its
    /// `CONNECTION_CLOSE` before the runtime is dropped ([`super::run_pump`]). Dropping it here
    /// left nothing to drive the close onto the wire, so a deliberate quit reached the host as
    /// silence — an 8 s idle timeout with no quit code, which the host reads as an unwanted
    /// disconnect and lingers the display for.
    pub(super) ep: quinn::Endpoint,
    pub(super) session: Session,
    pub(super) ctrl_send: quinn::SendStream,
    pub(super) ctrl_recv: io::MsgReader,
    pub(super) negotiated: Negotiated,
    pub(super) host_caps: u8,
}

pub(super) async fn connect_and_handshake(args: &WorkerArgs) -> Result<HandshakeOut> {
    let (host, port, pin) = (&args.host, args.port, args.pin);
    let (mode, compositor, gamepad) = (args.mode, args.compositor, args.gamepad);
    let (bitrate_kbps, video_caps, audio_channels) =
        (args.bitrate_kbps, args.video_caps, args.audio_channels);
    let (video_codecs, preferred_codec, display_hdr) =
        (args.video_codecs, args.preferred_codec, args.display_hdr);
    let (launch, identity, shutdown) = (&args.launch, &args.identity, &args.shutdown);
    let remote: std::net::SocketAddr = join_host_port(host, port)
        .parse()
        .map_err(|_| PunktfunkError::InvalidArg("host:port"))?;
    let (ep, observed) = endpoint::client_pinned_with_identity(
        pin,
        identity.as_ref().map(|(c, k)| (c.as_str(), k.as_str())),
    );
    let ep = ep.map_err(|e| PunktfunkError::Io(std::io::Error::other(e.to_string())))?;
    // Dial with retry across the connect budget, not a single attempt: one quinn dial gives
    // up after the transport's idle window (~8 s of silence), which is shorter than a
    // suspend-to-RAM resume — the Steam Deck flow fires Wake-on-LAN and connects
    // immediately, so the host is still waking while the first Initials go out, and a
    // single-shot dial died just before the host came up. Short attempts keep the Initial
    // cadence dense (quinn's per-attempt retransmits back off toward multi-second gaps), so
    // the connect lands within ~a second of the host's network returning. Only SILENCE is
    // retried: a host that answers and rejects us (pin mismatch, ALPN/version, typed close)
    // must surface immediately, and the embedder's shutdown flag (budget expiry in
    // `connect`, or a user cancel) stops the loop between attempts.
    const DIAL_ATTEMPT: std::time::Duration = std::time::Duration::from_secs(3);
    // Redial headroom: leave room for the control handshake (Hello/Welcome/clock sync)
    // after a late dial success, so it still completes inside the embedder's budget.
    const CONTROL_HEADROOM: std::time::Duration = std::time::Duration::from_secs(2);
    let start = tokio::time::Instant::now();
    let deadline = start + args.connect_timeout;
    let redial_until = start + args.connect_timeout.saturating_sub(CONTROL_HEADROOM);
    let conn = loop {
        let connecting = ep
            .connect(remote, "punktfunk")
            .map_err(|_| PunktfunkError::InvalidArg("connect"))?;
        // Cap the attempt to the remaining budget so a success never lands after the
        // embedder's `ready_rx` wait has already given up and flagged a teardown.
        let now = tokio::time::Instant::now();
        let attempt = DIAL_ATTEMPT.min(deadline.saturating_duration_since(now));
        let gave_up = || {
            tokio::time::Instant::now() >= redial_until
                || shutdown.load(std::sync::atomic::Ordering::SeqCst)
        };
        match tokio::time::timeout(attempt, connecting).await {
            Ok(Ok(conn)) => break conn,
            Ok(Err(e)) => {
                // A pin mismatch surfaces as a TLS failure; report it as a crypto error so
                // the embedder can distinguish "wrong host identity" from plain IO trouble.
                let fp_mismatch = pin.is_some()
                    && observed.lock().unwrap().map(|fp| Some(fp) != pin) == Some(true);
                if fp_mismatch {
                    return Err(PunktfunkError::Crypto);
                }
                // The transport's own idle expiry — the host never answered — is the one
                // retryable outcome; everything else is a real answer or a local failure.
                let host_silent = matches!(e, quinn::ConnectionError::TimedOut);
                if !host_silent {
                    return Err(PunktfunkError::Io(std::io::Error::other(e.to_string())));
                }
                if gave_up() {
                    return Err(PunktfunkError::Timeout);
                }
            }
            // Attempt window elapsed with the host still silent; dropping `connecting`
            // abandoned that dial — go again unless the budget is spent.
            Err(_) => {
                if gave_up() {
                    return Err(PunktfunkError::Timeout);
                }
            }
        }
        tracing::debug!(%remote, "host silent — re-dialing (wake/resume tolerant connect)");
    };
    let fingerprint = observed.lock().unwrap().unwrap_or([0u8; 32]);
    // The rest of the handshake runs in an inner future so a failure can consult
    // `conn.close_reason()`: a host that turned us away with a typed application close
    // (pairing not armed / denied / approval timeout / version mismatch / busy) surfaces
    // as `PunktfunkError::Rejected` instead of the generic transport error the failed
    // read produces — the difference between "not accepted" and the actual cause.
    let handshake = async {
        let (mut send, recv) = conn
            .open_bi()
            .await
            .map_err(|e| PunktfunkError::Io(std::io::Error::other(e.to_string())))?;
        // Frame every read on this stream through the resumable reader: the control loop
        // below drives it from a `select!` arm and `clock_sync` wraps it in a timeout, and a
        // partial frame lost to either would misalign the stream for the whole session.
        let mut recv = io::MsgReader::new(recv);

        io::write_msg(
            &mut send,
            &Hello {
                abi_version: crate::WIRE_VERSION,
                mode,
                compositor,
                gamepad,
                bitrate_kbps,
                // The embedder's device name — what the host's pending-approval list and paired-
                // devices store show for this client. `None` makes the host fall back to a
                // fingerprint-derived "device abcd1234" label.
                name: args.name.clone(),
                // Library id to launch this session, if the embedder asked for one.
                launch: launch.clone(),
                // The embedder's decode/present caps (e.g. the Windows client advertises
                // VIDEO_CAP_10BIT | VIDEO_CAP_HDR). The host only upgrades to a 10-bit / HDR encode
                // when the matching bit is set, so `0` stays an 8-bit BT.709 stream. HOST_TIMING is
                // OR'd in unconditionally: every NativeClient build demuxes the 0xCF plane, and the
                // bit only asks the host for observability datagrams (never changes the encode).
                // PROBE_SEQ likewise: the shared reassembler keeps probe filler in its own window
                // (every embedder inherits it), so the host may burst speed tests without consuming
                // video frame indexes. STREAMED_AU the same way: the shared reassembler accepts
                // sentinel-headed streamed blocks (retro-validated at the final block), so the host
                // may overlap a multi-slice encode's tail with packetize/FEC/pacing.
                // VIDEO_CAP_MULTI_SLICE must NOT join this unconditional set: it is DECODER
                // truth (Amlogic MediaCodec wedges on multi-slice AUs — the 0.17.0 Chromecast
                // regression), so only the embedder can set it, per its decode stack.
                video_caps: video_caps
                    | crate::quic::VIDEO_CAP_HOST_TIMING
                    | crate::quic::VIDEO_CAP_PROBE_SEQ
                    | crate::quic::VIDEO_CAP_STREAMED_AU,
                // Requested surround channel count; the host echoes the resolved value in Welcome.
                audio_channels,
                // The codecs this client can decode + its soft preference (0 = auto). The host
                // resolves the emitted codec from these and reports it in `Welcome::codec`.
                video_codecs,
                preferred_codec,
                // The client display's HDR volume → the host's virtual-display EDID (host apps
                // tone-map to the client's real panel). `None` = unknown/SDR.
                display_hdr,
                // NOT unconditional like HOST_TIMING above: CLIENT_CAP_CURSOR makes the host
                // stop compositing the pointer, so only an embedder that actually renders the
                // cursor locally may set it (the embedder decides, we pass through).
                client_caps: args.client_caps,
                // Unconditional like STREAMED_AU: the shared reassembler pins geometry
                // per-frame and every receive buffer is sized from MAX_DATAGRAM_BYTES, so
                // every embedder accepts a mid-session shard change up to this ceiling
                // (design/shard-payload-reneg.md W0.3 — the host only renegotiates, and only
                // grows to jumbo, when this advertises it).
                max_shard_payload: crate::config::max_shard_payload() as u16,
                // The audio format this client is ASKING for. At the legacy 48 kHz / 16-bit pair
                // (what every `connect` caller gets) the encoder omits both fields and the Hello
                // stays byte-identical to the pre-hi-res wire form. Anything else came from
                // `connect_with_audio_format`, which is also what set CLIENT_CAP_AUDIO_HIRES in
                // `client_caps` — capable AND turned on, the VIDEO_CAP_444 precedent. The two
                // travel together on purpose: the bit is the opt-in and these are only its
                // parameters, so neither is meaningful without the other.
                audio_rate_hz: args.audio_rate_hz,
                audio_bits: args.audio_bits,
            }
            .encode(),
        )
        .await?;
        let welcome = Welcome::decode(&recv.read_msg().await?)?;
        if welcome.compositor != CompositorPref::Auto {
            tracing::info!(
                compositor = welcome.compositor.as_str(),
                "host resolved compositor"
            );
        }
        if welcome.gamepad != GamepadPref::Auto {
            tracing::info!(
                gamepad = welcome.gamepad.as_str(),
                "host resolved gamepad backend"
            );
        }

        // Reserve our data-plane port, then start the host.
        let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let udp_port = probe.local_addr()?.port();
        drop(probe);
        io::write_msg(
            &mut send,
            &Start {
                client_udp_port: udp_port,
            }
            .encode(),
        )
        .await?;

        // Wall-clock skew handshake on the control stream (before the session's control task takes
        // it): align our clock to the host's so the embedder can express receive/present instants in
        // the host's capture clock (the AU `pts_ns`). 0 ⇒ an old host that didn't answer (shared-clock
        // assumption, as before). This is the substrate for glass-to-glass present-time measurement.
        let (clock_offset_ns, clock_rtt_ns) =
            match crate::quic::clock_sync(&mut send, &mut recv).await {
                Some(skew) => {
                    tracing::info!(
                        offset_ns = skew.offset_ns,
                        rtt_us = skew.rtt_ns / 1000,
                        rounds = skew.rounds,
                        "clock skew estimated (host-client)"
                    );
                    (skew.offset_ns, Some(skew.rtt_ns))
                }
                None => (0, None),
            };

        // WG relay mode (the session process published its relay's data listener in
        // WG_RELAY_DATA_PORT and dialed the loopback relay): the data plane must target
        // THIS session's relay listener, not `welcome.udp_port` — that is the host-side
        // service port the gate dispatches on, identical for every session, so a second
        // WG session's video would land in the FIRST session's relay (zero frames on 2,
        // stray traffic killing 1). The loopback guard keeps a stale value from
        // redirecting a real direct connection.
        let wg_data = crate::client::WG_RELAY_DATA_PORT.load(std::sync::atomic::Ordering::SeqCst);
        let data_port = if remote.ip().is_loopback() && wg_data != 0 {
            wg_data
        } else {
            welcome.udp_port
        };
        let host_udp = std::net::SocketAddr::new(remote.ip(), data_port);
        let transport =
            UdpTransport::connect(&format!("0.0.0.0:{udp_port}"), &host_udp.to_string())?;
        // Hole-punch the host's data port so video traverses a NAT / stateful inter-VLAN firewall
        // (control + side planes ride the client-initiated QUIC; the raw video UDP needs the client
        // to open the path first). Stops with the session via the shared shutdown flag.
        if let Ok(sock) = transport.try_clone_socket() {
            crate::transport::spawn_data_punch(sock, shutdown.clone());
        }
        let mut session = Session::new(welcome.session_config(Role::Client), Box::new(transport))?;
        // PyroWave sessions opt into partial delivery (plan §4.4): an aged-out lossy
        // frame arrives as blocks-with-holes instead of vanishing — the all-intra codec
        // renders it as one frame of localized blur, strictly better than a freeze.
        if welcome.codec == crate::quic::CODEC_PYROWAVE {
            session.set_deliver_partial_frames(true);
        }
        // Slice-progressive delivery (the embedder's opt-in): AU prefixes hand up as
        // `Frame::part` pieces while the tail is still on the wire. Never on PyroWave — its
        // all-intra frame channel drains newest-wins per QUEUE ENTRY, so parts of one AU read as
        // separate AUs and the drain shreds the AU it is mid-way through (`FrameChannel::pop`
        // spells out the mechanism and what a fix would take). Unrelated to the host's streamed-AU
        // wire (`VIDEO_CAP_STREAMED_AU`), which still completes one whole `Frame` per AU.
        if args.frame_parts && welcome.codec != crate::quic::CODEC_PYROWAVE {
            session.set_deliver_frame_parts(true);
        }
        Ok::<_, PunktfunkError>((
            session,
            send,
            recv,
            Negotiated {
                mode: welcome.mode,
                compositor: welcome.compositor,
                gamepad: welcome.gamepad,
                host_fingerprint: fingerprint,
                bitrate_kbps: welcome.bitrate_kbps,
                clock_offset_ns,
                clock_rtt_ns,
                bit_depth: welcome.bit_depth,
                color: welcome.color,
                chroma_format: welcome.chroma_format,
                audio_channels: welcome.audio_channels,
                // The RESOLVED audio format, taken straight off the Welcome and never reconciled
                // with what we asked for: the host may legitimately answer lower (or plain Opus)
                // and its answer is the only authority — the rule at both ends is "never claim a
                // rate you did not get" (`design/hi-res-audio.md` §4.3/§9). A default Opus
                // session decodes these as `AUDIO_CODEC_OPUS` / 48 000 / 16 / 0, which is exactly
                // what an older host that omits the whole tail also yields, so the legacy path
                // reaches the embedder unchanged.
                audio_codec: welcome.audio_codec,
                audio_rate_hz: welcome.audio_rate_hz,
                audio_bits: welcome.audio_bits,
                audio_frame_us: welcome.audio_frame_us,
                codec: welcome.codec,
                shard_payload: welcome.shard_payload,
                host_caps: welcome.host_caps,
                mgmt_port: welcome.mgmt_port,
                grants: welcome.grants,
                expires_in_secs: welcome.expires_in_secs,
            },
            welcome.host_caps,
        ))
    };
    match handshake.await {
        Ok((session, send, recv, negotiated, host_caps)) => Ok(HandshakeOut {
            conn,
            ep,
            session,
            ctrl_send: send,
            ctrl_recv: recv,
            negotiated,
            host_caps,
        }),
        Err(e) => {
            // The host's typed close can land a beat AFTER the stream error it caused: the
            // stream reset/FIN and the CONNECTION_CLOSE are in flight together, and quinn can
            // hand the reader its mid-frame EOF before it processes the close. Give the close a
            // short grace to arrive so a host-side setup failure renders as its real reason
            // ("the host could not start the stream session") instead of "control stream
            // finished mid-frame". No-op when the connection already closed (or never will —
            // bounded by the timeout).
            if conn.close_reason().is_none() {
                let _ = tokio::time::timeout(std::time::Duration::from_millis(300), conn.closed())
                    .await;
            }
            Err(match reject_from_close(&conn) {
                Some(r) => PunktfunkError::Rejected(r),
                None => e,
            })
        }
    }
}
