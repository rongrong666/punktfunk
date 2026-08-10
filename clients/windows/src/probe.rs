//! Network speed-test probe — the GUI's per-host "Test Network Speed…" ([`crate::app`]'s
//! speed page) and the `--headless --speed-test` CLI.
//!
//! Split out of the former in-process session module: the shared spawned-`punktfunk-session`
//! binary owns real streaming now, but the speed test is a shell-side, decode-less measurement
//! over the real data plane, so it stays here. [`decodable_codecs`] rode along for the same
//! reason — the probe connect still advertises which codecs this client can decode.

use punktfunk_core::client::NativeClient;
use punktfunk_core::config::{CompositorPref, GamepadPref, Mode};
use std::time::{Duration, Instant};

/// The `quic` codec bitfield this client can decode. Advertised to the host so it never emits
/// a codec we can't decode.
///
/// It is pf-client-core's [`decodable_codecs`](pf_client_core::video::decodable_codecs) —
/// the codecs the SESSION BINARY's rungs speak, which is the process that actually decodes.
/// This shell used to walk libavcodec's registry (`ffmpeg::decoder::find` per id) for the
/// same answer; that was wrong in two ways even before M10 deleted the dependency. It
/// described the decoders in THIS process, which decodes nothing, and it answered "a
/// decoder exists" where the question is "a rung can keep up" — the AV1-on-CPU promise
/// `decodable_codecs_for` exists to refuse.
///
/// ⚠ Deliberately the DEVICE-FREE answer ([`decodable_codecs`], not
/// `decodable_codecs_for`): this connect creates no presenter and has no `VulkanDecodeDevice`
/// to gate AV1 on, and it decodes nothing — the codec it advertises is never exercised. A
/// real session's Hello is built in the session binary, with the device in hand.
pub fn decodable_codecs() -> u8 {
    pf_client_core::video::decodable_codecs()
}

/// Blocking speed-test probe (the GUI's per-host "Test" and the `--headless --speed-test` CLI):
/// a minimal identified connect (720p60 — the host builds a virtual output, but nothing is
/// decoded), then `request_probe` (a 2 s burst up to the host's 3 Gbps ceiling) polled to
/// completion. Run on a worker thread.
pub fn run_speed_probe(
    addr: &str,
    port: u16,
    fp_hex: Option<&str>,
    identity: (String, String),
) -> Result<punktfunk_core::client::ProbeOutcome, String> {
    // Pin the saved/advertised fingerprint when we have one; a manual host measures over TOFU.
    let pin = fp_hex.and_then(crate::trust::parse_hex32);
    let c = NativeClient::connect(
        addr,
        port,
        Mode {
            width: 1280,
            height: 720,
            refresh_hz: 60,
        },
        CompositorPref::Auto,
        GamepadPref::Auto,
        0, // bitrate_kbps: host default
        0, // video_caps: probe connect, nothing is decoded
        2, // audio_channels: stereo baseline
        decodable_codecs(),
        0,     // preferred_codec: no preference
        None,  // display_hdr: probe connect, nothing presents
        0,     // client_caps: probe connect, nothing renders a cursor
        false, // frame_parts: probe/whole-AU consumer
        None,  // launch: no game
        // Same label a real session sends — a speed test against a host that doesn't know us yet
        // should knock under this device's name, not a fingerprint placeholder.
        Some(punktfunk_core::client::device_name()),
        pin,
        Some(identity),
        Duration::from_secs(15),
    )
    .map_err(|e| format!("连接失败：{e:?}"))?;
    c.request_probe(3_000_000, 2_000)
        .map_err(|e| format!("探测失败：{e:?}"))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        std::thread::sleep(Duration::from_millis(250));
        if c.probe_result().done {
            // Let the last UDP shards land before tearing down.
            std::thread::sleep(Duration::from_millis(400));
            return Ok(c.probe_result());
        }
        if Instant::now() > deadline {
            return Err("探测超时".to_string());
        }
    }
}
