//! pf-wgtunnel — a userspace WireGuard shell around punktfunk/1.
//!
//! One public UDP port carries WireGuard; the QUIC control plane and the raw
//! UDP video data plane ride *inside* the tunnel as synthetic IPv4/UDP
//! packets (no tun device, no admin rights needed on either side).
//!
//! - [`server`] is the host-side gate: it holds the only public socket,
//!   decrypts inner packets and relays them to punktfunk-host services bound
//!   on loopback (QUIC 9777 / data 9778 by default).
//! - [`client`] is the client-side relay: it listens on loopback for the
//!   punktfunk client's QUIC + data sockets and forwards them over the tunnel.
//!
//! Inner addressing is fixed and private to the tunnel: host `10.8.0.1`,
//! client `10.8.0.2`. Only UDP is carried; UDP checksum is zero (legal on
//! IPv4) and the IPv4 header checksum is computed.

use std::io;
use std::net::{SocketAddr, UdpSocket};

use boringtun::noise::{Tunn, TunnResult};

pub mod client;
pub mod ippkt;
pub mod keys;
pub mod server;

/// Maximum datagram we ever move in either direction.
pub(crate) const MAX_DATAGRAM: usize = 1 << 16;

/// Bind a UDP socket with 8 MiB recv/send buffers. The tunnel carries full-rate video bursts and
/// the OS default buffer (64 KiB on Windows) drops half the stream on the floor even on loopback.
/// Buffer sizing is best-effort (an OS cap is not fatal); the bind itself is.
pub(crate) fn udp_bind(addr: SocketAddr) -> io::Result<UdpSocket> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let sock = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    let _ = sock.set_recv_buffer_size(8 << 20);
    let _ = sock.set_send_buffer_size(8 << 20);
    sock.bind(&addr.into())?;
    Ok(sock.into())
}

/// Encapsulate one inner packet and write every resulting WireGuard datagram
/// through `send`. Also drains anything boringtun queued behind the packet.
pub(crate) fn encapsulate_and_send(
    tunn: &Tunn,
    inner: &[u8],
    send: &dyn Fn(&[u8]) -> io::Result<()>,
) -> io::Result<()> {
    let mut dst = vec![0u8; (inner.len() + 64).max(2048)];
    if let TunnResult::WriteToNetwork(pkt) = tunn.encapsulate(inner, &mut dst) {
        send(pkt)?;
    }
    loop {
        let mut dst = vec![0u8; MAX_DATAGRAM];
        match tunn.decapsulate(None, &[], &mut dst) {
            TunnResult::WriteToNetwork(pkt) => send(pkt)?,
            _ => break,
        }
    }
    Ok(())
}
