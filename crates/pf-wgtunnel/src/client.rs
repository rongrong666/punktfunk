//! Client-side WireGuard relay.
//!
//! Listens on loopback for the punktfunk client's QUIC socket (default
//! 127.0.0.1:9777) and data socket (default 127.0.0.1:9778), wraps every
//! datagram in a synthetic IPv4/UDP packet, encrypts it and ships it to the
//! server's single public UDP port. Replies are sent back to the originating
//! local socket *from* the matching loopback listener, so the punktfunk
//! client sees exactly the address it dialed.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

use crate::ippkt;
use crate::server::HOST_IP;
use crate::{encapsulate_and_send, MAX_DATAGRAM};

/// Fixed inner tunnel address of the client side.
pub const CLIENT_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 2);

const KIND_QUIC: u8 = 0;
const KIND_DATA: u8 = 1;

pub struct ClientConfig {
    /// Public server address (host gate).
    pub server: SocketAddr,
    /// This client's static private key.
    pub private_key: X25519SecretKey,
    /// Server's static public key.
    pub server_public: X25519PublicKey,
    /// Loopback listener for the QUIC control plane.
    pub listen_quic: SocketAddr,
    /// Loopback listener for the video data plane.
    pub listen_data: SocketAddr,
}

struct Shared {
    tunn: Tunn,
    wg: UdpSocket,
    /// (kind, local client source port) -> local client address.
    flows: Mutex<HashMap<(u8, u16), SocketAddr>>,
    quic_sock: UdpSocket,
    data_sock: UdpSocket,
    quic_port: u16,
    data_port: u16,
}

fn send_wg(shared: &Shared, pkt: &[u8]) -> io::Result<()> {
    shared.wg.send(pkt).map(|_| ())
}

/// WireGuard socket reader: decrypt and hand inner packets back to the
/// originating local client socket.
fn wg_reader(shared: Arc<Shared>) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let n = match shared.wg.recv(&mut buf) {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[wgtunnel-client] wg recv: {e}");
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let datagram = buf[..n].to_vec();
        let mut data: &[u8] = &datagram;
        loop {
            let mut dst = vec![0u8; MAX_DATAGRAM];
            match shared.tunn.decapsulate(None, data, &mut dst) {
                TunnResult::WriteToNetwork(pkt) => {
                    let v = pkt.to_vec();
                    let _ = send_wg(&shared, &v);
                }
                TunnResult::WriteToTunnelV4(pkt, _) => {
                    let v = pkt.to_vec();
                    deliver_inner(&shared, &v);
                }
                _ => break,
            }
            data = &[];
        }
    }
}

fn deliver_inner(shared: &Shared, inner_bytes: &[u8]) {
    let Some(inner) = ippkt::parse_udp(inner_bytes) else {
        return;
    };
    let (kind, sock) = if inner.src_port == shared.quic_port {
        (KIND_QUIC, &shared.quic_sock)
    } else if inner.src_port == shared.data_port {
        (KIND_DATA, &shared.data_sock)
    } else {
        return;
    };
    let addr = shared
        .flows
        .lock()
        .unwrap()
        .get(&(kind, inner.dst_port))
        .copied();
    if let Some(addr) = addr {
        let _ = sock.send_to(&inner.payload, addr);
    }
}

/// Loopback listener for one punktfunk client socket (QUIC or data).
fn local_reader(shared: Arc<Shared>, kind: u8, svc_port: u16) {
    let sock = if kind == KIND_QUIC {
        &shared.quic_sock
    } else {
        &shared.data_sock
    };
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[wgtunnel-client] local recv (kind {kind}): {e}");
                thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        shared.flows.lock().unwrap().insert((kind, src.port()), src);
        let inner = ippkt::build_udp(CLIENT_IP, src.port(), HOST_IP, svc_port, &buf[..n]);
        let _ = encapsulate_and_send(&shared.tunn, &inner, &|pkt| send_wg(&shared, pkt));
    }
}

/// Run the relay forever. Blocks the calling thread.
pub fn run_client(cfg: ClientConfig) -> io::Result<()> {
    let wg = crate::udp_bind((Ipv4Addr::UNSPECIFIED, 0).into())?;
    wg.connect(cfg.server)?;
    let quic_sock = crate::udp_bind(cfg.listen_quic)?;
    let data_sock = crate::udp_bind(cfg.listen_data)?;
    eprintln!(
        "[wgtunnel-client] {} <- quic {} data {} (server {})",
        cfg.server,
        cfg.listen_quic,
        cfg.listen_data,
        cfg.server
    );

    let tunn = Tunn::new(
        Arc::new(cfg.private_key),
        Arc::new(cfg.server_public),
        None,
        Some(25), // persistent keepalive keeps NAT mappings open
        0,
        None,
    )
    .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;

    let shared = Arc::new(Shared {
        tunn: *tunn,
        wg,
        flows: Mutex::new(HashMap::new()),
        quic_port: cfg.listen_quic.port(),
        data_port: cfg.listen_data.port(),
        quic_sock,
        data_sock,
    });

    // Kick off the handshake immediately so the first datagrams have a
    // session waiting for them (encapsulate would start one anyway).
    {
        let mut dst = [0u8; 2048];
        if let TunnResult::WriteToNetwork(pkt) =
            shared.tunn.format_handshake_initiation(&mut dst, false)
        {
            let v = pkt.to_vec();
            let _ = send_wg(&shared, &v);
        }
    }

    let s1 = Arc::clone(&shared);
    thread::spawn(move || wg_reader(s1));
    let s2 = Arc::clone(&shared);
    let qp = shared.quic_port;
    thread::spawn(move || local_reader(s2, KIND_QUIC, qp));
    let s3 = Arc::clone(&shared);
    let dp = shared.data_port;
    thread::spawn(move || local_reader(s3, KIND_DATA, dp));

    // Timer thread: handshake retransmits, keepalives, session rotation.
    loop {
        thread::sleep(Duration::from_millis(250));
        let mut dst = [0u8; 2048];
        if let TunnResult::WriteToNetwork(pkt) = shared.tunn.update_timers(&mut dst) {
            let v = pkt.to_vec();
            let _ = send_wg(&shared, &v);
        }
    }
}
