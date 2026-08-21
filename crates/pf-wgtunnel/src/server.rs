//! Host-side WireGuard gate.
//!
//! Holds the single public UDP socket. For each decrypted inner UDP packet it
//! picks the loopback service by inner destination port (QUIC / data) and
//! forwards through a per-flow loopback socket, so the punktfunk-host
//! services only ever see 127.0.0.1 peers. Replies take the reverse path and
//! are re-encrypted to the current peer endpoint.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use boringtun::crypto::{X25519PublicKey, X25519SecretKey};
use boringtun::noise::{Tunn, TunnResult};

use crate::ippkt::{self, InnerUdp};
use crate::{encapsulate_and_send, MAX_DATAGRAM};

/// Fixed inner tunnel address of the host side.
pub const HOST_IP: Ipv4Addr = Ipv4Addr::new(10, 8, 0, 1);

const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

pub struct ServerConfig {
    /// Public UDP socket to listen on (the only exposed port).
    pub listen: SocketAddr,
    /// Host static private key.
    pub private_key: X25519SecretKey,
    /// Allowed client public keys.
    pub peers: Vec<X25519PublicKey>,
    /// Loopback address of the QUIC control plane.
    pub quic_target: SocketAddr,
    /// Loopback address of the video data plane.
    pub data_target: SocketAddr,
}

/// (client inner ip, client inner port, service port) — one flow per tuple.
type FlowKey = (Ipv4Addr, u16, u16);

struct Flow {
    sock: UdpSocket, // loopback socket, connect()ed to the real service
}

struct Peer {
    tunn: Box<Tunn>,
    endpoint: Mutex<Option<SocketAddr>>,
    flows: Mutex<HashMap<FlowKey, Arc<Flow>>>,
}

fn flow_reader(
    peer: Arc<Peer>,
    public_sock: Arc<UdpSocket>,
    flow: Arc<Flow>,
    key: FlowKey,
) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match flow.sock.recv(&mut buf) {
            Ok(n) => {
                let inner = ippkt::build_udp(HOST_IP, key.2, key.0, key.1, &buf[..n]);
                let endpoint = *peer.endpoint.lock().unwrap();
                if let Some(ep) = endpoint {
                    let _ = encapsulate_and_send(&peer.tunn, &inner, &|pkt| {
                        public_sock.send_to(pkt, ep).map(|_| ())
                    });
                }
            }
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    || e.kind() == io::ErrorKind::TimedOut =>
            {
                // Idle: drop the flow so a later packet re-creates it.
                peer.flows.lock().unwrap().remove(&key);
                return;
            }
            Err(_) => {
                peer.flows.lock().unwrap().remove(&key);
                return;
            }
        }
    }
}

fn handle_inner(
    peer: &Arc<Peer>,
    public_sock: &Arc<UdpSocket>,
    inner_bytes: &[u8],
    quic_target: SocketAddr,
    data_target: SocketAddr,
) {
    let Some(inner) = ippkt::parse_udp(inner_bytes) else {
        return;
    };
    let InnerUdp {
        src_ip,
        src_port,
        dst_port,
        payload,
        ..
    } = inner;
    let target = if dst_port == quic_target.port() {
        quic_target
    } else if dst_port == data_target.port() {
        data_target
    } else {
        return;
    };
    let key: FlowKey = (src_ip, src_port, dst_port);
    let flow = {
        let mut flows = peer.flows.lock().unwrap();
        match flows.get(&key) {
            Some(f) => Arc::clone(f),
            None => {
                let Ok(sock) = crate::udp_bind((Ipv4Addr::LOCALHOST, 0).into()) else {
                    return;
                };
                if sock.connect(target).is_err() {
                    return;
                }
                let _ = sock.set_read_timeout(Some(FLOW_IDLE_TIMEOUT));
                let flow = Arc::new(Flow { sock });
                flows.insert(key, Arc::clone(&flow));
                let peer2 = Arc::clone(peer);
                let pub2 = Arc::clone(public_sock);
                let flow2 = Arc::clone(&flow);
                thread::spawn(move || flow_reader(peer2, pub2, flow2, key));
                flow
            }
        }
    };
    let _ = flow.sock.send(&payload);
}

fn process_datagram(
    peer: &Arc<Peer>,
    public_sock: &Arc<UdpSocket>,
    src: SocketAddr,
    datagram: &[u8],
    quic_target: SocketAddr,
    data_target: SocketAddr,
) {
    let mut data: &[u8] = datagram;
    let mut src_ip: Option<IpAddr> = Some(src.ip());
    loop {
        let mut dst = vec![0u8; MAX_DATAGRAM];
        match peer.tunn.decapsulate(src_ip, data, &mut dst) {
            TunnResult::WriteToNetwork(pkt) => {
                let v = pkt.to_vec();
                let _ = public_sock.send_to(&v, src);
            }
            TunnResult::WriteToTunnelV4(pkt, _) => {
                let v = pkt.to_vec();
                handle_inner(peer, public_sock, &v, quic_target, data_target);
            }
            _ => break,
        }
        data = &[];
        src_ip = None;
    }
}

/// Run the gate forever. Blocks the calling thread.
pub fn run_server(cfg: ServerConfig) -> io::Result<()> {
    let sock = Arc::new(crate::udp_bind(cfg.listen)?);
    eprintln!(
        "[wgtunnel-server] public {} -> quic {} data {} ({} peer(s))",
        cfg.listen,
        cfg.quic_target,
        cfg.data_target,
        cfg.peers.len()
    );

    let secret = Arc::new(cfg.private_key);
    let mut peers = Vec::with_capacity(cfg.peers.len());
    for (i, p) in cfg.peers.iter().enumerate() {
        let tunn = Tunn::new(
            Arc::clone(&secret),
            Arc::new(X25519PublicKey::from(p.as_bytes())),
            None,       // no preshared key
            Some(25),   // persistent keepalive handled client-side too
            (i + 1) as u32,
            None,       // default rate limiter
        )
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        peers.push(Arc::new(Peer {
            tunn,
            endpoint: Mutex::new(None),
            flows: Mutex::new(HashMap::new()),
        }));
    }
    let peers = Arc::new(peers);

    // Timer thread: keepalives, handshake retransmits, session expiry.
    {
        let peers = Arc::clone(&peers);
        let sock = Arc::clone(&sock);
        thread::spawn(move || loop {
            thread::sleep(Duration::from_millis(250));
            for peer in peers.iter() {
                let endpoint = *peer.endpoint.lock().unwrap();
                if let Some(ep) = endpoint {
                    let mut dst = [0u8; 2048];
                    if let TunnResult::WriteToNetwork(pkt) = peer.tunn.update_timers(&mut dst) {
                        let v = pkt.to_vec();
                        let _ = sock.send_to(&v, ep);
                    }
                }
            }
        });
    }

    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[wgtunnel-server] recv: {e}");
                continue;
            }
        };
        let datagram = buf[..n].to_vec();

        let known = peers
            .iter()
            .find(|p| *p.endpoint.lock().unwrap() == Some(src))
            .map(Arc::clone);

        match known {
            Some(peer) => process_datagram(
                &peer,
                &sock,
                src,
                &datagram,
                cfg.quic_target,
                cfg.data_target,
            ),
            None => {
                // Unknown endpoint: a new handshake. Only the peer whose static
                // key matches can decrypt it; try them all.
                for p in peers.iter() {
                    let mut dst = [0u8; 2048];
                    if let TunnResult::WriteToNetwork(resp) =
                        p.tunn.decapsulate(Some(src.ip()), &datagram, &mut dst)
                    {
                        let resp = resp.to_vec();
                        *p.endpoint.lock().unwrap() = Some(src);
                        let _ = sock.send_to(&resp, src);
                        eprintln!("[wgtunnel-server] peer handshake from {src}");
                        break;
                    }
                }
            }
        }
    }
}
