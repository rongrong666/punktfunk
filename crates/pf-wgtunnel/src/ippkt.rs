//! Minimal inner-packet plumbing: hand-rolled IPv4 + UDP, no tun device needed.
//!
//! The tunnel carries synthetic IPv4/UDP datagrams between the client relay and
//! the host gate. UDP checksum is zero (legal on IPv4); the IPv4 header
//! checksum is computed properly so nothing in the path chokes on it.

use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;
const IP_PROTO_UDP: u8 = 17;

/// A parsed inner UDP datagram.
#[derive(Debug, Clone)]
pub struct InnerUdp {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: Vec<u8>,
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    debug_assert_eq!(header.len(), IPV4_HEADER_LEN);
    let mut sum: u32 = 0;
    for i in (0..IPV4_HEADER_LEN).step_by(2) {
        sum += u16::from_be_bytes([header[i], header[i + 1]]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a synthetic IPv4 + UDP packet around `payload`.
pub fn build_udp(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total_len = (IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);

    // IPv4 header (checksum filled in after).
    pkt.push(0x45); // version 4, IHL 5
    pkt.push(0); // DSCP/ECN
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes()); // identification
    pkt.extend_from_slice(&0x4000u16.to_be_bytes()); // flags: DF, frag offset 0
    pkt.push(64); // TTL
    pkt.push(IP_PROTO_UDP);
    pkt.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    pkt.extend_from_slice(&src_ip.octets());
    pkt.extend_from_slice(&dst_ip.octets());
    let csum = ipv4_checksum(&pkt);
    pkt[10..12].copy_from_slice(&csum.to_be_bytes());

    // UDP header, checksum zero.
    pkt.extend_from_slice(&src_port.to_be_bytes());
    pkt.extend_from_slice(&dst_port.to_be_bytes());
    pkt.extend_from_slice(&((UDP_HEADER_LEN + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(payload);
    pkt
}

/// Parse a synthetic IPv4 + UDP packet. Returns `None` for anything that is
/// not a well-formed, unfragmented IPv4 UDP datagram.
pub fn parse_udp(pkt: &[u8]) -> Option<InnerUdp> {
    if pkt.len() < IPV4_HEADER_LEN + UDP_HEADER_LEN {
        return None;
    }
    if pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl != IPV4_HEADER_LEN {
        return None; // no options supported
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len != pkt.len() {
        return None;
    }
    let frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if frag & 0x3fff != 0 {
        return None; // no fragments
    }
    if pkt[9] != IP_PROTO_UDP {
        return None;
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let udp = &pkt[IPV4_HEADER_LEN..];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
    let udp_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if udp_len < UDP_HEADER_LEN || IPV4_HEADER_LEN + udp_len > pkt.len() {
        return None;
    }
    Some(InnerUdp {
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload: udp[UDP_HEADER_LEN..udp_len].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let payload = b"hello punktfunk";
        let pkt = build_udp(
            Ipv4Addr::new(10, 8, 0, 2),
            51234,
            Ipv4Addr::new(10, 8, 0, 1),
            9777,
            payload,
        );
        let parsed = parse_udp(&pkt).expect("parse");
        assert_eq!(parsed.src_ip, Ipv4Addr::new(10, 8, 0, 2));
        assert_eq!(parsed.dst_ip, Ipv4Addr::new(10, 8, 0, 1));
        assert_eq!(parsed.src_port, 51234);
        assert_eq!(parsed.dst_port, 9777);
        assert_eq!(parsed.payload, payload);
    }
}
