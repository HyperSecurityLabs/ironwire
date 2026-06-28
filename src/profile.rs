/// IronWire — Profile & Configuration
///
/// Banner display, port parsing, TCP option generation, interface
/// resolution, and server file loading utilities.

use pnet::packet::tcp::TcpFlags;
use pnet::util::MacAddr;
use rand::Rng;
use std::net::Ipv4Addr;

/// Prints the IronWire ASCII banner with legal warnings.
pub fn show_banner() {
    let c = |s, code| format!("\x1b[{}m{}\x1b[0m", code, s);
    let g = 92; let lg = 96;

    println!();
    println!("{}", c("  +-------------------------------+",lg));
    println!("  | {} |",c("█ █▀█ █▀█ █▄█ █░█░█ █ █▀█ █▀▀", g));
    println!("  | {} |",c("█ █▀▄ █▄█ █░█ █▄█▄█ █ █▀▄ █▄▄", g));
    println!("{}", c("  +-------------------------------+",lg));
    println!("  {}  {}  {}", c("[~]", lg), c("khaninkali", g), c("— because who needs UDP?", lg));
    println!("  {}  {}  {}", c("[~]", lg), c("HyperSec Off Labs", g), c("--=[ TCP raw dog since '25 ]=--", lg));
    println!("  {}  {}  {}", c("[~]", lg), c("I am Alter", g), c("— your wi-fi's worst nightmare", lg));
    println!("  {}  {}  {}", c("[~]", lg), c("github.com/HyperSecuritylabs", g), c("--=[ no refunds, no mercy ]=--", lg));
    println!("{}", c("  +-------------------------------+", g));
    println!("  {}{}", c("[!] ", 91), c("WARNING: This WILL fry packets & annoy sysadmins.", 93));
    println!("  {}{}", c("[!] ", 91), c("WARNING: Only use on networks you own or have written permission to test.", 93));
    println!("  {}{}", c("[!] ", 91), c("WARNING: Author assumes ZERO liability for any misuse or mayhem.", 93));
    println!("  {}{}", c("[!] ", 91), c("WARNING: Running this without authorization is a felony in most countries.", 93));
    println!("{}", c("  +-------------------------------+", g));
    println!();
}

/// Commonly scanned TCP ports.
pub const COMMON_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443, 9200, 27017,
];

/// Scan type names mapped to their TCP flag byte values.
/// Note: 'connect' is removed because IronWire operates at raw-socket level
/// (AF_PACKET) and cannot perform real connect() syscall scans from layer 2.
/// Use 'syn' for standard half-open scanning instead.
pub const SCAN_FLAGS: &[(&str, u8)] = &[
    ("syn", TcpFlags::SYN),
    ("ack", TcpFlags::ACK),
    ("fin", TcpFlags::FIN),
    ("xmas", TcpFlags::FIN | TcpFlags::PSH | TcpFlags::URG),
    ("null", 0),
    ("rst", TcpFlags::RST),
];

/// Looks up the TCP flag byte for a scan type name.
pub fn get_scan_flags(scan_type: &str) -> u8 {
    for (name, flags) in SCAN_FLAGS {
        if *name == scan_type { return *flags; }
    }
    TcpFlags::SYN
}

/// Parses a port specification string into a list of port numbers.
/// Supports "common", ranges (80-100), and comma-separated lists.
pub fn parse_ports(port_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    if port_str == "common" { return COMMON_PORTS.to_vec(); }
    for part in port_str.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(s), Ok(e)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for port in s..=e { ports.push(port); }
                }
            }
        } else {
            if let Ok(p) = part.parse::<u16>() { ports.push(p); }
        }
    }
    ports
}

/// Generates a random public IPv4 address for source IP spoofing.
/// Excludes 0/8, 10/8, 127/8, 169.254/16, 172.16/12, 192.168/16,
/// multicast (224-239/4), reserved (240+/4), and .0/.255 host bits.
pub fn random_ip() -> Ipv4Addr {
    let mut rng = rand::thread_rng();
    loop {
        let a = rng.gen_range(1..224);
        let b = rng.gen_range(0..=255);
        let c = rng.gen_range(0..=255);
        let d = rng.gen_range(1..255);

        if a == 10 { continue; }
        if a == 169 && b == 254 { continue; }
        if a == 172 && b >= 16 && b <= 31 { continue; }
        if a == 192 && b == 168 { continue; }

        return Ipv4Addr::new(a, b, c, d);
    }
}

/// Generates a random high source port.
pub fn random_port() -> u16 {
    rand::thread_rng().gen_range(1024..65535)
}

/// Generates randomised TCP options (MSS, window scale, SACK, timestamps).
pub fn generate_tcp_options() -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut opts = Vec::new();
    opts.push(2); opts.push(4);
    let mss: u16 = rng.gen_range(536..1460);
    opts.extend_from_slice(&mss.to_be_bytes());
    if rng.gen_bool(0.7) {
        opts.push(3); opts.push(3); opts.push(rng.gen_range(0..14));
    }
    if rng.gen_bool(0.8) {
        opts.push(4); opts.push(2);
    }
    if rng.gen_bool(0.6) {
        opts.push(8); opts.push(10);
        opts.extend_from_slice(&rng.gen::<u32>().to_be_bytes());
        opts.extend_from_slice(&0u32.to_be_bytes());
    }
    while opts.len() % 4 != 0 { opts.push(1); }
    opts
}

/// Resolves the first non-loopback network interface with an IPv4 address.
pub fn resolve_interface() -> Option<(String, MacAddr, Ipv4Addr)> {
    let ifaces = pnet::datalink::interfaces();
    for iface in &ifaces {
        if iface.is_up() && iface.name != "lo" && !iface.ips.is_empty() {
            let mac = iface.mac?;
            if let std::net::IpAddr::V4(v4) = iface.ips.iter()
                .find(|i| i.is_ipv4())?
                .ip()
            {
                return Some((iface.name.clone(), mac, v4));
            }
        }
    }
    None
}

/// Resolves the best interface, preferring wlan0 over eth0.
pub fn resolve_best_interface() -> Option<(String, MacAddr, Ipv4Addr)> {
    let ifaces = pnet::datalink::interfaces();
    // Prefer wlan0 (wireless)
    for name in &["wlan0", "wlan1", "wlp2s0", "wlp3s0", "eth0", "enp0s3", "enp2s0"] {
        if let Some(iface) = ifaces.iter().find(|i| i.name == *name) {
            if iface.is_up() && !iface.ips.is_empty() {
                if let Some(mac) = iface.mac {
                    if let std::net::IpAddr::V4(v4) = iface.ips.iter()
                        .find(|i| i.is_ipv4())?
                        .ip()
                    {
                        return Some((iface.name.clone(), mac, v4));
                    }
                }
            }
        }
    }
    None
}

/// Resolves interface info by name.
pub fn resolve_by_name(name: &str) -> Option<(String, MacAddr, Ipv4Addr)> {
    let ifaces = pnet::datalink::interfaces();
    let iface = ifaces.iter().find(|i| i.name == name)?;
    let mac = iface.mac?;
    if let std::net::IpAddr::V4(v4) = iface.ips.iter()
        .find(|i| i.is_ipv4())?
        .ip()
    {
        Some((iface.name.clone(), mac, v4))
    } else {
        None
    }
}

/// Parsed server file contents: a list of (IP, port) pairs.
pub struct ServersFile {
    pub entries: Vec<(Ipv4Addr, u16)>,
}

impl ServersFile {
    /// Loads a servers file where each line is `ip:port` or just `ip`.
    pub fn load(path: &str, default_port: u16) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read {}: {}", path, e))?;
        let mut entries = Vec::new();
        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') { continue; }
            if let Some((host, port_str)) = trimmed.rsplit_once(':') {
                let ip: Ipv4Addr = host.trim().parse().map_err(|_| format!("bad IP: {}", host))?;
                let port: u16 = port_str.trim().parse().map_err(|_| format!("bad port: {}", port_str))?;
                entries.push((ip, port));
            } else {
                let ip: Ipv4Addr = trimmed.parse().map_err(|_| format!("bad IP: {}", trimmed))?;
                entries.push((ip, default_port));
            }
        }
        if entries.is_empty() {
            return Err("no valid entries in servers file".into());
        }
        Ok(Self { entries })
    }
}
