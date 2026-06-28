> IRONWIRE

[![Kali](https://img.shields.io/badge/Kali-Linux-31748f?style=for-the-badge&logo=kalilinux&logoColor=000&labelColor=31748f)](https://www.kali.org) 
[![Rust](https://img.shields.io/badge/Rust-Language-eb6f92?style=for-the-badge&logo=rust&logoColor=000&labelColor=eb6f92)](https://www.rust-lang.org) 
[![License](https://img.shields.io/badge/License-MIT-9ccfd8?style=for-the-badge&logo=open-source-initiative&logoColor=000&labelColor=9ccfd8)](https://github.com) 
[![Portal](https://img.shields.io/badge/Portal-HSOL-2d6a4f?style=for-the-badge&logo=google-chrome&logoColor=000&labelColor=2d6a4f)](https://hypersecurityoffseclabs.great-site.net) 
[![Telegram](https://img.shields.io/badge/Telegram-Join-c4a7e7?style=for-the-badge&logo=telegram&logoColor=000&labelColor=c4a7e7)](https://t.me/hypersecurity_offsec)
[![Warning](https://img.shields.io/badge/Warning-Educational%20Only-f6c177?style=for-the-badge&labelColor=f6c177)](https://hypersecurityoffseclabs.great-site.net)
[![_Port_Scanning](https://img.shields.io/badge/_Port_Scanning-7_Scan_Types-9ccfd8?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=9ccfd8)](https://hypersecurityoffseclabs.great-site.net)

IronWire is a raw TCP packet crafting and network stress testing framework built in Rust. Operating at Layer 2 via AF_PACKET, it bypasses the kernel TCP stack to give full control over flags, sequence numbers, options, and source addresses. Designed for adversarial simulations — port scanning, SYN flooding, TCP reflection, amplification analysis, and full 3-way handshake floods — with an adaptive bypass engine that self-tunes based on real-time packet loss. Linux only, root required.

**Version:** 4.5.0
**Author:** khaninkali · HyperSecurity Offensive Labs

---

[![_Capabilities](https://img.shields.io/badge/_Capabilities-Attack_Vectors-eb6f92?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=eb6f92)](https://hypersecurityoffseclabs.great-site.net)


| Type | Flags | Evasion |
|---|---|---|
| SYN | SYN | Standard — detected by most IDS |
| CONNECT | SYN (full connect) | Logged by application |
| ACK | ACK | **Stealth** — many IDS ignore ACK scans |
| FIN | FIN | Evasive — some firewalls don't log FIN |
| XMAS | FIN+PSH+URG | Unusual flag combo evades simple rules |
| NULL | 0 flags | **Most evasive** — no flags to match |
| RST | RST | Useful for killing existing connections |

[![_SYN_Flood](https://img.shields.io/badge/_SYN_Flood-Resource_Exhaustion-31748f?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=31748f)](https://hypersecurityoffseclabs.great-site.net)
- Random source IP (evades per-IP rate limiting)
- Random source port (evades per-port limiting)
- Random TCP options (evades signature-based detection)
- Burst control with adaptive delay

[![_TCP_Reflection](https://img.shields.io/badge/_TCP_Reflection-Victim_Spoofing-c4a7e7?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=c4a7e7)](https://hypersecurityoffseclabs.great-site.net)

Sends SYN with spoofed source IP = victim. Each reflector responds with SYN-ACK to the victim, hiding the attacker origin.

[![_TCP_Amplification](https://img.shields.io/badge/_TCP_Amplification-Factor_Discovery-ebbcba?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=ebbcba)](https://hypersecurityoffseclabs.great-site.net)

Tracks sent vs received bytes per service to calculate amplification factor. Typical TCP factors: 1.3x–1.5x.

[![_ACK_Reflection](https://img.shields.io/badge/_ACK_Reflection-RST_Flood-f6c177?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=f6c177)](https://hypersecurityoffseclabs.great-site.net)

Sends ACK packets with spoofed victim source to reflectors. ACK packets often pass through firewall ACLs — stateful firewalls expect ACKs on established connections.

[![_Handshake_Flood](https://img.shields.io/badge/_Handshake_Flood-Connection_Exhaustion-908caa?style=for-the-badge&logo=terminal&logoColor=ffffff&labelColor=908caa)](https://hypersecurityoffseclabs.great-site.net)

Completes full TCP handshake (SYN → SYN-ACK → ACK), sends keep-alive data, holds connections open until FIN teardown. Kernel RST suppression via iptables.

---

## Adaptive Bypass Engine

Auto-tuning stealth profiles with loss-based rate adaptation:

| Profile | Base Delay | Burst | Jitter | Strategy |
|---|---|---|---|---|
| **Silent** | 50ms | 5 | 100ms | Minimum footprint |
| **Adaptive** | 20ms | 20 | 50ms | Self-tuning |
| **Aggressive** | 0ms | 50 | 5ms | Max throughput |

The adaptive monitor uses a sliding window to track packet loss:
- Loss > 30% → delay doubles
- Loss 10–30% → +10ms
- 20 consecutive successes → –5ms (ramp up)
- 5 consecutive failures → 3x delay

---

## CLI Reference

```
ironwire --target <IP> --ports <PORTS> [OPTIONS]
ironwire --servers servers.txt [OPTIONS]
```

| Flag | Default | Description |
|---|---|---|
| `-t, --target` | — | Target IP address |
| `-p, --ports` | common | Ports: range (1-1000), list (80,443), common |
| `-c, --connections` | 50 | Connection burst size |
| `-d, --duration` | 120s | Test duration |
| `-a, --attack-type` | scan | scan / flood / reflect / amplify / ack-reflect / handshake / comprehensive |
| `--scan-type` | syn | syn / connect / ack / fin / xmas / null / rst |
| `-g, --aggression` | 3 | 1 (slow) to 5 (max) |
| `--source-variation` | true | Randomize source IP |
| `--random-ports` | true | Randomize source port |
| `--random-options` | true | Randomize TCP options |
| `--profile` | adaptive | silent / adaptive / aggressive |
| `--auto-interface` | true | Auto-select best interface |
| `--target-mac` | — | Manual target MAC override |
| `--interface` | — | Network interface (auto-detected) |
| `--victim` | — | Victim IP for reflection/amplification |
| `--reflector-port` | 80 | Reflector port |
| `--amp` | 80,443,22,8080 | Amplifier ports |
| `--servers` | — | Path to servers.txt |
| `--hto` | 5s | Handshake timeout |

---

## Requirements

- **Linux** (raw sockets via AF_PACKET)
- **Root** (`libc::getuid() == 0`)
- **Rust** (edition 2021)

---

## OPSEC

- Random source IPs must be routable on your network to trigger responses
- Aggression 5 saturates the transmit ring buffer — can crash `pnet` on low-end NICs
- iptables RST suppression rule persists if process is SIGKILL'd — always SIGTERM (Ctrl+C)
- MAC resolution leaves ARP cache entries — clean up after engagement
- Enable `net.ipv4.conf.all.rp_filter=0` on attack box to allow spoofed source packets
