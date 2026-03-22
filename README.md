# ARPSpoofing/MITM Tool — Documentation

---

## README.md


# ☠️ ARPSpoofing / MITM Tool v1.0

> A high-performance, low-overhead ARP poisoning framework for authorized
> network security research and penetration testing.
>
> **⚠️ Legal Notice:** Use only on networks you own or have explicit written
> permission to test. Unauthorized use is illegal and unethical.
> The author assumes zero liability for misuse.

---

## 📖 Table of Contents

- [Overview](#overview)
- [How It Works](#how-it-works)
- [Architecture & Engineering](#architecture--engineering)
- [Attack Modes](#attack-modes)
- [Spoof Switch](#spoof-switch)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Performance Notes](#performance-notes)
- [Restoration / Cleanup](#restoration--cleanup)
- [License](#license)
- [Author's Note](#authorship-note)
---

## Overview

ARPSpoofing/MITM Tool is a Python-based Layer 2 attack framework that
implements ARP cache poisoning with three distinct operational modes —
**flood**, **stealth**, and **hybrid** — each designed for a different
threat model and detection-evasion requirement.

The tool was designed from the ground up with one engineering constraint:
**Scapy must never appear in the hot path.** All packet sending and
receiving after startup is done through raw `AF_PACKET` sockets with a
kernel-level BPF filter, and incoming frames are parsed with a single
`struct.unpack` call (~0.3 μs). Scapy is only used at startup for MAC
resolution and one-time frame construction.

---

## How It Works

### The ARP Protocol Weakness

ARP (Address Resolution Protocol) is stateless and unauthenticated.
Any host on a LAN can broadcast or unicast an ARP reply claiming that
a given IP address belongs to a MAC address it chooses — and the
receiving host will blindly update its ARP cache.

This tool exploits that weakness to insert the attacker's machine
between a target host and its default gateway (router):


Normal traffic flow:
  Target ──────────────────────► Router ──► Internet

After ARP poisoning (full MITM):
  Target ──► Attacker (us) ──► Router ──► Internet
              ↑  we see everything here

Two spoofed ARP replies maintain the illusion:

| Frame | Claim | Sent to |
|-------|-------|---------|
| `frame_to_target` | "Router IP is at **our** MAC" | Target |
| `frame_to_router` | "Target IP is at **our** MAC" | Router |

As long as these frames keep refreshing the caches, all traffic flows
through the attacker's machine.

---

## Architecture & Engineering

### Design Philosophy

The core idea driving this tool is a clean separation between
**startup work** (slow, convenient) and **hot-path work** (fast, raw):


┌─────────────────────────────────────────────────────┐
│                    STARTUP (slow path)               │
│  • Scapy: MAC resolution via ARP probes              │
│  • Scapy: Build Ethernet+ARP frames ONCE as bytes    │
│  • fcntl/ioctl: Read own hardware MAC from kernel    │
│  • Open AF_PACKET sockets, attach BPF filter         │
└───────────────────────────┬─────────────────────────┘
                            │  pre-built bytes[]
                            ▼
┌─────────────────────────────────────────────────────┐
│                  HOT PATH (fast path)                │
│  • socket.send(pre_built_bytes)  — zero alloc        │
│  • socket.recv() — kernel drops non-ARP via BPF      │
│  • struct.unpack_from(42 bytes) — ~0.3 μs parse      │
│  • NO Scapy, NO dict lookups, NO frame construction  │
└─────────────────────────────────────────────────────┘

### Key Engineering Decisions

#### 1. Pre-built Packet Bytes
Both spoofed frames (`frame_to_target`, `frame_to_router`) are
constructed **exactly once** before any loop starts and stored as
plain `bytes` objects. Sending them is a single `socket.send(bytes)`
call — no object allocation, no field serialization, no Scapy overhead
per iteration.

#### 2. AF_PACKET Raw Sockets
All I/O uses `AF_PACKET / SOCK_RAW` — Layer 2 raw sockets that bypass
the kernel's TCP/IP stack entirely. The tool operates directly at the
Ethernet frame level, which is required for:
- Sending frames with a spoofed source MAC
- Receiving frames before any routing decision is made
- Zero-copy semantics between NIC and userspace buffer

#### 3. Kernel-Level BPF Filter
A compiled BPF (Berkeley Packet Filter) program is attached to the
receiver socket via `SO_ATTACH_FILTER`. The filter matches only frames
with EtherType `0x0806` (ARP). All other traffic — TCP, UDP, ICMP,
everything — is dropped **inside the kernel**, before it is ever copied
to userspace. This means:
- Near-zero CPU cost for busy networks
- The Python process never wakes up for non-ARP frames
- No need for userspace EtherType checks (though one is kept as
  a belt-and-suspenders fallback)

#### 4. struct.unpack ARP Parser
The reactive path parses incoming ARP request frames with a single
`struct.unpack_from` call on 28 bytes. No Scapy, no object creation,
no attribute lookups. The parsed fields (sender IP, target IP, opcode)
are enough to decide which spoofed reply, if any, to fire.

#### 5. Separate Sender / Receiver Sockets
A dedicated `RawSender` socket and a dedicated `RawReceiver` socket
(with BPF) are opened separately. This avoids the overhead of the BPF
filter firing on frames the sender itself just transmitted, and keeps
the two concerns cleanly isolated.

---

## Attack Modes

The three modes represent a spectrum from **maximum reliability** to
**maximum stealth**, with hybrid sitting in the middle:


Reliability ◄──────────────────────────► Stealth
   flood          hybrid          stealth

### 🚀 Flood Mode
**Strategy:** Unconditional periodic transmission.

Every `--interval` seconds (default: 1.0 s), the tool sends both
spoofed ARP replies regardless of what the targets are doing. The
ARP caches are re-poisoned on a fixed schedule.

- **Pros:** Dead-simple, highly reliable, works even if the victim
  constantly refreshes its cache.
- **Cons:** Generates periodic traffic that a network IDS (e.g.,
  Snort ARP preprocessor, XArp) can fingerprint trivially — the
  regular cadence is a strong anomaly signal.
- **Best for:** Lab environments, CTF challenges, fast proof-of-concept.


Timeline:
t=0s  → send spoof   t=1s  → send spoof   t=2s  → send spoof ...

### 🕵️ Stealth Mode
**Strategy:** Pure reactive — fire only when triggered.

A raw BPF-filtered socket listens for ARP **requests**. When the
router broadcasts "who has \<target IP\>?", the tool immediately
unicasts the spoofed reply. When the target broadcasts "who has
\<router IP\>?", it does the same in the other direction.

No unsolicited ARP replies are ever sent. The tool is silent until
the victims themselves ask a question.

- **Pros:** Generates the absolute minimum number of spoofed packets.
  No periodic anomaly. Blends naturally into normal ARP traffic patterns.
- **Cons:** If the attacker misses a legitimate reply (e.g., the real
  router replies before us), the poison is temporarily broken until
  the next request cycle (typically 20–30 s for most OSes).
- **Best for:** Environments with active ARP monitoring, red-team
  engagements where stealth is prioritized over reliability.


Timeline:
victim asks "who has router?" → we reply instantly → cache poisoned
(silence until next request)

### 🔄 Hybrid Mode
**Strategy:** Reactive hot path + low-rate proactive background thread.

A background thread sends spoofed replies at a low rate
(`--interval`, default: 1.0 s but typically set to 3–10 s for stealth).
The main thread simultaneously runs the reactive listener from stealth
mode. The two subsystems share the same pre-built frame bytes and a
single sender socket (writes are not split-second concurrent enough
to need locking on the socket itself).

- **Pros:** Best of both worlds — the reactive path keeps poisoning
  instant and the proactive thread guarantees eventual re-poisoning
  even if requests are missed. The proactive interval can be set
  very low (e.g., 10 s) to reduce IDS visibility while still
  maintaining reliability.
- **Cons:** Slightly more complex; two threads running (though the
  background thread is lightweight).
- **Best for:** Real-world engagements where both reliability and
  reduced IDS visibility matter.


Timeline:
t=0s   proactive burst
t=0.4s victim asks → reactive reply (instant)
t=3s   proactive burst
t=5.1s victim asks → reactive reply (instant)
...

### Mode Comparison Table

| Property | Flood | Stealth | Hybrid |
|----------|-------|---------|--------|
| Packets per minute (idle network) | ~120 | ~0 | ~12–20 |
| Reaction to ARP request | next interval | instant | instant |
| IDS anomaly score | high | very low | low |
| Reliability if requests missed | ✅ | ❌ | ✅ |
| CPU overhead | minimal | minimal | minimal |
| Threads used | 1 | 1 | 2 |

---

## Spoof Switch

The `-s / --spoof` flag enables **single-target (router-only) spoofing**.

In normal full-MITM mode, both the target and the router have their
ARP caches poisoned. The spoof flag changes the behavior so that
**only the router's ARP cache is poisoned** — the target is never
sent any spoofed frame.


Full MITM (-s not set):
  Router ARP cache:  target_ip → our_mac   ← poisoned
  Target ARP cache:  router_ip → our_mac   ← poisoned
  Result: traffic flows both ways through attacker

Single-target (-s set):
  Router ARP cache:  target_ip → our_mac   ← poisoned
  Target ARP cache:  router_ip → router_mac (unchanged, correct)
  Result: only traffic FROM target TO router is intercepted
          (router's replies go directly to target, bypassing attacker)

**Use case:** One-way traffic interception — for example, capturing
outbound requests from the target without modifying inbound responses,
or in scenarios where touching the target's ARP table would be
detected by host-based security software running on the victim.

---

## Installation

### Requirements
- Linux (AF_PACKET is Linux-specific)
- Python 3.10+ (uses `X | Y` union type hints)
- Root / `CAP_NET_RAW` capability
- Scapy (used only at startup)

bash
# Install Scapy
pip install scapy

# Or via package manager
sudo apt install python3-scapy

### Optional: Grant CAP_NET_RAW without sudo
bash
sudo setcap cap_net_raw+eip $(which python3)
# Run without sudo (capability is on the interpreter binary)
python3 arp_spoofer.py 192.168.1.6 192.168.1.1 -i eth0 -m hybrid

### Enable IP Forwarding (required for MITM — do NOT skip)
bash
# Temporary (resets on reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
> Without IP forwarding enabled, the attacker's kernel will DROP
> all forwarded packets rather than relay them, effectively causing
> a denial-of-service instead of a transparent MITM.

---

## Usage


usage: arp_spoofer.py [-h] [-i IFACE] [-m {flood,stealth,hybrid}] [-s]
               [--interval INTERVAL] [--burst BURST]
               target_ip router_ip

positional arguments:
  target_ip             Target (victim) IP address
  router_ip             Router / gateway IP address

options:
  -h, --help            show this help message and exit
  -i, --iface IFACE     Network interface to use (default: wlan0)
  -m, --mode {flood,stealth,hybrid}
                        Attack mode (default: flood)
  -s, --spoof           Single-target spoof: only poison the router's cache
  --interval INTERVAL   Seconds between proactive bursts (default: 1.0)
  --burst BURST         Pre-poison packets per side at startup (default: 5)

---

## Examples

bash
# Full MITM, hybrid mode, custom interface
sudo python3 arp_spoofer.py 192.168.1.6 192.168.1.1 -i eth0 -m hybrid

# Full MITM, flood mode, faster interval
sudo python3 arp_spoofer.py 10.0.0.50 10.0.0.1 -i enp3s0 -m flood --interval 0.5

# Stealth mode, router-only poison (single-target)
sudo python3 arp_spoofer.py 192.168.1.6 192.168.1.1 -i wlan0 -m stealth -s

# Hybrid, slow proactive rate (reduced IDS visibility), large pre-poison burst
sudo python3 arp_spoofer.py 192.168.1.100 192.168.1.1 -i eth0 -m hybrid \
    --interval 8.0 --burst 15

---

## Performance Notes

| Metric | Value |
|--------|-------|
| ARP frame parse latency | ~0.3 μs (`struct.unpack`) |
| Scapy frame parse latency | ~80–150 μs (typical) |
| Hot-path Scapy calls | **0** |
| Kernel-filtered frames (BPF) | 100% non-ARP traffic |
| Pre-built frame allocations per send | **0** |
| Threads (flood / stealth) | 1 |
| Threads (hybrid) | 2 |

---

## Restoration / Cleanup

On `Ctrl+C`, the tool automatically sends **correct** ARP replies to
both sides ($N = 7$ by default, spaced 300 ms apart) to restore their
caches to the legitimate state:


Sent to router:  "target_ip is at target_real_mac"
Sent to target:  "router_ip is at router_real_mac"  (unless -s was used)

This ensures the network returns to normal operation without requiring
a reboot or cache flush on the victim machines.

---

## License

See [LICENSE](#license-details) section below.

---

## Authorship note

hello Parsa here , this is my first my project as a Learner/Student in the vast field of cybersecurity , the core concepts of the project(different attack modes , the switches , prebuilding packets , the use of AF_packet ,  and the overall Architecture/Engineering of the project were done by me) and also the initial code of this project was written with the scapy Module but for Maximuxm Efficiency , Refinements and Crucial Modifications ,  I used claude opus, thank you for reading!!!


