"""
ISP View - real-time packet monitor that shows what your ISP can see.

Captures every IPv4 packet on your main network adapter (Windows raw socket,
needs Administrator - no extra drivers) and explains, per connection, what is
visible to anyone on the path (your ISP):

  * every remote IP address, port, packet size and timing
  * plaintext DNS lookups (every domain name you resolve)
  * the domain name inside TLS ClientHello (SNI) for HTTPS
  * the domain name inside QUIC/HTTP3 Initial packets (decryptable by anyone)
  * full URLs + content of plaintext HTTP
"""

import csv
import ctypes
import hashlib
import hmac
import ipaddress
import os
import socket
import struct
import sys
import threading
import time
from collections import deque

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

try:
    import psutil
except Exception:  # pragma: no cover
    psutil = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover
    HAVE_CRYPTO = False


APP_NAME = "ISP View"

# --------------------------------------------------------------------------
# Admin / elevation
# --------------------------------------------------------------------------

def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin():
    if getattr(sys, "frozen", False):
        exe, args = sys.executable, sys.argv[1:]
    else:
        exe, args = sys.executable, [os.path.abspath(sys.argv[0])] + sys.argv[1:]
    params = " ".join(f'"{a}"' for a in args)
    rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
    return rc > 32


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def default_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 53))  # UDP connect sends nothing
        return s.getsockname()[0]
    finally:
        s.close()


def iface_for_ip(ip):
    if not psutil:
        return None
    for name, addrs in psutil.net_if_addrs().items():
        for a in addrs:
            if a.family == socket.AF_INET and a.address == ip:
                return name
    return None


VPN_NAME_HINTS = ("vpn", "wireguard", "wintun", "tap-", "tap ", "tun", "proton", "nord",
                  "mullvad", "surfshark", "express", "windscribe", "tailscale", "zerotier",
                  "cloudflare warp", "pia", "ipvanish", "cyberghost")
SKIP_IFACE_HINTS = ("loopback", "vethernet", "virtualbox", "vmware", "hyper-v")


class Iface:
    def __init__(self, name, ip, vpn):
        self.name, self.ip, self.vpn = name, ip, vpn

    def __repr__(self):
        return f"{self.name} ({self.ip}){' [VPN]' if self.vpn else ''}"


def capture_interfaces():
    """All active IPv4 adapters worth sniffing, VPN adapters flagged."""
    out = []
    if psutil:
        stats = psutil.net_if_stats()
        for name, addrs in psutil.net_if_addrs().items():
            st = stats.get(name)
            low = name.lower()
            if not st or not st.isup or any(h in low for h in SKIP_IFACE_HINTS):
                continue
            for a in addrs:
                if a.family == socket.AF_INET and not a.address.startswith(("127.", "169.254.")):
                    out.append(Iface(name, a.address, any(h in low for h in VPN_NAME_HINTS)))
    if not out:
        ip = default_local_ip()
        out.append(Iface(iface_for_ip(ip) or "default", ip, False))
    return out


def fmt_bytes(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def fmt_rate(n):
    return fmt_bytes(n) + "/s"


_global_cache = {}


def is_public(ip):
    r = _global_cache.get(ip)
    if r is None:
        try:
            a = ipaddress.ip_address(ip)
            r = a.is_global and not a.is_multicast and not ip.endswith(".255")
        except ValueError:
            r = False
        _global_cache[ip] = r
    return r


TCP_SERVICES = {
    443: "HTTPS", 80: "HTTP", 22: "SSH", 853: "DNS-over-TLS", 993: "IMAPS",
    995: "POP3S", 465: "SMTPS", 587: "SMTP", 25: "SMTP", 143: "IMAP",
    110: "POP3", 21: "FTP", 23: "Telnet", 3389: "RDP", 5228: "Google Push",
    5223: "Apple Push", 8080: "HTTP-alt", 8443: "HTTPS-alt", 1194: "OpenVPN",
    445: "SMB", 53: "DNS (TCP)", 5222: "XMPP", 6881: "BitTorrent",
}
UDP_SERVICES = {
    443: "QUIC / HTTP3", 53: "DNS", 123: "NTP", 3478: "STUN/WebRTC",
    19302: "STUN (Google)", 51820: "WireGuard VPN", 1194: "OpenVPN",
    500: "IPsec VPN", 4500: "IPsec VPN", 853: "DNS-over-QUIC",
    5353: "mDNS", 5355: "LLMNR", 137: "NetBIOS", 1900: "SSDP", 67: "DHCP",
    68: "DHCP", 3479: "STUN/WebRTC", 3480: "STUN/WebRTC",
}
VPN_PORTS = {("UDP", 51820), ("UDP", 1194), ("TCP", 1194), ("UDP", 500), ("UDP", 4500)}
PLAINTEXT_PORTS = {("TCP", 80), ("TCP", 21), ("TCP", 23), ("TCP", 25), ("TCP", 110),
                   ("TCP", 143), ("TCP", 8080)}
DNS_QTYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 65: "HTTPS", 64: "SVCB", 255: "ANY"}
HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                b"PATCH ", b"CONNECT ")


# --------------------------------------------------------------------------
# Protocol parsers
# --------------------------------------------------------------------------

class Truncated(Exception):
    pass


def sni_from_client_hello(h):
    """h = TLS handshake message (starts with type byte 0x01). Returns SNI or None.
    Raises Truncated if more data is needed."""
    try:
        if h[0] != 1:
            return None
        body_len = int.from_bytes(h[1:4], "big")
        if len(h) < 4 + body_len:
            raise Truncated()
        p = 4 + 2 + 32
        p += 1 + h[p]                                   # session id
        p += 2 + struct.unpack("!H", h[p:p + 2])[0]     # cipher suites
        p += 1 + h[p]                                   # compression
        ext_len = struct.unpack("!H", h[p:p + 2])[0]
        p += 2
        end = p + ext_len
        while p + 4 <= end:
            et, el = struct.unpack("!HH", h[p:p + 4])
            p += 4
            if et == 0 and el > 5:
                q = p + 2
                if h[q] == 0:
                    nl = struct.unpack("!H", h[q + 1:q + 3])[0]
                    return h[q + 3:q + 3 + nl].decode("ascii", "replace")
            p += el
    except (IndexError, struct.error):
        return None
    return None


def parse_http_request(payload):
    try:
        head = payload[:4096].split(b"\r\n\r\n", 1)[0].decode("latin-1")
    except Exception:
        return None
    lines = head.split("\r\n")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        return None
    host = ""
    for ln in lines[1:]:
        if ln.lower().startswith("host:"):
            host = ln[5:].strip()
            break
    path = parts[1]
    url = path if path.startswith("http") else f"http://{host}{path}"
    return host, f"{parts[0]} {url}"


def _dns_name(msg, off):
    labels, ret, hops = [], None, 0
    while True:
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if ret is None:
                ret = off + 2
            off = ((ln & 0x3F) << 8) | msg[off + 1]
            hops += 1
            if hops > 15:
                raise ValueError("loop")
            continue
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", "replace"))
        off += 1 + ln
    return ".".join(labels), (ret if ret is not None else off)


def parse_dns(msg):
    """Returns (is_response, [(name, qtype)], [ip,...]) or None."""
    try:
        _id, flags, qd, an, _ns, _ar = struct.unpack("!6H", msg[:12])
        off, qs, ips = 12, [], []
        for _ in range(min(qd, 4)):
            name, off = _dns_name(msg, off)
            qtype = struct.unpack("!H", msg[off:off + 2])[0]
            off += 4
            qs.append((name, qtype))
        is_resp = bool(flags & 0x8000)
        if is_resp:
            for _ in range(min(an, 64)):
                _n, off = _dns_name(msg, off)
                t, _c, _ttl, rdl = struct.unpack("!HHIH", msg[off:off + 10])
                off += 10
                if t == 1 and rdl == 4:
                    ips.append(socket.inet_ntoa(msg[off:off + 4]))
                off += rdl
        return is_resp, qs, ips
    except Exception:
        return None


# ---- QUIC v1 Initial packet decryption (keys are public by design) --------

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _hkdf_expand_label(secret, label, length):
    full = b"tls13 " + label
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _varint(b, p):
    first = b[p]
    n = 1 << (first >> 6)
    v = first & 0x3F
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, p + n


_quic_key_cache = {}


def quic_initial_crypto_frames(dgram):
    """Decrypt a client QUIC v1 Initial packet. Returns (dcid, [(offset, data)])."""
    if not HAVE_CRYPTO or len(dgram) < 1200 - 100:
        return None
    b0 = dgram[0]
    if not (b0 & 0x80) or (b0 & 0x30) != 0:
        return None
    if dgram[1:5] != b"\x00\x00\x00\x01":
        return None
    try:
        p = 5
        dl = dgram[p]
        dcid = bytes(dgram[p + 1:p + 1 + dl])
        p += 1 + dl
        p += 1 + dgram[p]                      # scid
        tl, p = _varint(dgram, p)
        p += tl                                # token
        length, p = _varint(dgram, p)
        pn_off = p

        keys = _quic_key_cache.get(dcid)
        if keys is None:
            initial = hmac.new(QUIC_V1_SALT, dcid, hashlib.sha256).digest()
            cs = _hkdf_expand_label(initial, b"client in", 32)
            keys = (_hkdf_expand_label(cs, b"quic key", 16),
                    _hkdf_expand_label(cs, b"quic iv", 12),
                    _hkdf_expand_label(cs, b"quic hp", 16))
            if len(_quic_key_cache) > 512:
                _quic_key_cache.clear()
            _quic_key_cache[dcid] = keys
        key, iv, hp = keys

        sample = bytes(dgram[pn_off + 4:pn_off + 20])
        enc = Cipher(algorithms.AES(hp), modes.ECB()).encryptor()
        mask = enc.update(sample) + enc.finalize()
        first = b0 ^ (mask[0] & 0x0F)
        pnl = (first & 3) + 1
        pn_bytes = bytes(dgram[pn_off + i] ^ mask[1 + i] for i in range(pnl))
        header = bytes([first]) + bytes(dgram[1:pn_off]) + pn_bytes
        pn = int.from_bytes(pn_bytes, "big")
        nonce = bytes(a ^ b for a, b in zip(iv, pn.to_bytes(12, "big")))
        ct = bytes(dgram[pn_off + pnl:pn_off + length])
        plain = AESGCM(key).decrypt(nonce, ct, header)
    except Exception:
        return None

    frames, q = [], 0
    try:
        while q < len(plain):
            ft = plain[q]
            if ft in (0x00, 0x01):
                q += 1
            elif ft == 0x06:
                off, q = _varint(plain, q + 1)
                ln, q = _varint(plain, q)
                frames.append((off, plain[q:q + ln]))
                q += ln
            elif ft in (0x02, 0x03):
                _, q = _varint(plain, q + 1)
                _, q = _varint(plain, q)
                rc, q = _varint(plain, q)
                _, q = _varint(plain, q)
                for _ in range(rc * 2):
                    _, q = _varint(plain, q)
                if ft == 0x03:
                    for _ in range(3):
                        _, q = _varint(plain, q)
            else:
                break
    except IndexError:
        pass
    return dcid, frames


# --------------------------------------------------------------------------
# State
# --------------------------------------------------------------------------

SEV_PLAIN, SEV_DOMAIN, SEV_OPAQUE, SEV_VPN, SEV_LAN, SEV_HIDDEN = (
    "plain", "domain", "opaque", "vpn", "lan", "hidden")


class Flow:
    __slots__ = ("proto", "rip", "rport", "lport", "host", "host_src", "url",
                 "b_out", "b_in", "p_out", "p_in", "first", "last", "proc",
                 "dirty", "public", "iface", "tunneled", "vpn_proto")

    def __init__(self, proto, rip, rport, lport, ifc):
        self.proto, self.rip, self.rport, self.lport = proto, rip, rport, lport
        self.host = self.host_src = self.url = self.vpn_proto = ""
        self.b_out = self.b_in = self.p_out = self.p_in = 0
        self.first = self.last = time.time()
        self.proc = ""
        self.dirty = True
        self.public = is_public(rip)
        self.iface = ifc.name
        self.tunneled = ifc.vpn

    @property
    def service(self):
        if self.vpn_proto:
            return f"{self.vpn_proto} VPN"
        table = TCP_SERVICES if self.proto == "TCP" else UDP_SERVICES
        return table.get(self.rport, table.get(self.lport, self.proto))

    @property
    def isp_visible(self):
        return not self.tunneled and (self.public or self.rport == 53)

    def visibility(self):
        """(severity, plain-English description of what the ISP sees)"""
        key = (self.proto, self.rport)
        if self.tunneled:
            return SEV_HIDDEN, "Nothing - inside your VPN tunnel (encrypted)"
        if not self.public and self.rport != 53:
            return SEV_LAN, "Local network only - never reaches your ISP"
        if self.vpn_proto:
            return SEV_VPN, f"Only that you use a {self.vpn_proto} VPN to this server + volume"
        if any(h in self.proc.lower() for h in ("vpn", "wireguard")):
            return SEV_VPN, "Only that you use a VPN to this server + volume"
        if self.url or key in PLAINTEXT_PORTS:
            return SEV_PLAIN, "EVERYTHING - unencrypted (full URLs, content)"
        if self.rport == 53:
            return SEV_PLAIN, "Every domain name you look up (plaintext DNS)"
        if key in VPN_PORTS:
            return SEV_VPN, "That you use a VPN + traffic volume; contents hidden"
        if self.rport == 853:
            return SEV_OPAQUE, "Encrypted DNS - only the resolver's IP"
        if self.host_src == "SNI":
            return SEV_DOMAIN, "Website name (TLS SNI) + volume; content encrypted"
        if self.host_src == "QUIC":
            return SEV_DOMAIN, "Website name (QUIC Initial) + volume; content encrypted"
        if self.host_src == "DNS":
            return SEV_DOMAIN, "Server IP; domain inferable from your DNS lookup"
        return SEV_OPAQUE, "Only server IP, port, packet sizes & timing"


class State:
    def __init__(self, ifaces):
        self.ifaces = ifaces
        self.lock = threading.Lock()
        self.flows = {}
        self.dns_ip = {}            # ip -> domain (from observed DNS answers)
        self.dns_log = deque(maxlen=2000)
        self.dns_seq = 0
        self.pkts = deque(maxlen=400)
        self.pkt_seq = 0
        self.cap_out = self.cap_in = self.cap_pout = self.cap_pin = 0
        self.port_proc = {}         # (proto, lport) -> process name
        self.tcp_pending = {}       # partial TLS ClientHellos
        self.quic_pending = {}      # dcid -> {offset: data}
        self.paused = False
        self.errors = []

    def clear(self):
        with self.lock:
            self.flows.clear()
            self.dns_log.clear()
            self.pkts.clear()
            self.cap_out = self.cap_in = self.cap_pout = self.cap_pin = 0

    # ---- per-packet processing (sniffer thread) ----
    def handle(self, d, ifc):
        if self.paused or len(d) < 20 or (d[0] >> 4) != 4:
            return
        ihl = (d[0] & 0x0F) * 4
        total = struct.unpack("!H", d[2:4])[0]
        proto_n = d[9]
        src = socket.inet_ntoa(d[12:16])
        dst = socket.inet_ntoa(d[16:20])
        frag_off = struct.unpack("!H", d[6:8])[0] & 0x1FFF
        size = len(d)
        payload = d[ihl:total] if ihl <= total <= len(d) else d[ihl:]

        outgoing = src == ifc.ip
        remote = dst if outgoing else src

        sport = dport = 0
        info = ""
        if proto_n == 6 and frag_off == 0 and len(payload) >= 20:
            proto = "TCP"
            sport, dport = struct.unpack("!HH", payload[:4])
            doff = (payload[12] >> 4) * 4
            flags = payload[13]
            data = payload[doff:]
            fl = "".join(c for c, bit in (("S", 2), ("A", 16), ("F", 1), ("R", 4), ("P", 8))
                         if flags & bit)
            info = f"[{fl}] {len(data)} B" if data else f"[{fl}]"
        elif proto_n == 17 and frag_off == 0 and len(payload) >= 8:
            proto = "UDP"
            sport, dport = struct.unpack("!HH", payload[:4])
            data = payload[8:]
            info = f"{len(data)} B"
        elif proto_n == 1:
            proto, data = "ICMP", b""
            info = "ping" if payload[:1] in (b"\x08", b"\x00") else "icmp"
        else:
            proto, data = f"IP/{proto_n}", b""

        lport, rport = (sport, dport) if outgoing else (dport, sport)
        key = (ifc.name, proto, remote, rport)

        with self.lock:
            fl_ = self.flows.get(key)
            if fl_ is None:
                fl_ = self.flows[key] = Flow(proto, remote, rport, lport, ifc)
                fl_.proc = self.port_proc.get((proto, lport), "")
                h = self.dns_ip.get(remote)
                if h:
                    fl_.host, fl_.host_src = h, "DNS"
            fl_.last = time.time()
            fl_.dirty = True
            if outgoing:
                fl_.b_out += size
                fl_.p_out += 1
                self.cap_out += size
                self.cap_pout += 1
            else:
                fl_.b_in += size
                fl_.p_in += 1
                self.cap_in += size
                self.cap_pin += 1
            if not fl_.proc:
                fl_.proc = self.port_proc.get((proto, lport), "")

            # ---- what's readable in the payload ----
            if data:
                if proto == "UDP" and 53 in (sport, dport):
                    info = self._dns(data, remote, outgoing, fl_) or info
                elif proto == "TCP" and outgoing:
                    info = self._tcp_payload(data, (lport, remote, rport), fl_) or info
                elif proto == "UDP" and not ifc.vpn and data[1:4] == b"\x00\x00\x00" and (
                        (data[0] == 1 and len(data) == 148) or
                        (data[0] == 2 and len(data) == 92) or
                        (data[0] == 3 and len(data) == 64) or
                        (data[0] == 4 and len(data) >= 32 and len(data) % 16 == 0)):
                    if not fl_.vpn_proto:
                        fl_.vpn_proto = "WireGuard"
                    info = "WireGuard VPN packet (encrypted)"
                elif proto == "UDP" and outgoing and rport == 443:
                    info = self._quic(data, fl_) or info

            self.pkt_seq += 1
            self.pkts.append((self.pkt_seq, time.time(), "OUT" if outgoing else "IN",
                              proto, ifc.name, f"{remote}:{rport}" if rport else remote, size,
                              (fl_.host + "  " if fl_.host else "") + info,
                              fl_.isp_visible, fl_.tunneled))

    def _dns(self, data, remote, outgoing, fl_):
        r = parse_dns(data)
        if not r:
            return None
        is_resp, qs, ips = r
        if not qs:
            return None
        name, qt = qs[0]
        qtn = DNS_QTYPES.get(qt, str(qt))
        if not is_resp and outgoing:
            self.dns_seq += 1
            self.dns_log.append((self.dns_seq, time.time(), name, qtn, remote, fl_.proc,
                                 fl_.tunneled))
            return f"DNS query {qtn} {name}"
        if is_resp:
            for ip in ips:
                self.dns_ip[ip] = name
                f = self._flow_for_ip(ip)
                for fx in f:
                    if not fx.host:
                        fx.host, fx.host_src, fx.dirty = name, "DNS", True
            return f"DNS answer {name} -> {', '.join(ips[:3]) or '(no A)'}"
        return None

    def _flow_for_ip(self, ip):
        return [f for k, f in self.flows.items() if k[2] == ip]

    def _tcp_payload(self, data, tkey, fl_):
        pend = self.tcp_pending.pop(tkey, None)
        if pend is not None:
            data = pend + data
        if data[:1] == b"\x16" and len(data) >= 9 and data[5] == 1:
            try:
                sni = sni_from_client_hello(data[5:])
            except Truncated:
                if len(data) < 32768:
                    self.tcp_pending[tkey] = bytes(data)
                if len(self.tcp_pending) > 256:
                    self.tcp_pending.clear()
                return "TLS ClientHello (partial)"
            if sni:
                fl_.host, fl_.host_src, fl_.dirty = sni, "SNI", True
                return f"TLS ClientHello SNI={sni}"
            return "TLS ClientHello (no SNI / ECH)"
        if data.startswith(HTTP_METHODS):
            r = parse_http_request(data)
            if r:
                host, line = r
                if host:
                    fl_.host, fl_.host_src = host.split(":")[0], "HTTP"
                fl_.url = line
                return f"PLAINTEXT HTTP: {line}"
        return None

    def _quic(self, data, fl_):
        r = quic_initial_crypto_frames(data)
        if not r:
            return None
        dcid, frames = r
        chunks = self.quic_pending.setdefault(dcid, {})
        for off, d in frames:
            chunks[off] = d
        buf = bytearray()
        while True:
            nxt = None
            for off, d in chunks.items():
                if off <= len(buf) < off + len(d):
                    nxt = d[len(buf) - off:]
                    break
            if nxt is None:
                break
            buf += nxt
        try:
            sni = sni_from_client_hello(bytes(buf)) if len(buf) >= 4 else None
        except Truncated:
            if len(self.quic_pending) > 256:
                self.quic_pending.clear()
            return "QUIC Initial (partial ClientHello)"
        self.quic_pending.pop(dcid, None)
        if sni:
            fl_.host, fl_.host_src, fl_.dirty = sni, "QUIC", True
            return f"QUIC Initial SNI={sni}"
        return "QUIC Initial"


# --------------------------------------------------------------------------
# Background threads
# --------------------------------------------------------------------------

class Sniffer(threading.Thread):
    def __init__(self, state, ifc):
        super().__init__(daemon=True)
        self.state, self.ifc = state, ifc
        self.stop_evt = threading.Event()

    def run(self):
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 * 1024 * 1024)
            s.bind((self.ifc.ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(0.5)
        except OSError as e:
            self.state.errors.append(f"{self.ifc.name}: {e}")
            return
        try:
            while not self.stop_evt.is_set():
                try:
                    d = s.recv(65535)
                except socket.timeout:
                    continue
                except OSError:
                    continue
                try:
                    self.state.handle(d, self.ifc)
                except Exception:
                    pass
        finally:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
            s.close()


class ProcMapper(threading.Thread):
    def __init__(self, state):
        super().__init__(daemon=True)
        self.state = state
        self.names = {}

    def run(self):
        if not psutil:
            return
        while True:
            try:
                m = {}
                for c in psutil.net_connections(kind="inet4"):
                    if not c.laddr or not c.pid:
                        continue
                    name = self.names.get(c.pid)
                    if name is None:
                        try:
                            name = psutil.Process(c.pid).name()
                        except Exception:
                            name = f"pid {c.pid}"
                        self.names[c.pid] = name
                    proto = "TCP" if c.type == socket.SOCK_STREAM else "UDP"
                    m[(proto, c.laddr.port)] = name
                with self.state.lock:
                    self.state.port_proc.update(m)
                    for f in self.state.flows.values():
                        if not f.proc:
                            p = m.get((f.proto, f.lport))
                            if p:
                                f.proc, f.dirty = p, True
                if len(self.names) > 2000:
                    self.names.clear()
            except Exception:
                pass
            time.sleep(1.5)


# --------------------------------------------------------------------------
# GUI
# --------------------------------------------------------------------------

BG, PANEL, FG, MUTED = "#14161b", "#1d2027", "#e6e8ec", "#8b93a3"
ACCENT_UP, ACCENT_DN = "#f0a04b", "#4ba3f0"
SEV_COLORS = {SEV_PLAIN: "#ff6b6b", SEV_DOMAIN: "#f5c04e", SEV_OPAQUE: "#7ad88a",
              SEV_VPN: "#8fb4ff", SEV_LAN: "#6b7280", SEV_HIDDEN: "#b48cf2"}
SEV_ORDER = {SEV_PLAIN: 0, SEV_DOMAIN: 1, SEV_VPN: 2, SEV_OPAQUE: 3, SEV_HIDDEN: 4, SEV_LAN: 5}


class App:
    def __init__(self, root, state):
        self.root, self.state = root, state
        self.wire_ifaces = [i.name for i in state.ifaces if not i.vpn]
        self.vpn_ifaces = [i.name for i in state.ifaces if i.vpn]
        self.hist_up = deque([0] * 90, maxlen=90)
        self.hist_dn = deque([0] * 90, maxlen=90)
        self.last_io = None
        self.last_io_t = time.time()
        self.pkt_seen = 0
        self.dns_seen = 0
        self.sort_col, self.sort_rev = "total", True
        self.hide_lan = tk.BooleanVar(value=True)
        self.show_tunnel = tk.BooleanVar(value=True)
        self.autoscroll = tk.BooleanVar(value=True)
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.refresh_flows(force=True))

        root.title(f"{APP_NAME} - what your ISP can see")
        root.geometry("1320x860")
        root.minsize(900, 560)
        root.configure(bg=BG)
        self._style()
        self._build()
        self.tick()

    # ---- styling ----
    def _style(self):
        st = ttk.Style(self.root)
        st.theme_use("clam")
        st.configure(".", background=BG, foreground=FG, fieldbackground=PANEL,
                     font=("Segoe UI", 10))
        st.configure("TFrame", background=BG)
        st.configure("Panel.TFrame", background=PANEL)
        st.configure("TLabel", background=BG, foreground=FG)
        st.configure("Muted.TLabel", foreground=MUTED)
        st.configure("Panel.TLabel", background=PANEL)
        st.configure("PanelMuted.TLabel", background=PANEL, foreground=MUTED,
                     font=("Segoe UI", 9))
        st.configure("Big.TLabel", background=PANEL, font=("Segoe UI Semibold", 17))
        st.configure("TCheckbutton", background=BG, foreground=FG)
        st.map("TCheckbutton", background=[("active", BG)])
        st.configure("TButton", background=PANEL, foreground=FG, borderwidth=0,
                     padding=(12, 5))
        st.map("TButton", background=[("active", "#2a2e38")])
        st.configure("TEntry", fieldbackground=PANEL, foreground=FG, insertcolor=FG)
        st.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG,
                     rowheight=24, borderwidth=0, font=("Segoe UI", 9))
        st.configure("Treeview.Heading", background="#262a33", foreground=FG,
                     relief="flat", font=("Segoe UI Semibold", 9))
        st.map("Treeview", background=[("selected", "#2f4a6b")])
        st.map("Treeview.Heading", background=[("active", "#30353f")])
        st.configure("TNotebook", background=BG, borderwidth=0)
        st.configure("TNotebook.Tab", background=PANEL, foreground=MUTED, padding=(14, 6))
        st.map("TNotebook.Tab", background=[("selected", "#2a2e38")],
               foreground=[("selected", FG)])

    # ---- layout ----
    def _build(self):
        top = ttk.Frame(self.root, padding=(14, 10, 14, 4))
        top.pack(fill="x")
        ttk.Label(top, text=APP_NAME, font=("Segoe UI Semibold", 15)).pack(side="left")
        self.status = ttk.Label(top, style="Muted.TLabel", text="   Capturing on " +
                                ", ".join(map(repr, self.state.ifaces)))
        self.status.pack(side="left")
        ttk.Button(top, text="Export CSV", command=self.export).pack(side="right", padx=3)
        ttk.Button(top, text="Clear", command=self.clear).pack(side="right", padx=3)
        self.pause_btn = ttk.Button(top, text="Pause", command=self.toggle_pause)
        self.pause_btn.pack(side="right", padx=3)

        if self.vpn_ifaces:
            ban = tk.Label(self.root, bg="#2b2140", fg="#d9c6ff", anchor="w", padx=12, pady=6,
                           font=("Segoe UI", 10), justify="left", wraplength=1200,
                           text=f"\u25cf VPN active ({', '.join(self.vpn_ifaces)}). Your ISP only "
                                f"sees what goes over {', '.join(self.wire_ifaces) or 'the physical adapter'}"
                                f": an encrypted tunnel to the VPN server. Traffic inside the tunnel "
                                f"(purple rows) is hidden from the ISP - but visible to your VPN provider.")
            ban.pack(fill="x", padx=18, pady=(4, 0))

        # stats cards
        cards = ttk.Frame(self.root, padding=(14, 6))
        cards.pack(fill="x")
        self.stat = {}
        for i, (k, label, color) in enumerate([
                ("up", "Upload to ISP now", ACCENT_UP), ("dn", "Download from ISP now", ACCENT_DN),
                ("sent", "Sent (captured)", FG), ("recv", "Received (captured)", FG),
                ("hosts", "Servers contacted", FG), ("leaks", "Domains visible to ISP", "#f5c04e")]):
            f = ttk.Frame(cards, style="Panel.TFrame", padding=(12, 8))
            f.grid(row=0, column=i, sticky="nsew", padx=4)
            cards.columnconfigure(i, weight=1)
            ttk.Label(f, text=label, style="PanelMuted.TLabel").pack(anchor="w")
            lbl = ttk.Label(f, text="-", style="Big.TLabel", foreground=color)
            lbl.pack(anchor="w")
            sub = ttk.Label(f, text="", style="PanelMuted.TLabel")
            sub.pack(anchor="w")
            self.stat[k] = (lbl, sub)

        self.graph = tk.Canvas(self.root, height=70, bg=PANEL, highlightthickness=0)
        self.graph.pack(fill="x", padx=18, pady=(4, 6))

        # toolbar
        bar = ttk.Frame(self.root, padding=(14, 2))
        bar.pack(fill="x")
        ttk.Label(bar, text="Filter:").pack(side="left")
        ttk.Entry(bar, textvariable=self.filter_var, width=34).pack(side="left", padx=6)
        ttk.Checkbutton(bar, text="Hide local-network traffic", variable=self.hide_lan,
                        command=lambda: self.refresh_flows(force=True)).pack(side="left", padx=10)
        if self.vpn_ifaces:
            ttk.Checkbutton(bar, text="Show traffic inside VPN tunnel", variable=self.show_tunnel,
                            command=lambda: self.refresh_flows(force=True)).pack(side="left")
        legend = ttk.Frame(bar)
        legend.pack(side="right")
        for sev, txt in ((SEV_PLAIN, "Fully exposed"), (SEV_DOMAIN, "Domain exposed"),
                         (SEV_VPN, "VPN"), (SEV_OPAQUE, "IP only"),
                         (SEV_HIDDEN, "Hidden (in tunnel)")):
            tk.Label(legend, text="●", fg=SEV_COLORS[sev], bg=BG,
                     font=("Segoe UI", 11)).pack(side="left")
            ttk.Label(legend, text=txt, style="Muted.TLabel").pack(side="left", padx=(0, 10))

        nb = ttk.Notebook(self.root)
        nb.pack(fill="both", expand=True, padx=14, pady=(6, 4))
        self.nb = nb

        # tab 1: connections
        cols = [("host", "Domain / host", 230), ("sees", "What your ISP sees", 330),
                ("ip", "Remote IP", 120), ("svc", "Service", 135), ("proc", "App", 130),
                ("out", "↑ Sent", 80), ("in", "↓ Recv", 80),
                ("pk", "Packets", 70), ("last", "Last seen", 75)]
        self.flow_tree = self._tree(nb, cols, "  Connections (ISP view)  ")
        for sev, c in SEV_COLORS.items():
            self.flow_tree.tag_configure(sev, foreground=c)

        # tab 2: dns
        self.dns_tree = self._tree(nb, [("t", "Time", 90), ("name", "Domain looked up", 340),
                                        ("type", "Type", 65), ("srv", "Sent to resolver", 130),
                                        ("isp", "Visible to ISP?", 210), ("proc", "App", 140)],
                                   "  DNS lookups (plaintext)  ", sortable=False)
        self.dns_tree.tag_configure("vis", foreground=SEV_COLORS[SEV_DOMAIN])
        self.dns_tree.tag_configure("hid", foreground=SEV_COLORS[SEV_HIDDEN])
        # tab 3: live packets
        self.pkt_tree = self._tree(nb, [("t", "Time", 95), ("dir", "Dir", 50),
                                        ("proto", "Proto", 55), ("local", "Adapter", 120),
                                        ("remote", "Remote", 170), ("size", "Size", 65),
                                        ("info", "Visible info", 520)],
                                   "  Live packets  ", sortable=False)
        self.pkt_tree.tag_configure("OUT", foreground=ACCENT_UP)
        self.pkt_tree.tag_configure("IN", foreground=ACCENT_DN)
        self.pkt_tree.tag_configure("leak", foreground="#f5c04e")
        self.pkt_tree.tag_configure("lan", foreground="#6b7280")
        self.pkt_tree.tag_configure("tun", foreground=SEV_COLORS[SEV_HIDDEN])

        # tab 4: summary
        sf = ttk.Frame(nb, style="Panel.TFrame")
        nb.add(sf, text="  Plain-English summary  ")
        self.summary = tk.Text(sf, bg=PANEL, fg=FG, relief="flat", wrap="word",
                               font=("Segoe UI", 10), padx=16, pady=12, insertbackground=FG)
        self.summary.pack(fill="both", expand=True)
        self.summary.tag_configure("h", font=("Segoe UI Semibold", 12), spacing3=4)
        self.summary.tag_configure("red", foreground=SEV_COLORS[SEV_PLAIN])
        self.summary.tag_configure("yel", foreground=SEV_COLORS[SEV_DOMAIN])
        self.summary.tag_configure("grn", foreground=SEV_COLORS[SEV_OPAQUE])
        self.summary.tag_configure("mut", foreground=MUTED)

        foot = ttk.Frame(self.root, padding=(14, 0, 14, 8))
        foot.pack(fill="x")
        ttk.Checkbutton(foot, text="Auto-scroll live packets",
                        variable=self.autoscroll).pack(side="left")
        note = ("IPv4 capture via Windows raw socket. HTTPS contents are encrypted - "
                "your ISP sees who you talk to, when, and how much, not what.")
        if not HAVE_CRYPTO:
            note += "  (QUIC SNI decoding disabled: 'cryptography' not installed)"
        ttk.Label(foot, text=note, style="Muted.TLabel").pack(side="right")

    def _tree(self, nb, cols, title, sortable=True):
        frame = ttk.Frame(nb, style="Panel.TFrame")
        nb.add(frame, text=title)
        tv = ttk.Treeview(frame, columns=[c[0] for c in cols], show="headings")
        for cid, name, w in cols:
            if sortable:
                tv.heading(cid, text=name, anchor="w", command=lambda c=cid: self.sort_by(c))
            else:
                tv.heading(cid, text=name, anchor="w")
            num = cid in ("out", "in", "pk", "size")
            tv.column(cid, width=w, anchor="e" if num else "w", stretch=cid in ("sees", "info", "name", "host"))
        ys = ttk.Scrollbar(frame, orient="vertical", command=tv.yview)
        tv.configure(yscrollcommand=ys.set)
        tv.pack(side="left", fill="both", expand=True)
        ys.pack(side="right", fill="y")
        return tv

    # ---- actions ----
    def toggle_pause(self):
        self.state.paused = not self.state.paused
        self.pause_btn.configure(text="Resume" if self.state.paused else "Pause")

    def clear(self):
        self.state.clear()
        for tv in (self.flow_tree, self.dns_tree, self.pkt_tree):
            tv.delete(*tv.get_children())

    def sort_by(self, col):
        if self.sort_col == col:
            self.sort_rev = not self.sort_rev
        else:
            self.sort_col = col
            self.sort_rev = col in ("out", "in", "pk", "last")
        self.refresh_flows(force=True)

    def export(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")],
                                            initialfile=f"isp_view_{time.strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        with self.state.lock:
            flows = list(self.state.flows.values())
            dns = list(self.state.dns_log)
        with open(path, "w", newline="", encoding="utf-8") as fh:
            w = csv.writer(fh)
            w.writerow(["adapter", "host", "host_source", "what_isp_sees", "remote_ip", "proto",
                        "remote_port", "service", "app", "bytes_sent", "bytes_recv",
                        "packets_sent", "packets_recv", "first_seen", "last_seen", "http_url"])
            for f in flows:
                w.writerow([f.iface, f.host, f.host_src, f.visibility()[1], f.rip, f.proto, f.rport,
                            f.service, f.proc, f.b_out, f.b_in, f.p_out, f.p_in,
                            time.strftime("%H:%M:%S", time.localtime(f.first)),
                            time.strftime("%H:%M:%S", time.localtime(f.last)), f.url])
            w.writerow([])
            w.writerow(["dns_time", "domain", "type", "resolver", "app", "visible_to_isp"])
            for _s, t, n, q, r, p, tun in dns:
                w.writerow([time.strftime("%H:%M:%S", time.localtime(t)), n, q, r, p,
                            "no (inside VPN)" if tun else "yes"])
        messagebox.showinfo(APP_NAME, f"Saved {len(flows)} connections and {len(dns)} DNS lookups.")

    # ---- periodic refresh ----
    def tick(self):
        try:
            if self.state.errors:
                self.status.configure(text="   Capture error: " + "; ".join(self.state.errors),
                                      foreground="#ff6b6b")
            self.update_rates()
            self.refresh_flows()
            self.refresh_dns()
            self.refresh_packets()
            if int(time.time()) % 3 == 0:
                self.refresh_summary()
        finally:
            self.root.after(1000, self.tick)

    def update_rates(self):
        now = time.time()
        io = None
        if psutil and self.wire_ifaces:
            try:
                per = psutil.net_io_counters(pernic=True)
                nics = [per[n] for n in self.wire_ifaces if n in per]
                if nics:
                    io = type("io", (), {"bytes_sent": sum(n.bytes_sent for n in nics),
                                         "bytes_recv": sum(n.bytes_recv for n in nics)})
            except Exception:
                io = None
        if io is not None:
            cur = (io.bytes_sent, io.bytes_recv)
        else:
            cur = (self.state.cap_out, self.state.cap_in)
        if self.last_io is not None:
            dt = max(now - self.last_io_t, 0.001)
            up = max(cur[0] - self.last_io[0], 0) / dt
            dn = max(cur[1] - self.last_io[1], 0) / dt
            self.hist_up.append(up)
            self.hist_dn.append(dn)
            self.stat["up"][0].configure(text=fmt_rate(up))
            self.stat["dn"][0].configure(text=fmt_rate(dn))
            if io is not None:
                self.stat["up"][1].configure(text=f"adapter total {fmt_bytes(io.bytes_sent)}")
                self.stat["dn"][1].configure(text=f"adapter total {fmt_bytes(io.bytes_recv)}")
        self.last_io, self.last_io_t = cur, now

        s = self.state
        self.stat["sent"][0].configure(text=fmt_bytes(s.cap_out))
        self.stat["sent"][1].configure(text=f"{s.cap_pout:,} packets")
        self.stat["recv"][0].configure(text=fmt_bytes(s.cap_in))
        self.stat["recv"][1].configure(text=f"{s.cap_pin:,} packets")
        with s.lock:
            pub = [f for f in s.flows.values() if f.isp_visible]
            ips = {f.rip for f in pub if f.public}
            doms = {f.host for f in pub if f.host and not f.vpn_proto}
            doms |= {e[2] for e in s.dns_log if not e[6]}
        self.stat["hosts"][0].configure(text=f"{len(ips)}")
        self.stat["hosts"][1].configure(text="public IPs the ISP sees")
        self.stat["leaks"][0].configure(text=f"{len(doms)}")
        self.stat["leaks"][1].configure(text="via DNS / SNI / HTTP")
        self.draw_graph()

    def draw_graph(self):
        c = self.graph
        c.delete("all")
        w = max(c.winfo_width(), 100)
        h = 70
        peak = max(max(self.hist_up), max(self.hist_dn), 1024)
        n = len(self.hist_up)
        step = w / (n - 1)
        for series, color in ((self.hist_dn, ACCENT_DN), (self.hist_up, ACCENT_UP)):
            pts = []
            for i, v in enumerate(series):
                pts += [i * step, h - 6 - (v / peak) * (h - 30)]
            c.create_line(*pts, fill=color, width=2, smooth=True)
        c.create_text(8, 8, anchor="nw", fill=MUTED, font=("Segoe UI", 8),
                      text=f"last 90 s   peak {fmt_rate(peak)}   "
                           f"— upload (orange)  — download (blue)")

    def _flow_row(self, f):
        sev, sees = f.visibility()
        host = f.host or ""
        if f.host_src:
            host = f"{host}   [{f.host_src}]"
        if f.url and not f.tunneled:
            sees = f"{sees}  → {f.url}"
        return sev, (host, sees, f.rip, f"{f.service} :{f.rport}" if f.rport else f.service,
                     f.proc, fmt_bytes(f.b_out), fmt_bytes(f.b_in), f.p_out + f.p_in,
                     time.strftime("%H:%M:%S", time.localtime(f.last)))

    def refresh_flows(self, force=False):
        flt = self.filter_var.get().strip().lower()
        hide = self.hide_lan.get()
        tv = self.flow_tree
        with self.state.lock:
            flows = list(self.state.flows.items())
            rows = {}
            for key, f in flows:
                iid = "|".join(map(str, key))
                visible = not (hide and not f.public and f.rport != 53 and not f.tunneled)
                if f.tunneled and not self.show_tunnel.get():
                    visible = False
                if visible and flt:
                    hay = f"{f.host} {f.rip} {f.proc} {f.service} {f.url}".lower()
                    visible = flt in hay
                rows[iid] = (f, visible, f.dirty or force)
                f.dirty = False
            snapshot = {iid: (f, vis, self._flow_row(f) if (chg and vis) else None,
                              f.b_out + f.b_in, f.p_out + f.p_in, f.last, f.visibility()[0])
                        for iid, (f, vis, chg) in rows.items()}
        existing = set(tv.get_children())
        for iid, (f, vis, row, *_rest) in snapshot.items():
            if not vis:
                if iid in existing:
                    tv.delete(iid)
                continue
            if iid not in existing:
                sev, vals = row or self._flow_row(f)
                tv.insert("", "end", iid=iid, values=vals, tags=(sev,))
            elif row:
                sev, vals = row
                tv.item(iid, values=vals, tags=(sev,))
        for iid in existing - snapshot.keys():
            tv.delete(iid)

        col = self.sort_col
        def keyf(iid):
            f, _v, _r, total, pk, last, sev = snapshot[iid]
            return {"total": total, "out": f.b_out, "in": f.b_in, "pk": pk, "last": last,
                    "host": (f.host or "~").lower(), "ip": tuple(int(x) for x in f.rip.split(".")),
                    "svc": f.service, "proc": f.proc.lower(),
                    "sees": SEV_ORDER[sev]}.get(col, total)
        kids = [i for i in tv.get_children() if i in snapshot]
        try:
            kids.sort(key=keyf, reverse=self.sort_rev)
        except Exception:
            return
        for idx, iid in enumerate(kids):
            if tv.index(iid) != idx:
                tv.move(iid, "", idx)

    def refresh_dns(self):
        with self.state.lock:
            new = [e for e in self.state.dns_log if e[0] > self.dns_seen]
        for seq, t, name, qt, srv, proc, tun in new:
            isp = "No - sent inside VPN tunnel" if tun else "YES - plaintext on the wire"
            self.dns_tree.insert("", 0, values=(time.strftime("%H:%M:%S", time.localtime(t)),
                                                name, qt, srv, isp, proc),
                                 tags=("hid" if tun else "vis",))
            self.dns_seen = seq
        kids = self.dns_tree.get_children()
        if len(kids) > 2000:
            self.dns_tree.delete(*kids[2000:])

    def refresh_packets(self):
        with self.state.lock:
            new = [p for p in self.state.pkts if p[0] > self.pkt_seen]
        if len(new) > 300:
            new = new[-300:]
        tv = self.pkt_tree
        hide = self.hide_lan.get()
        show_tun = self.show_tunnel.get()
        for seq, t, d, proto, loc, rem, size, info, public, tun in new:
            self.pkt_seen = seq
            if (tun and not show_tun) or (hide and not public and not tun):
                continue
            tag = d
            if tun:
                tag = "tun"
            elif not public:
                tag = "lan"
            elif "SNI=" in info or "DNS query" in info or "PLAINTEXT" in info:
                tag = "leak"
            tv.insert("", "end", values=(time.strftime("%H:%M:%S", time.localtime(t)) +
                                         f".{int((t % 1) * 1000):03d}",
                                         d, proto, loc, rem, size, info), tags=(tag,))
        kids = tv.get_children()
        if len(kids) > 600:
            tv.delete(*kids[:len(kids) - 600])
        if self.autoscroll.get() and new:
            kids = tv.get_children()
            if kids:
                tv.see(kids[-1])

    def refresh_summary(self):
        with self.state.lock:
            allf = list(self.state.flows.values())
            wire_dns = [e for e in self.state.dns_log if not e[6]]
            tun_dns = [e for e in self.state.dns_log if e[6]]
        flows = [f for f in allf if f.isp_visible]
        tunneled = [f for f in allf if f.tunneled and f.public]
        ndns = len(wire_dns)
        dns_domains = {e[2] for e in wire_dns}
        resolvers = {e[4] for e in wire_dns}
        by_sev = {}
        for f in flows:
            by_sev.setdefault(f.visibility()[0], []).append(f)
        doms = {}
        for f in flows:
            if f.host and not f.vpn_proto:
                doms[f.host] = doms.get(f.host, 0) + f.b_in + f.b_out
        total = sum(f.b_in + f.b_out for f in flows)

        t = self.summary
        y = t.yview()[0]
        t.configure(state="normal")
        t.delete("1.0", "end")
        t.insert("end", "What your ISP can see right now\n", "h")
        t.insert("end", f"Since capture started: {len(flows)} connections to "
                        f"{len({f.rip for f in flows})} servers, {fmt_bytes(total)} on the wire.\n\n")

        if self.vpn_ifaces:
            vb = sum(f.b_in + f.b_out for f in tunneled)
            t.insert("end", "VPN is on\n", "h")
            t.insert("end", f"\u2022 {len(tunneled)} connections ({fmt_bytes(vb)}) and "
                            f"{len(tun_dns)} DNS lookups went through the VPN tunnel. Your ISP can't "
                            "see any of them - only the encrypted tunnel to the VPN server.\n", "grn")
            t.insert("end", "\u2022 Your VPN provider now sees what your ISP would have seen "
                            "(purple rows).\n", "mut")
            t.insert("end", "\u2022 Anything listed below is traffic that bypasses the tunnel "
                            "(split tunnelling, VPN server connection, local network).\n\n")

        t.insert("end", "Always visible (for every packet)\n", "h")
        t.insert("end", "• Your public IP and the IP of every server you talk to\n"
                        "• Ports / protocol (reveals the kind of service: web, VPN, SSH, games...)\n"
                        "• When you are online, how much data you move, and traffic patterns "
                        "(enough to guess e.g. video streaming vs browsing)\n\n")

        t.insert("end", "Domain names leaked\n", "h")
        if ndns:
            t.insert("end", f"• {ndns} plaintext DNS lookups for {len(dns_domains)} domains "
                            f"(resolver{'s' if len(resolvers) > 1 else ''}: "
                            f"{', '.join(sorted(resolvers)[:4])}). ", "yel")
            t.insert("end", "If the resolver is your router or ISP, they log every name.\n")
        else:
            t.insert("end", "\u2022 No plaintext DNS reaching the ISP - lookups are encrypted "
                            "(DoH/DoT/VPN), or nothing has been looked up yet.\n", "grn")
        sni = [f for f in flows if f.host_src in ("SNI", "QUIC")]
        if sni:
            t.insert("end", f"• {len({f.host for f in sni})} website names read straight out of "
                            f"HTTPS/QUIC handshakes (SNI) - visible even with encrypted DNS.\n", "yel")
        plain = by_sev.get(SEV_PLAIN, [])
        http = [f for f in plain if f.url]
        if http:
            t.insert("end", f"• {len(http)} UNENCRYPTED HTTP connections - full URL and page "
                            "content readable:\n", "red")
            for f in http[:8]:
                t.insert("end", f"     {f.url}\n", "red")
        vpn = by_sev.get(SEV_VPN, [])
        if vpn:
            t.insert("end", f"• VPN traffic detected to {', '.join(sorted({f.rip for f in vpn})[:3])}: "
                            "your ISP sees the tunnel but not what's inside.\n", "grn")
        t.insert("end", "\n")

        t.insert("end", "Top domains by traffic (as the ISP would see them)\n", "h")
        for host, b in sorted(doms.items(), key=lambda kv: -kv[1])[:15]:
            t.insert("end", f"  {fmt_bytes(b):>10}   {host}\n")
        if not doms:
            t.insert("end", "  (nothing yet - browse somewhere)\n", "mut")
        t.insert("end", "\n")

        t.insert("end", "Hidden from your ISP\n", "h")
        t.insert("end", "• Contents of HTTPS / QUIC traffic: page paths, search terms, messages, "
                        "passwords, cookies\n"
                        "• Anything inside a VPN tunnel (they only see the VPN server)\n"
                        "• Traffic that stays on your local network\n", "grn")
        t.insert("end", "\nTip: enabling encrypted DNS hides lookups, ECH (Encrypted Client Hello) "
                        "hides SNI where supported, and a VPN hides everything except the fact "
                        "you use one.\n", "mut")
        t.configure(state="disabled")
        t.yview_moveto(y)


# --------------------------------------------------------------------------

def main():
    if os.name != "nt":
        print("This app is Windows-only.")
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    if not is_admin():
        if relaunch_as_admin():
            return
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(APP_NAME, "Administrator rights are required to capture packets.")
        return
    try:
        ifaces = capture_interfaces()
    except OSError:
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(APP_NAME, "No network connection found.")
        return

    state = State(ifaces)
    for ifc in ifaces:
        Sniffer(state, ifc).start()
    ProcMapper(state).start()
    root = tk.Tk()
    App(root, state)
    root.mainloop()


if __name__ == "__main__":
    main()
