"""pxdns: carry UDP DNS over a TCP-only path.

Runs inside a proxy egress's network namespace. The host's per-egress resolver
asks its upstream over UDP, as it would through any tunnel; the namespace
redirects that here; this asks the same upstream over TCP, which the namespace
redirects into the relay and so through the proxy. Nothing leaves the
namespace as UDP - a SOCKS5 or HTTP proxy would not carry it - and the answer
comes from where the egress's traffic exits, not from the entry tunnel.

Deliberately small and dependency-free: standard library only, nothing from
vpngw, no per-query logging. If no upstream answers, the requester gets
nothing and times out. There is never a second path to try.
"""

from __future__ import annotations

import json
import socket
import struct
import sys
import threading

TCP_TIMEOUT = 5.0
MAX_INFLIGHT = 64          # a burst of queries must not become a burst of threads
DEFAULT_UDP_LIMIT = 512    # RFC 1035, when the query carries no EDNS(0)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed mid-message")
        buf += chunk
    return buf


def ask_tcp(server: str, query: bytes, timeout: float = TCP_TIMEOUT) -> bytes:
    """One query over TCP with RFC 1035 length framing."""
    with socket.create_connection((server, 53), timeout=timeout) as s:
        s.sendall(struct.pack("!H", len(query)) + query)
        (length,) = struct.unpack("!H", _recv_exact(s, 2))
        return _recv_exact(s, length)


def _skip_name(msg: bytes, off: int) -> int:
    while True:
        if off >= len(msg):
            raise ValueError("name runs past the message")
        n = msg[off]
        if n == 0:
            return off + 1
        if n & 0xC0 == 0xC0:          # compression pointer ends the name
            return off + 2
        off += 1 + n


def question_end(msg: bytes) -> int:
    """Offset just past the question section."""
    (qdcount,) = struct.unpack("!H", msg[4:6])
    off = 12
    for _ in range(qdcount):
        off = _skip_name(msg, off) + 4
    return off


def udp_limit(query: bytes) -> int:
    """The largest UDP answer the requester said it accepts (EDNS(0) OPT)."""
    try:
        an, ns, ar = struct.unpack("!HHH", query[6:12])
        off = question_end(query)
        for _ in range(an + ns):
            off = _skip_name(query, off)
            (rdlen,) = struct.unpack("!H", query[off + 8:off + 10])
            off += 10 + rdlen
        for _ in range(ar):
            off = _skip_name(query, off)
            rtype, rclass = struct.unpack("!HH", query[off:off + 4])
            if rtype == 41:            # OPT: CLASS holds the payload size
                return max(DEFAULT_UDP_LIMIT, rclass)
            (rdlen,) = struct.unpack("!H", query[off + 8:off + 10])
            off += 10 + rdlen
    except (ValueError, struct.error, IndexError):
        pass
    return DEFAULT_UDP_LIMIT


def truncated(reply: bytes) -> bytes:
    """The reply's header and question, with TC set and nothing else.

    The requester then retries over TCP, which the namespace sends straight
    into the relay - so a large answer still arrives, by the same path.
    """
    end = question_end(reply)
    (flags,) = struct.unpack("!H", reply[2:4])
    header = reply[:2] + struct.pack("!H", flags | 0x0200) + reply[4:6] + b"\0" * 6
    return header + reply[12:end]


def answer(sock: socket.socket, query: bytes, addr, upstreams: list[str],
           gate: threading.Semaphore) -> None:
    try:
        reply = None
        for server in upstreams:
            try:
                reply = ask_tcp(server, query)
                break
            except OSError:
                continue
        if reply is None:
            return
        if len(reply) > udp_limit(query):
            reply = truncated(reply)
        sock.sendto(reply, addr)
    except (OSError, ValueError, struct.error):
        pass
    finally:
        gate.release()


def serve(port: int, upstreams: list[str]) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    gate = threading.Semaphore(MAX_INFLIGHT)
    while True:
        query, addr = sock.recvfrom(4096)
        if len(query) < 12:
            continue
        if not gate.acquire(blocking=False):
            continue                   # shed load; the requester retries
        threading.Thread(target=answer, args=(sock, query, addr, upstreams, gate),
                         daemon=True).start()


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m vpngw.pxdns CONFIG.json", file=sys.stderr)
        return 2
    with open(argv[1], encoding="utf-8") as fh:
        conf = json.load(fh)
    upstreams = [u for u in conf.get("upstreams", []) if ":" not in u]
    if not upstreams:
        print("pxdns: no IPv4 upstream configured", file=sys.stderr)
        return 1
    serve(int(conf.get("port", 5353)), upstreams)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
