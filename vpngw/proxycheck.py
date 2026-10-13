"""proxycheck: ask a proxy, one step at a time, whether it will carry a connection.

Run inside a proxy egress's namespace, where the only way out is TCP to the
proxy server. It speaks the proxy's protocol itself rather than going through
redsocks, because redsocks answers every failure the same way - it closes the
client's connection - and "it doesn't work" is not something an operator can
fix. This tells the steps apart:

  connect   the proxy server did not answer at all
  auth      it answered, and refused the login
  tunnel    it accepted the login, and refused to connect onward
  ok        it would carry a connection

Reads one JSON object on stdin - never the command line, which every local
account can read in ps - and prints one JSON object. Standard library only.
"""

from __future__ import annotations

import base64
import json
import socket
import struct
import sys

TIMEOUT = 8.0

SOCKS_REPLIES = {
    1: "general failure",
    2: "not allowed by the proxy's rules",
    3: "network unreachable from the proxy",
    4: "host unreachable from the proxy",
    5: "connection refused at the destination",
    6: "TTL expired",
    7: "command not supported",
    8: "address type not supported",
}


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise OSError("the proxy closed the connection")
        buf += chunk
    return buf


def _result(stage: str, ok: bool, detail: str = "") -> dict:
    return {"stage": stage, "ok": ok, "detail": detail}


def socks5(s: socket.socket, user: str, password: str,
           host: str, port: int) -> dict:
    # Offer exactly the method this login uses, so a server that would accept
    # no authentication cannot quietly pass a check of the password.
    method = 0x02 if user else 0x00
    s.sendall(bytes([5, 1, method]))
    ver, chosen = _recv_exact(s, 2)
    if ver != 5:
        return _result("connect", False, "the server is not a SOCKS5 proxy")
    if chosen == 0xFF:
        # Offered no login and refused: it wants one. Offered a login and
        # refused: it takes none - typically a proxy that admits callers by
        # address instead. Two different fixes, so two different answers.
        return _result("auth", False,
                       "refuses a username and password" if user else "needs a login")
    if chosen == 0x02:
        u, p = user.encode(), password.encode()
        s.sendall(bytes([1, len(u)]) + u + bytes([len(p)]) + p)
        _, status = _recv_exact(s, 2)
        if status != 0:
            return _result("auth", False, "login rejected")
    elif chosen != 0x00:
        return _result("auth", False, f"unsupported login method {chosen}")

    s.sendall(bytes([5, 1, 0, 1]) + socket.inet_aton(host) + struct.pack("!H", port))
    ver, rep, _, atyp = _recv_exact(s, 4)
    if rep != 0:
        return _result("tunnel", False, SOCKS_REPLIES.get(rep, f"error {rep}"))
    # Drain the bound address so the reply is fully read.
    if atyp == 1:
        _recv_exact(s, 4 + 2)
    elif atyp == 3:
        _recv_exact(s, _recv_exact(s, 1)[0] + 2)
    elif atyp == 4:
        _recv_exact(s, 16 + 2)
    return _result("ok", True)


def http_connect(s: socket.socket, user: str, password: str,
                 host: str, port: int) -> dict:
    lines = [f"CONNECT {host}:{port} HTTP/1.1", f"Host: {host}:{port}"]
    if user:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {token}")
    s.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
    head = b""
    while b"\r\n\r\n" not in head and len(head) < 8192:
        chunk = s.recv(1024)
        if not chunk:
            break
        head += chunk
    status = head.split(b"\r\n", 1)[0].decode(errors="replace").split()
    if len(status) < 2 or not status[1].isdigit():
        return _result("connect", False, "the server is not an HTTP proxy")
    code = int(status[1])
    if code == 407:
        return _result("auth", False, "login rejected" if user else "needs a login")
    if 200 <= code < 300:
        return _result("ok", True)
    return _result("tunnel", False, f"the proxy answered {code}")


def check(conf: dict) -> dict:
    server, port = conf["server"], int(conf["port"])
    user, password = conf.get("username", ""), conf.get("password", "")
    host = conf.get("target_host", "1.1.1.1")
    tport = int(conf.get("target_port", 443))
    try:
        s = socket.create_connection((server, port), timeout=TIMEOUT)
    except OSError as exc:
        return _result("connect", False, str(exc))
    with s:
        s.settimeout(TIMEOUT)
        try:
            if conf["type"] == "socks5":
                return socks5(s, user, password, host, tport)
            return http_connect(s, user, password, host, tport)
        except (OSError, ValueError) as exc:
            # Mid-conversation: it answered, so this is no longer "connect".
            return _result("tunnel", False, str(exc))


def main() -> int:
    try:
        conf = json.load(sys.stdin)
    except ValueError:
        print(json.dumps(_result("connect", False, "bad input")))
        return 2
    print(json.dumps(check(conf)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
