"""Proxy egress: a SOCKS5 or HTTP CONNECT proxy, relayed in its own namespace.

The relay does not run on the gateway. Each proxy egress gets a network
namespace, vpngw-px-<slug>, joined to the host by one veth: px-<slug> on the
host, px0 inside. redsocks runs inside, unprivileged. To the host, a client's
connection is forwarded traffic into px-<slug>, and the relay's connection to
its proxy server is forwarded traffic out of it - so both cross the forward
chain, and the existing kill switch applies to them unchanged.

That is the whole point of the namespace. A relay on the host, the way
OpenWrt's transparent-proxy plugins work, would make the relay's upstream the
gateway's *own* traffic: governed by the output chain, opened by a maintenance
window, invisible to every forward counter, and confined only if the relay's
sockets behave. In here it has two interfaces, lo and px0, and nothing it
sends can reach anything except back through the forward chain into its entry
tunnel, and only to its one server.

Inside the namespace:

- every TCP connection arriving on px0 is redirected to redsocks, which reads
  the original destination and asks the proxy to connect there;
- UDP DNS from the host's per-egress resolver is redirected to pxdns, which
  asks the same upstream over TCP - redirected into redsocks in turn - so
  lookups exit where the traffic exits;
- the only thing allowed out of px0 is TCP to the proxy server's address and
  port. Forwarding is off; IPv6 is off.

The credentials never appear on a command line or in a log. They are read
from the 0600 secrets file and handed to redsocks as a systemd credential.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import string
import time
from pathlib import Path

from .. import config
from ..models import Tunnel, TunnelKind, ValidationError
from ..net.shell import CommandError, run, try_run
from .base import LinkInfo, TunnelDriver, link_exists, link_state

log = logging.getLogger("vpngw.proxy")

#: Run a command in the host's mount namespace.
#:
#: The daemon runs sandboxed (ProtectHome, ProtectControlGroups), and systemd
#: implements that with a private mount namespace. `ip netns add` works by
#: bind-mounting the new namespace onto /run/netns/<name> - and done from in
#: here, that mount stays in here. The daemon could use the namespace; the
#: relay units, started by systemd from the host, saw an empty file and failed
#: with "Failed to open network namespace path ... Invalid argument". Made in
#: the host's namespace instead, the mount propagates into the daemon's too,
#: because a service's mount namespace follows the host's.
HOST_MOUNTS = ["nsenter", "--mount=/proc/1/ns/mnt", "--"]

RELAY_UNIT = "vpngw-proxy@{slug}.service"
DNS_UNIT = "vpngw-pxdns@{slug}.service"
NS_IFACE = "px0"
NS_TABLE = "vpngw_px"
LISTEN_TIMEOUT = 10
PROBE_URL = "https://1.1.1.1/cdn-cgi/trace"
# The probe runs inside the reconcile loop. A dead proxy must not hold that
# loop - and so every other tunnel's failover - for longer than this.
PROBE_TIMEOUT = 5
#: How long a diagnosis of a failing proxy is reused before asking again.
DIAGNOSIS_TTL = 60
_diagnoses: dict[str, tuple[float, dict]] = {}


def last_stage(slug: str) -> str:
    """The step the last diagnosis of a proxy found broken, or "".

    For the panel, so it can offer the fix that matches - a new login, a new
    address - without running a test of its own to find out which.
    """
    cached = _diagnoses.get(slug)
    return str(cached[1].get("stage") or "") if cached else ""

#: Characters redsocks can carry inside a quoted config string. Its format has
#: no escaping, so a quote, backslash, semicolon or line break could end the
#: string early and start a directive of the caller's choosing. Refusing them
#: is cheaper than an escaping scheme nobody can verify against redsocks's
#: parser, and residential proxy credentials do not use them.
CRED_CHARS = frozenset(string.ascii_letters + string.digits
                       + "._~!@#$%^&*()+=,:/?[]{}|<>'-")
CRED_MAX = 255


# ---------------------------------------------------------------------------
# credentials
# ---------------------------------------------------------------------------

def credentials_path(slug: str) -> Path:
    return config.SECRETS_DIR / f"{slug}.proxy"


def validate_credentials(username: str, password: str) -> None:
    """Refuse what redsocks cannot carry safely. Never echoes the values."""
    if bool(username) != bool(password):
        raise ValidationError(
            "give both a username and a password, or neither")
    for label, value in (("username", username), ("password", password)):
        if len(value) > CRED_MAX:
            raise ValidationError(f"the {label} is longer than {CRED_MAX} characters")
        if not set(value) <= CRED_CHARS:
            raise ValidationError(
                f"the {label} contains a character the relay cannot carry "
                f"safely. Quotes, backslashes, semicolons and spaces are not "
                f"supported.")


def write_credentials(slug: str, username: str, password: str) -> None:
    validate_credentials(username, password)
    path = credentials_path(slug)
    if not username:
        path.unlink(missing_ok=True)
        return
    config.write_secret(path, json.dumps({"username": username,
                                          "password": password}))


def read_credentials(slug: str) -> tuple[str, str]:
    path = credentials_path(slug)
    if not path.exists():
        return "", ""
    data = json.loads(path.read_text())
    return data.get("username", ""), data.get("password", "")


# ---------------------------------------------------------------------------
# rendering
# ---------------------------------------------------------------------------

def server_of(t: Tunnel) -> str:
    """The one address the relay dials. Sorted, so it is stable across passes."""
    return sorted(t.endpoints)[0]


def render_namespace_ruleset(t: Tunnel) -> str:
    """The namespace's whole ruleset. Loaded as one transaction."""
    server, port = server_of(t), int(t.proxy["port"])
    relay, dns = config.PROXY_RELAY_PORT, config.PROXY_DNS_PORT
    return f"""\
flush ruleset

table inet {NS_TABLE} {{
    # Clients' connections, and the host resolver's TCP: into the relay.
    # The host resolver's UDP: into pxdns, which turns it into TCP.
    chain pre_nat {{
        type nat hook prerouting priority dstnat; policy accept;
        iifname "{NS_IFACE}" meta l4proto tcp redirect to :{relay}
        iifname "{NS_IFACE}" udp dport 53 redirect to :{dns}
    }}

    # What starts inside - pxdns's TCP to its upstream, the health probe -
    # goes into the relay too. The relay's own connection to its server is
    # the single exception, or it would be redirected into itself.
    chain out_nat {{
        type nat hook output priority dstnat; policy accept;
        ip daddr {server} tcp dport {port} return
        meta l4proto tcp ip daddr != 127.0.0.0/8 redirect to :{relay}
    }}

    chain input {{
        type filter hook input priority filter; policy drop;
        iif lo accept
        ct state established,related accept
        iifname "{NS_IFACE}" ct status dnat tcp dport {relay} accept
        iifname "{NS_IFACE}" ct status dnat udp dport {dns} accept
    }}

    chain forward {{
        type filter hook forward priority filter; policy drop;
    }}

    # One way out: TCP to the proxy server. The host enforces the same with
    # px_upstream, and does not rely on this.
    chain output {{
        type filter hook output priority filter; policy drop;
        oif lo accept
        ct state established,related accept
        oifname "{NS_IFACE}" ip daddr {server} tcp dport {port} accept
    }}
}}
"""


def render_redsocks(t: Tunnel, username: str, password: str) -> str:
    validate_credentials(username, password)
    kind = {"socks5": "socks5", "http": "http-connect"}[t.proxy["type"]]
    lines = [
        "base {",
        # log_info would record every connection's destination. A privacy
        # gateway keeps no such list.
        "    log_debug = off;",
        "    log_info = off;",
        '    log = "stderr";',
        "    daemon = off;",
        "    redirector = iptables;",
        "}",
        "redsocks {",
        "    local_ip = 0.0.0.0;",
        f"    local_port = {config.PROXY_RELAY_PORT};",
        f"    ip = {server_of(t)};",
        f"    port = {int(t.proxy['port'])};",
        f"    type = {kind};",
    ]
    if username:
        lines += [f'    login = "{username}";', f'    password = "{password}";']
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_pxdns(upstreams: list[str]) -> str:
    return json.dumps({"port": config.PROXY_DNS_PORT,
                       "upstreams": list(upstreams)}) + "\n"


def netns_del(name: str) -> None:
    """Remove a named namespace - mount and file - from the host's view."""
    try_run(HOST_MOUNTS + ["ip", "netns", "del", name])
    # ip netns del leaves a file that never had a namespace on it.
    try_run(HOST_MOUNTS + ["rm", "-f", f"/run/netns/{name}"])


# ---------------------------------------------------------------------------
# driver
# ---------------------------------------------------------------------------

class ProxyDriver(TunnelDriver):
    kind = TunnelKind.PROXY
    #: Seconds between HTTP probes once the egress is UP. Each costs a TLS
    #: handshake through a proxy that is often billed by the byte.
    probe_interval = 30

    @staticmethod
    def _runtime(t: Tunnel) -> Path:
        return config.PROXY_RUNTIME / t.slug

    @staticmethod
    def _ns(t: Tunnel, *argv: str, **kw):
        return run(["ip", "netns", "exec", t.netns, *argv], **kw)

    @staticmethod
    def _netns_ready(name: str) -> bool:
        """A real namespace, not just a file where one should be."""
        return os.path.ismount(Path("/run/netns", name))

    def _netns_add(self, name: str) -> None:
        if self._netns_ready(name):
            return
        # A file with no namespace mounted on it - left by a failed attempt -
        # would make `ip netns add` refuse with "File exists". Clear it first.
        if Path("/run/netns", name).exists():
            netns_del(name)
        run(HOST_MOUNTS + ["ip", "netns", "add", name])

    def _upstreams(self, t: Tunnel) -> list[str]:
        # The same list the egress's dnsmasq asks, so the two agree on where
        # a lookup goes; pxdns cannot see which upstream dnsmasq picked.
        ups = [d for d in (t.dns or []) if ":" not in d]
        return ups or list(config.Settings.load().dns.fallback_upstream)

    def _write_runtime(self, t: Tunnel, username: str, password: str) -> None:
        d = self._runtime(t)
        d.mkdir(parents=True, exist_ok=True)
        os.chmod(d, stat.S_IRWXU)
        for name, text in (("redsocks.conf", render_redsocks(t, username, password)),
                           ("pxdns.json", render_pxdns(self._upstreams(t)))):
            fd = os.open(d / name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                fh.write(text)

    def _wait_listening(self, t: Tunnel) -> bool:
        deadline = time.time() + LISTEN_TIMEOUT
        while time.time() < deadline:
            res = try_run(["ip", "netns", "exec", t.netns, "ss", "-Hltn",
                           f"sport = :{config.PROXY_RELAY_PORT}"])
            if res.ok and res.stdout.strip():
                return True
            time.sleep(0.5)
        return False

    # -- lifecycle ----------------------------------------------------------

    def up(self, t: Tunnel) -> LinkInfo:
        if not t.endpoints:
            raise RuntimeError(
                f"the proxy server {t.proxy.get('host')} has not been resolved "
                f"through {t.via} yet. Not bringing it up: there is nowhere "
                f"for the relay to go. It comes up by itself once {t.via} can "
                f"answer")
        username, password = read_credentials(t.slug)
        host_ip, ns_ip = config.proxy_link(t.esid)

        # 1. The namespace, sealed before it has any way out: its ruleset is
        #    loaded while lo is its only interface.
        self._netns_add(t.netns)
        self._ns(t, "sysctl", "-qw", "net.ipv4.ip_forward=0")
        self._ns(t, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
        self._ns(t, "sysctl", "-qw", "net.ipv6.conf.default.disable_ipv6=1")
        ruleset = render_namespace_ruleset(t)
        self._ns(t, "nft", "-c", "-f", "-", input_text=ruleset)
        self._ns(t, "nft", "-f", "-", input_text=ruleset)
        self._ns(t, "ip", "link", "set", "lo", "up")

        # 2. The veth. Its table holds only the blackhole until steering
        #    installs the route, after the health probe passes.
        if not link_exists(t.iface):
            run(["ip", "link", "add", t.iface, "type", "veth",
                 "peer", "name", NS_IFACE, "netns", t.netns])
        try_run(["sysctl", "-qw", f"net.ipv6.conf.{t.iface}.disable_ipv6=1"])
        run(["ip", "addr", "replace", f"{host_ip}/30", "dev", t.iface])
        run(["ip", "link", "set", t.iface, "up"])
        self._ns(t, "ip", "addr", "replace", f"{ns_ip}/30", "dev", NS_IFACE)
        self._ns(t, "ip", "link", "set", NS_IFACE, "up")
        self._ns(t, "ip", "route", "replace", "default", "via", host_ip,
                 "dev", NS_IFACE)

        # 3. The relay and the resolver.
        self._write_runtime(t, username, password)
        run(["systemctl", "restart", RELAY_UNIT.format(slug=t.slug),
             DNS_UNIT.format(slug=t.slug)])
        if not self._wait_listening(t):
            log.warning("%s: relay not listening after %ds", t.slug, LISTEN_TIMEOUT)
        log.info("proxy %s up (%s %s:%s via %s)", t.slug, t.proxy["type"],
                 server_of(t), t.proxy["port"], t.via)
        return self.state(t)

    def down(self, t: Tunnel) -> None:
        # The interface first: the kernel withdraws the route with it and the
        # policy table's blackhole answers, before anything else is touched.
        try_run(["ip", "link", "del", "dev", t.iface])
        try_run(["systemctl", "stop", DNS_UNIT.format(slug=t.slug),
                 RELAY_UNIT.format(slug=t.slug)])
        netns_del(t.netns)
        shutil.rmtree(self._runtime(t), ignore_errors=True)

    def state(self, t: Tunnel) -> LinkInfo:
        info = link_state(t.iface)
        if info.exists:
            # The next hop for this egress's table: a veth is not
            # point-to-point, so the far end has to be named.
            info.gateway = config.proxy_link(t.esid)[1]
        return info

    def healthy_hint(self, t: Tunnel) -> tuple[bool | None, str]:
        if not link_exists(t.iface):
            return False, "proxy interface is missing"
        if not try_run(["systemctl", "is-active", "--quiet",
                        RELAY_UNIT.format(slug=t.slug)]).ok:
            return False, "the proxy relay is not running"
        return None, ""

    def diagnose(self, t: Tunnel, *, fresh: bool = False) -> dict:
        """Which step of reaching the proxy fails, asked from inside the
        namespace - through the entry tunnel, exactly as the relay goes.

        The login travels on stdin, never on a command line.
        """
        if not t.endpoints:
            return {"stage": "resolve", "ok": False, "detail": ""}
        cached = _diagnoses.get(t.slug)
        if not fresh and cached and time.time() - cached[0] < DIAGNOSIS_TTL:
            return cached[1]
        import sys
        username, password = read_credentials(t.slug)
        payload = json.dumps({"type": t.proxy["type"], "server": server_of(t),
                              "port": int(t.proxy["port"]),
                              "username": username, "password": password})
        res = try_run(["ip", "netns", "exec", t.netns, sys.executable, "-m",
                       "vpngw.proxycheck"], input_text=payload,
                      timeout=PROBE_TIMEOUT + 4)
        try:
            result = json.loads(res.stdout)
        except (ValueError, TypeError):
            result = {"stage": "relay", "ok": False, "detail": ""}
        _diagnoses[t.slug] = (time.time(), result)
        return result

    def explain(self, t: Tunnel, d: dict) -> str:
        """A diagnosis in the panel's words. Never contains a credential."""
        where = f"{t.proxy.get('host')}:{t.proxy.get('port')}"
        return {
            "resolve": f"{t.proxy.get('host')} couldn't be resolved through {t.via}.",
            "connect": f"The proxy at {where} didn't answer through {t.via}.",
            "auth": {
                "needs a login": "The proxy wants a username and password, "
                                 "and none is set.",
                "refuses a username and password":
                    "The proxy does not take a username and password: it may "
                    "admit callers by address instead.",
            }.get(d.get("detail"), "The proxy rejected the username or password."),
            "tunnel": "The proxy accepted the login but would not connect "
                      f"onward: {d.get('detail') or 'no reason given'}.",
            "ok": "The proxy answers, but the relay did not carry the probe.",
        }.get(d.get("stage"), "The proxy relay stopped. It restarts by itself; "
                              "clients stay blocked meanwhile.")

    def probe(self, t: Tunnel) -> tuple[bool, float | None, str | None, str]:
        """An HTTP request from inside the namespace, through the relay.

        ICMP does not cross a proxy, so the usual ping cannot say anything
        about one. This crosses exactly what a client's connection crosses
        after it enters the namespace - the relay, the entry tunnel, the
        proxy - and reports the proxy's exit address on the way.

        Returns (ok, milliseconds, exit address, reason). The reason is
        filled in only on failure, from a diagnosis of which step broke.
        """
        marker = "vpngw-probe-time="
        res = try_run(["ip", "netns", "exec", t.netns, "curl", "--silent",
                       "--fail", "--max-time", str(PROBE_TIMEOUT),
                       "--write-out", "\n" + marker + "%{time_total}",
                       PROBE_URL], timeout=PROBE_TIMEOUT + 4)
        if not res.ok:
            return False, None, None, self.explain(t, self.diagnose(t))
        exit_ip, ms = None, None
        for line in res.stdout.splitlines():
            if line.startswith("ip="):
                exit_ip = line[3:].strip()
            elif line.startswith(marker):
                try:
                    ms = float(line[len(marker):]) * 1000
                except ValueError:
                    pass
        if exit_ip is None:
            return False, ms, None, self.explain(t, self.diagnose(t))
        _diagnoses.pop(t.slug, None)
        return True, ms, exit_ip, ""
