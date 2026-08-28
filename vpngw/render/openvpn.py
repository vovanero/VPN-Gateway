"""Turns a provider's .ovpn file into one this gateway can be trusted to run.

A commercial .ovpn is written on the assumption that it owns the whole machine:
it pushes ``redirect-gateway``, installs default routes, and rewrites the
system resolver. Every one of those would fight the policy routing here, and
``redirect-gateway`` in particular would put a default route in the *main*
table - which is the classic way a multi-VPN box starts sending the wrong
client out the wrong tunnel.

Rather than trusting option precedence, directives we must own are stripped
from the provider file and reissued in a block we control. Anything we do not
recognise is passed through untouched, including inline <ca>/<cert>/<tls-auth>
blocks, so provider-specific crypto settings keep working.
"""

from __future__ import annotations

import re

# Directives removed from the provider's file. Each is reissued below, or
# deliberately not reissued at all.
STRIPPED = {
    # routing - ours, exclusively
    "dev", "dev-type", "dev-node",
    "redirect-gateway", "redirect-private",
    "route", "route-ipv6", "route-gateway", "route-metric", "route-nopull",
    "route-up", "route-pre-down",
    # process and logging - systemd's job
    "daemon", "log", "log-append", "writepid", "syslog", "errors-to-stderr",
    "user", "group", "chroot",
    # scripts - ours, exclusively
    "up", "down", "up-restart", "up-delay", "script-security",
    "management", "management-hold", "management-query-passwords",
    # credentials - we point at our own file with 0600 perms
    "auth-user-pass",
    # windows-only, meaningless here and noisy in the log
    "block-outside-dns", "register-dns", "dhcp-release", "dhcp-renew",
    # keeping the interface alive past a crash would keep a dead route alive
    # with it; we want the link to vanish so the blackhole takes over
    "persist-tun",
}

INLINE_BLOCK = re.compile(r"^<(/?)([a-z0-9-]+)>\s*$", re.IGNORECASE)


def strip_provider_config(text: str) -> tuple[str, list[str]]:
    """Return (filtered config, list of directives that were removed)."""
    out: list[str] = []
    removed: list[str] = []
    inside: str | None = None

    for raw in text.splitlines():
        line = raw.rstrip()
        m = INLINE_BLOCK.match(line.strip())
        if m:
            closing, tag = m.group(1), m.group(2).lower()
            inside = None if closing else tag
            out.append(line)
            continue
        if inside:  # inside <ca>...</ca> etc: copy verbatim, never parse
            out.append(line)
            continue

        stripped = line.strip()
        if not stripped or stripped.startswith(("#", ";")):
            out.append(line)
            continue

        directive = stripped.split()[0].lstrip("-").lower()
        if directive in STRIPPED:
            removed.append(stripped)
            out.append(f"# vpngw removed: {stripped}")
            continue
        out.append(line)

    return "\n".join(out) + "\n", removed


def render(
    provider_config: str,
    *,
    slug: str,
    iface: str,
    auth_file: str | None = None,
    updown_script: str = "/usr/libexec/vpngw/ovpn-updown.sh",
    mtu: int = 0,
    fwmark: int = 0,
    verb: int = 3,
) -> tuple[str, list[str]]:
    body, removed = strip_provider_config(provider_config)

    ours = [
        "",
        "# " + "-" * 68,
        "# vpngw overrides - appended after the provider's own directives.",
        "# " + "-" * 68,
        "client",
        f"dev {iface}",
        "dev-type tun",
        "nobind",
        "persist-key",
        "",
        "# Routes are installed by vpngw into this tunnel's private routing",
        "# table, never into the main one. Filtering the pushed routes rather",
        "# than using route-nopull keeps the pushed DNS servers, which a lot of",
        "# providers require you to use.",
        'pull-filter ignore "redirect-gateway"',
        'pull-filter ignore "redirect-private"',
        'pull-filter ignore "route "',
        'pull-filter ignore "route-ipv6"',
        'pull-filter ignore "block-outside-dns"',
        "",
        "# The up script reports the assigned address, peer and DNS back to the",
        "# daemon; nothing about the system is modified by it.",
        "script-security 2",
        f"up {updown_script}",
        f"down {updown_script}",
        "down-pre",
        f"setenv VPNGW_SLUG {slug}",
        "",
        "# Reconnect promptly, but never sit in a tight loop against a provider",
        "# that is refusing us.",
        "resolv-retry 5",
        "connect-retry 2 60",
        "connect-retry-max 0",
        "keepalive 10 60",
        "",
        f"verb {verb}",
        "mute 20",
    ]
    if mtu:
        ours.append(f"tun-mtu {mtu}")
    if fwmark:
        # SO_MARK on the transport socket - the OpenVPN spelling of
        # WireGuard's FwMark. What sends a chained tunnel's encrypted
        # traffic into its parent instead of out the WAN.
        ours.append(f"mark {fwmark}")
    if auth_file:
        ours.append(f"auth-user-pass {auth_file}")
        ours.append("auth-nocache")

    return body + "\n".join(ours) + "\n", removed


UPDOWN_SCRIPT = r"""#!/bin/sh
# vpngw OpenVPN --up/--down helper.
#
# Reports what the server assigned back to the daemon and does nothing else.
# In particular it does NOT touch /etc/resolv.conf or the routing table: on
# this gateway both belong to vpngw, and an .ovpn that expects to own them is
# exactly what we are defending against.
set -eu

SLUG="${VPNGW_SLUG:?VPNGW_SLUG not set}"
STATE_DIR=/run/vpngw/tunnels
mkdir -p "$STATE_DIR"

tmp="$STATE_DIR/.$SLUG.$$"
out="$STATE_DIR/$SLUG.env"

case "${script_type:-}" in
  up)
    {
      echo "state=up"
      echo "dev=${dev:-}"
      echo "local=${ifconfig_local:-}"
      echo "peer=${ifconfig_remote:-}"
      echo "gateway=${route_vpn_gateway:-${ifconfig_remote:-}}"
      echo "mtu=${tun_mtu:-}"
      echo "server=${trusted_ip:-}"
      echo "since=$(date +%s)"
      i=1
      while : ; do
        eval "opt=\${foreign_option_$i:-}"
        [ -n "$opt" ] || break
        case "$opt" in
          "dhcp-option DNS "*) echo "dns=${opt#dhcp-option DNS }" ;;
        esac
        i=$((i + 1))
      done
    } > "$tmp"
    mv "$tmp" "$out"
    ;;
  down)
    printf 'state=down\nsince=%s\n' "$(date +%s)" > "$tmp"
    mv "$tmp" "$out"
    ;;
esac

exit 0
"""
