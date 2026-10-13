#!/usr/bin/env bash
#
# vpngw installer for Debian 13 (trixie).
#
# Idempotent: safe to re-run after pulling changes. It never enables forwarding
# itself and never loosens an existing ruleset - the fail-closed skeleton is
# installed before anything else, so even a half-finished run leaves a box that
# forwards nothing rather than one that forwards everything.
#
# The topology is detected rather than assumed. Override anything with an
# environment variable:
#
#   VPNGW_WAN=eth0 VPNGW_LAN=eth1 VPNGW_ADMIN_WAN=1 ./install.sh
#
# The gateway keeps no history by default: journal silent, events off, DNS
# queries never logged, HTTP access logging off. Logging is opt-in from the
# panel (Settings -> Privacy & logging: none / normal / high).
#
set -euo pipefail

PREFIX=/opt/vpngw
ETC=/etc/vpngw
LIBEXEC=/usr/libexec/vpngw
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

RED=$'\033[31m'; GREEN=$'\033[32m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'

say()  { printf '%s==>%s %s\n' "$BOLD" "$OFF" "$*"; }
ok()   { printf '    %sok%s   %s\n' "$GREEN" "$OFF" "$*"; }
warn() { printf '    %swarn%s %s\n' "$YELLOW" "$OFF" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$OFF" "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run as root (or via sudo)"

# Everything this script drives - nft, ip, wg, sysctl, systemctl - lives in
# /usr/sbin or /sbin, and `su` without a dash keeps the calling user's PATH,
# which has neither. The failure that produces is thoroughly misleading:
# "nft: command not found" right after apt reported nftables installed, on a
# box where /usr/sbin/nft is sitting there the whole time.
PATH="/usr/sbin:/sbin:/usr/bin:/bin:$PATH"
export PATH

# ---------------------------------------------------------------------------
say "checking the host"

if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    [[ "${ID:-}" == "debian" ]] || warn "this is ${PRETTY_NAME:-unknown}, not Debian; proceeding anyway"
    ok "${PRETTY_NAME:-unknown}"
fi

PYVER=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null || echo none)
[[ "$PYVER" == none ]] && die "python3 is not installed"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' \
    || die "python3 $PYVER is too old; vpngw needs 3.11+ for tomllib"
ok "python3 $PYVER"

TOTAL_MB=$(awk '/MemTotal/ {print int($2/1024)}' /proc/meminfo)
if (( TOTAL_MB < 900 )); then
    warn "only ${TOTAL_MB} MB of RAM. vpngw runs a resolver per tunnel plus an"
    warn "OpenVPN process per OpenVPN tunnel; below ~1 GB these get OOM-killed"
    warn "under load. Raise the VM's memory to at least 2 GB."
else
    ok "${TOTAL_MB} MB RAM"
fi

# ---------------------------------------------------------------------------
say "detecting the topology"

# The uplink is whatever carries the default route. Guessing wrong here points
# every kill-switch rule at the wrong segment, so it is detected, printed, and
# overridable rather than assumed.
WAN="${VPNGW_WAN:-$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')}"
[[ -n "$WAN" ]] || die "cannot determine the uplink interface; set VPNGW_WAN"
ok "uplink (WAN): $WAN"

physical_ifaces() {
    for d in /sys/class/net/*/; do
        n=$(basename "$d")
        case "$n" in
            lo|br-*|wg-*|tun-*|veth*|docker*|virbr*|vpngw*) continue ;;
        esac
        [[ -e "$d/device" ]] || continue     # skip anything without a real device
        echo "$n"
    done
}

# `|| true` is load-bearing: grep exits 1 when it filters everything out, and
# under `set -e` a failing command substitution in an assignment kills the
# script. "No other interface" is a normal answer here, not an error.
LAN="${VPNGW_LAN:-$(physical_ifaces | grep -vx "$WAN" | head -1 || true)}"
if [[ -z "$LAN" ]]; then
    warn "no second network interface found. The gateway needs one facing the"
    warn "client VMs. Add an adapter and re-run, or set VPNGW_LAN."
    LAN="lan0"
else
    ok "client side (LAN): $LAN"
fi
[[ "$LAN" == "$WAN" ]] && die "VPNGW_LAN and VPNGW_WAN are the same interface"

# A dedicated management interface if a third adapter exists, otherwise
# management over the uplink restricted to one source range.
# Same again - a box with only two adapters is the common case, not a failure.
MGMT="${VPNGW_MGMT:-$(physical_ifaces | grep -vx "$WAN" | grep -vx "$LAN" | head -1 || true)}"
WAN_CIDR=$(ip -4 -o addr show dev "$WAN" 2>/dev/null | awk '{print $4; exit}' || true)
# Management access is per interface, the way any router does it: the panel
# and SSH answer on the LAN bridge (plus the management interface when one
# exists). The uplink joins only when the operator says so - typically because
# they administer the box from the network the uplink sits on, which is the
# common two-adapter lab layout.
wan_is_private() {
    [[ -n "$WAN_CIDR" ]] || return 1
    python3 - "$WAN_CIDR" <<'PY'
import ipaddress, sys
try:
    addr = ipaddress.ip_interface(sys.argv[1]).ip
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if addr.is_private else 1)
PY
}

# Default on for a private uplink - that is the lab layout, and it is where
# the operator is standing. Off for a routable one: a panel that controls a
# kill switch does not belong on the public internet by default.
if [[ -n "${VPNGW_ADMIN_WAN+set}" ]]; then
    ADMIN_WAN="$VPNGW_ADMIN_WAN"
elif wan_is_private; then
    ADMIN_WAN=1
else
    ADMIN_WAN=
fi

if [[ -n "$MGMT" ]]; then
    ok "management interface: $MGMT"
else
    if [[ -n "$ADMIN_WAN" ]]; then
        ok "no management adapter; the panel answers on the LAN bridge and"
        ok "on the uplink, which is private here"
    else
        warn "no spare adapter for a management segment; the panel answers on"
        warn "the LAN bridge only - the uplink is publicly routable. If you"
        warn "administer from it anyway, answer yes below."
    fi
fi

# The default has to dodge the uplink. Offering a client network that
# overlaps it invites an Enter keypress into a broken gateway: two
# interfaces on one subnet, and traffic for the uplink's own network
# treated as local by the client side.
lan_overlaps_wan() {
    # lan_overlaps_wan <lan-cidr> -> 0 when they overlap
    [[ -n "$WAN_CIDR" ]] || return 1
    python3 - "$1" "$WAN_CIDR" <<'PY'
import ipaddress, sys
try:
    lan = ipaddress.ip_interface(sys.argv[1]).network
    wan = ipaddress.ip_interface(sys.argv[2]).network
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if lan.overlaps(wan) else 1)
PY
}

pick_default_lan() {
    for candidate in 10.10.0.1/24 10.20.0.1/24 10.30.0.1/24 \
                     172.20.0.1/24 192.168.90.1/24; do
        lan_overlaps_wan "$candidate" || { echo "$candidate"; return; }
    done
    echo 10.10.0.1/24
}

LAN_CIDR="${VPNGW_LAN_CIDR:-$(pick_default_lan)}"
if lan_overlaps_wan "$LAN_CIDR"; then
    die "the client network $LAN_CIDR overlaps the uplink's ($WAN_CIDR).
       Both interfaces would sit on one subnet: routing between them is
       ambiguous, and traffic for the uplink's own network would be treated
       as local by the client side. Choose a different range with
       VPNGW_LAN_CIDR, or answer the client-network prompt below."
fi
ok "client network: $LAN_CIDR"
[[ -n "$WAN_CIDR" ]] && ok "does not overlap the uplink ($WAN_CIDR)"

# ---------------------------------------------------------------------------
# Interactive review. Everything above was detected; this is the chance to
# correct it before anything is written. Skipped when there is no terminal (a
# provisioning run) or when VPNGW_NONINTERACTIVE is set, so the same script
# works by hand and from automation.
if [[ -t 0 && -z "${VPNGW_NONINTERACTIVE:-}" ]]; then
    say "setup"
    cat <<EOF

  Detected the layout below. Press Enter to accept each value, or type a new
  one. Nothing is written until the end.

EOF
    ask() {  # ask <prompt> <default> <varname>
        local prompt="$1" default="$2" __var="$3" reply=""
        read -r -p "  $prompt [${default:-none}]: " reply || true
        printf -v "$__var" '%s' "${reply:-$default}"
    }

    echo "  Interfaces available: $(physical_ifaces | tr '\n' ' ')"
    ask "Uplink interface (faces the internet)" "$WAN" WAN
    ask "Client interface (faces the machines you want tunnelled)" "$LAN" LAN
    [[ "$WAN" == "$LAN" ]] && die "the uplink and the client interface must differ"

    echo
    echo "  The gateway's own address on the client segment. Clients use it as"
    echo "  their default route. Any private range works - it does not have to"
    echo "  be 10.10.0.1/24."
    while :; do
        ask "Client network (address/prefix)" "$LAN_CIDR" LAN_CIDR
        lan_overlaps_wan "$LAN_CIDR" || break
        warn "that overlaps the uplink's network ($WAN_CIDR) - both adapters"
        warn "would be on one subnet. Pick a different range."
    done

    echo
    echo "  Management: how you will reach SSH and the web panel."
    if [[ -n "$MGMT" ]]; then
        ask "Management interface (blank to use the uplink instead)" "$MGMT" MGMT
    fi
    echo "  The panel and SSH answer on the LAN bridge${MGMT:+ and $MGMT}."
    if [[ -n "$ADMIN_WAN" ]]; then
        echo "  The uplink ($WAN${WAN_CIDR:+ $WAN_CIDR}) is a private network, so"
        echo "  answering there too is the default - it is usually where you are."
    else
        echo "  The uplink ($WAN${WAN_CIDR:+ $WAN_CIDR}) is publicly routable."
        echo "  Answering there would put this panel on the internet; say yes"
        echo "  only if you know that is what you want."
    fi
    ask "Also answer on the uplink ($WAN)?${ADMIN_WAN:+ [Y/n]}${ADMIN_WAN:- [y/N]}" \
        "${ADMIN_WAN:+y}" ADMIN_WAN_ANSWER
    case "${ADMIN_WAN_ANSWER,,}" in
        y|yes|1) ADMIN_WAN=1 ;;
        *)       ADMIN_WAN=  ;;
    esac

    echo
    echo "  Clients normally live on the client interface alone, which is the"
    echo "  only layout where the gateway can guarantee they have no other way"
    echo "  out. Answer yes only if your machines sit on the uplink's subnet"
    echo "  and point their default route at this box - it still confines them"
    echo "  to their tunnel, but they could reach the real router directly and"
    echo "  nothing here would see it."
    ask "Do clients share the uplink's subnet? (yes/no)" "no" SHARED
    if [[ "${SHARED,,}" == y* ]]; then
        CLIENT_IFACES="[\"br-lan\", \"$WAN\"]"
        WAN_NET=$(python3 - "$WAN_CIDR" <<'PY'
import ipaddress, sys
try:
    print(ipaddress.ip_interface(sys.argv[1]).network)
except Exception:
    print("")
PY
)
        LAN_NET_ONLY=$(python3 - "$LAN_CIDR" <<'PY'
import ipaddress, sys
print(ipaddress.ip_interface(sys.argv[1]).network)
PY
)
        CLIENT_CIDRS="[\"$LAN_NET_ONLY\"${WAN_NET:+, \"$WAN_NET\"}]"
    fi

    echo
    ask "Serve DHCP on the client segment? (yes/no)" "no" WANT_DHCP
    [[ "${WANT_DHCP,,}" == y* ]] && DHCP_ENABLED=true

    echo
    echo "  Review:"
    printf "    %-22s %s\n" "uplink" "$WAN"
    printf "    %-22s %s -> br-lan %s\n" "client side" "$LAN" "$LAN_CIDR"
    printf "    %-22s %s
" "management" "br-lan${MGMT:+, $MGMT}${ADMIN_WAN:+, $WAN}"
    printf "    %-22s %s\n" "clients on uplink too" "${SHARED:-no}"
    printf "    %-22s %s\n" "DHCP" "${WANT_DHCP:-no}"
    echo
    read -r -p "  Continue? [Y/n]: " confirm || true
    [[ "${confirm,,}" == n* ]] && die "cancelled"
fi

CLIENT_IFACES="${CLIENT_IFACES:-[]}"
CLIENT_CIDRS="${CLIENT_CIDRS:-[]}"
DHCP_ENABLED="${DHCP_ENABLED:-false}"

# Which stack owns the interfaces? Debian installs ifupdown by default and
# leaves systemd-networkd disabled. Converting a machine you are connected to
# over its only working interface is a good way to lose it, so vpngw adapts:
# with ifupdown in charge the uplink is left exactly as the installer set it,
# and vpngw builds the client bridge itself at startup.
NET_STACK=networkd
if systemctl is-enabled networking >/dev/null 2>&1 &&
   ! systemctl is-enabled systemd-networkd >/dev/null 2>&1; then
    NET_STACK=ifupdown
fi
ok "network stack: $NET_STACK"

# The gateway's own resolvers must match [dns] bootstrap: under strict host
# egress those are the only ones the firewall lets this machine reach before a
# tunnel exists. Adopt what already works rather than overwriting it.
mapfile -t NS < <(grep -E '^\s*nameserver' /etc/resolv.conf 2>/dev/null |
                  awk '{print $2}' | grep -vE '^127\.' | head -3)
if (( ${#NS[@]} )); then
    ok "bootstrap resolvers: ${NS[*]}"
else
    NS=(1.1.1.1 9.9.9.9)
    warn "no usable nameserver in /etc/resolv.conf; using ${NS[*]}"
    printf 'nameserver %s\n' "${NS[@]}" > /etc/resolv.conf
fi
BOOTSTRAP=$(printf '"%s", ' "${NS[@]}"); BOOTSTRAP="${BOOTSTRAP%, }"

# ---------------------------------------------------------------------------
say "installing packages"

export DEBIAN_FRONTEND=noninteractive
PKGS=(
    nftables wireguard-tools openvpn conntrack dnsmasq-base
    iproute2 iputils-ping curl ca-certificates tcpdump ethtool bind9-dnsutils
    geoip-database geoip-bin
    netcat-openbsd python3 python3-fastapi python3-uvicorn python3-multipart
)
# Ask for real package names, not virtual ones. `dnsutils` is only a name
# bind9-dnsutils provides on Debian 13 - `dpkg -s dnsutils` therefore never
# reports it installed, so it landed in MISSING on every single run and sent
# a fully-provisioned gateway to apt for nothing. On a box with the kill
# switch armed that is not a no-op: host egress to the mirrors is dropped by
# design, so `apt-get update` sits through its timeouts before carrying on.
# An update that appears to hang is an update people interrupt.
# Wanted but not essential: without it the gateway works and only proxy
# egress is unavailable, so failing to get it must never fail an update.
OPTIONAL_PKGS=(redsocks)

# Debian's redsocks package ships its own service, which would start a relay
# with a default config on the host at the next boot. vpngw runs redsocks only
# inside a proxy egress's namespace, through its own unit, so the packaged one
# is masked before the package can enable it.
systemctl mask redsocks.service >/dev/null 2>&1 || true

# Fetch .debs through a tunnel and let apt install them from its cache.
#
# On a gateway that is already running, the kill switch drops the box's own
# traffic to the mirrors, so plain apt sits in timeouts - and if it did get
# out, the sources are plain HTTP and the ISP would read the package names off
# the wire ("this address just installed redsocks"). vpngw-update passes the
# tunnel it fetched the release through; the files come over that tunnel, by
# HTTPS, and `apt-get install --no-download` checks each one against the
# signed index before using it, so a tampered file is refused by apt itself.
# A fresh install has no kill switch and no tunnel yet, and uses plain apt.
install_through_tunnel() {
    local ip uri file https
    ip=$(dig +short +time=3 +tries=2 deb.debian.org "@$VPNGW_FETCH_RESOLVER" \
           2>/dev/null | grep -m1 -E '^[0-9.]+$')
    [[ -n "$ip" ]] || return 1
    while read -r uri file; do
        # Both Debian hosts are served by deb.debian.org over HTTPS; anything
        # else would need a lookup outside the tunnel, so it is refused.
        https=$(printf '%s' "$uri" | sed \
                  -e 's#^http://security\.debian\.org/#https://deb.debian.org/#' \
                  -e 's#^http://#https://#')
        [[ "$https" == https://deb.debian.org/* ]] || return 1
        curl -sS --fail --max-time 180 --interface "$VPNGW_FETCH_IFACE" \
             --resolve "deb.debian.org:443:$ip" \
             -o "/var/cache/apt/archives/$file" "$https" || return 1
    done < <(apt-get install --print-uris -qq -y --no-install-recommends "$@" \
               2>/dev/null | awk '{print $1, $2}' | tr -d "'")
    apt-get install --no-download -y -qq --no-install-recommends "$@"
}

# Which tunnel to fetch packages through, when the caller did not say.
#
# vpngw-update passes the tunnel it fetched the release through - but only
# from 2.8.0 on. An older vpngw-update runs this installer without one, and
# so does an installer run by hand; on a gateway that is already armed, plain
# apt then only times out, because the kill switch blocks the box's own
# egress. That is how every update from 2.7.1 left redsocks out. So ask the
# installed gateway for a tunnel that is up, by the test vpngw-update uses.
# Installed means "install ok installed". `dpkg -s` also succeeds for a package
# that was removed but kept its configuration files - no binary left - and an
# installer that trusted it skipped the package for good.
pkg_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

pick_fetch_tunnel() {
    [[ -n "${VPNGW_FETCH_IFACE:-}" && -n "${VPNGW_FETCH_RESOLVER:-}" ]] && return 0
    [[ -f "$PREFIX/vpngw/__init__.py" ]] || return 0
    local picked
    picked="$(PYTHONPATH="$PREFIX" python3 - 2>/dev/null <<'PY'
import time

from vpngw import config
from vpngw.db import Database
from vpngw.net import ifaces, routing

settings = config.Settings.load()


def routed(t):
    # Up means the interface exists AND the kernel has a real default route
    # in its table pointing at it - the panel's "routed" test. The interface
    # alone is not enough: a WireGuard device exists from the moment it is
    # configured, handshake or not. Never a proxy: curl --interface cannot
    # route on its veth, and a release is no reason to spend a metered
    # residential proxy's bytes.
    return (t.kind.value != "proxy" and ifaces.exists(t.iface)
            and routing.table_default(t.table) == t.iface)


def measured_up():
    """The tunnels the daemon has measured as up; None if it cannot say.

    Routed alone is not enough right after the daemon starts: until its
    first probes are in, a tunnel is routed whatever its state, and a dead
    one first in the list was picked - "could not reach GitHub through
    fi02", on a gateway with a working tunnel beside it.
    """
    try:
        from vpngw.cli import Daemon
        status = Daemon(settings).call("/api/status", timeout=5)
    except (Exception, SystemExit):
        return None
    return {t["slug"] for t in status.get("tunnels", []) if t.get("state") == "up"}


db = Database()
try:
    pick, deadline = None, time.time() + 30
    while pick is None:
        candidates = [t for t in db.tunnels(enabled_only=True) if routed(t)]
        up = measured_up()
        if up is None:
            # No daemon to ask: routed is the best evidence there is.
            pick = candidates[0] if candidates else None
            break
        pick = next((t for t in candidates if t.slug in up), None)
        if pick is None:
            if time.time() > deadline:
                break
            time.sleep(2)
    if pick:
        print(pick.iface, pick.slug, settings.dns.resolver_ip(pick.esid))
    else:
        print("", "", "")
finally:
    db.close()
PY
)" || return 0
    local slug
    read -r VPNGW_FETCH_IFACE slug VPNGW_FETCH_RESOLVER <<<"$picked" || true
    if [[ -n "${VPNGW_FETCH_IFACE:-}" && -n "${VPNGW_FETCH_RESOLVER:-}" ]]; then
        export VPNGW_FETCH_IFACE VPNGW_FETCH_RESOLVER
        ok "packages are fetched through $VPNGW_FETCH_IFACE"
    fi
}

install_missing() {
    if [[ -n "${VPNGW_FETCH_IFACE:-}" && -n "${VPNGW_FETCH_RESOLVER:-}" ]]; then
        install_through_tunnel "$@"
    else
        apt-get update -qq && apt-get install -y -qq "$@"
    fi
}

pick_fetch_tunnel
MISSING=()
for p in "${PKGS[@]}"; do
    pkg_installed "$p" || MISSING+=("$p")
done
if (( ${#MISSING[@]} )); then
    install_missing "${MISSING[@]}" || die "package installation failed"
    ok "installed: ${MISSING[*]}"
else
    ok "all packages already present"
fi

for p in "${OPTIONAL_PKGS[@]}"; do
    pkg_installed "$p" && continue
    if install_missing "$p" >/dev/null 2>&1; then
        ok "installed: $p"
    else
        warn "$p could not be installed; proxy egress is unavailable until it is"
    fi
done

# Installed is not the same as reachable. Check the binaries themselves, so a
# PATH or a half-removed package is caught here rather than three steps later
# with an error that points at the wrong thing.
for tool in nft ip wg sysctl systemctl dnsmasq dig; do
    command -v "$tool" >/dev/null 2>&1 && continue
    die "$tool is installed but not on PATH.
       If you became root with 'su', use 'su -' instead - plain 'su' keeps
       the calling user's PATH, which has no /usr/sbin."
done
ok "every required tool is reachable"

if ! python3 -c 'import fastapi, uvicorn' 2>/dev/null; then
    warn "fastapi/uvicorn not importable from the system python; creating a venv"
    apt-get install -y -qq python3-venv
    python3 -m venv --system-site-packages "$PREFIX/venv"
    "$PREFIX/venv/bin/pip" install --quiet fastapi uvicorn python-multipart
    PYTHON="$PREFIX/venv/bin/python3"
else
    PYTHON=/usr/bin/python3
fi
ok "interpreter: $PYTHON"

# ---------------------------------------------------------------------------
say "laying down files"

install -d -m 0755 "$PREFIX" "$LIBEXEC" /usr/share/doc/vpngw
install -d -m 0755 "$ETC"
install -d -m 0700 "$ETC/secrets"
install -d -m 0750 /var/lib/vpngw /var/log/vpngw

rm -rf "$PREFIX/vpngw"
cp -a "$SRC/vpngw" "$PREFIX/vpngw"
find "$PREFIX/vpngw" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
ok "python package -> $PREFIX/vpngw"

# The OpenVPN up/down helper is generated from the same source the driver uses,
# so the two can never drift apart.
PYTHONPATH="$PREFIX" "$PYTHON" - <<'PY' > "$LIBEXEC/ovpn-updown.sh"
from vpngw.render.openvpn import UPDOWN_SCRIPT
print(UPDOWN_SCRIPT, end="")
PY
chmod 0755 "$LIBEXEC/ovpn-updown.sh"
ok "openvpn up/down helper"

cat > /usr/local/bin/vpngwctl <<EOF
#!/bin/sh
# vpngw command line. See: vpngwctl --help
PYTHONPATH=$PREFIX exec $PYTHON -m vpngw.cli "\$@"
EOF
chmod 0755 /usr/local/bin/vpngwctl
ok "vpngwctl"

# The updater installs itself, so a gateway is never in the position this one
# was in for its first three versions: able to run, unable to update, because
# the script that updates it only shipped inside the version you did not have.
# Every install from here on leaves `vpngw-update` on the box.
if [[ -f "$SRC/scripts/update.sh" ]]; then
    install -m 0755 "$SRC/scripts/update.sh" /usr/local/bin/vpngw-update
    ok "vpngw-update"
fi

[[ -f "$SRC/README.md" ]] && cp "$SRC/README.md" /usr/share/doc/vpngw/
[[ -d "$SRC/docs" ]] && cp -r "$SRC/docs/." /usr/share/doc/vpngw/ 2>/dev/null || true

# ---------------------------------------------------------------------------
say "configuration"

if [[ -f "$ETC/vpngw.toml" ]]; then
    ok "$ETC/vpngw.toml exists, left alone"
    # An existing config wins over anything detected above, so from here on
    # report what the daemon will actually read. Otherwise an update prints a
    # summary - and a panel URL - describing a machine that does not exist:
    # the detected client network rather than the configured one. Loading it
    # through the daemon's own parser rather than grepping the file means the
    # summary cannot disagree with the daemon about what the file says.
    if CONFIGURED="$(PYTHONPATH="$PREFIX" "$PYTHON" -c '
import sys
from vpngw import config
n = config.Settings.load().net
print(n.wan_iface, n.lan_member, n.lan_cidr,
      "1" if n.wan_iface in n.management_ifaces() else "")
' 2>/dev/null)" && [[ -n "$CONFIGURED" ]]; then
        read -r WAN LAN LAN_CIDR ADMIN_WAN <<<"$CONFIGURED"
        WAN_CIDR="$(ip -4 -o addr show "$WAN" 2>/dev/null |
                    awk '{print $4; exit}')"
        ok "reporting the configured layout: $WAN, $LAN -> $LAN_CIDR"
    fi
else
    cat > "$ETC/vpngw.toml" <<EOF
# vpngw gateway configuration, generated by install.sh for this machine.
# Restart vpngw.service after editing.

[net]
wan_iface   = "$WAN"
lan_bridge  = "br-lan"
lan_member  = "$LAN"
lan_cidr    = "$LAN_CIDR"
mgmt_iface  = "${MGMT:-}"
mgmt_cidr   = "10.20.0.1/24"
# Management over the uplink, restricted to this source range. Empty when a
# dedicated mgmt_iface exists.
admin_ifaces = ["br-lan"${MGMT:+, \"$MGMT\"}${ADMIN_WAN:+, \"$WAN\"}]
# Interfaces client traffic is accepted from. Empty means the client bridge
# only - the layout where a client has no other way out. Listing the uplink
# here supports clients that share its subnet; they are still confined to their
# tunnel, but they could reach the real router directly and nothing here would
# see it.
client_ifaces = $CLIENT_IFACES
client_cidrs  = $CLIENT_CIDRS

[wan]
mode = "dhcp"
address = ""
gateway = ""
dns = []

[dhcp]
# Off unless asked for: statically addressed clients need nothing handed out,
# and a second DHCP server on a segment that already has one breaks it.
enabled = $DHCP_ENABLED
range_start = ""
range_end = ""
lease_hours = 12
announce_dns = true

[dns]
# Every client DNS query is DNAT-ed to a per-egress resolver on this subnet,
# regardless of what the client configured.
resolver_subnet = "10.99.0.0/21"
# Only used to resolve VPN endpoint hostnames before any tunnel exists. Must
# match what this machine can actually reach - see /etc/resolv.conf.
bootstrap = [$BOOTSTRAP]
fallback_upstream = ["1.1.1.1", "9.9.9.9"]
block_dot = false

[killswitch]
strict_host_egress = true
maintenance_minutes = 30

[health]
probe_interval = 5
probe_target   = "1.1.1.1"
probe_timeout  = 2
fail_threshold = 3
rise_threshold = 2
handshake_max_age = 180
exitip_interval = 120

[api]
bind = "0.0.0.0"
port = 8080
token = ""
EOF
    ok "wrote $ETC/vpngw.toml"
fi

PYTHONPATH="$PREFIX" "$PYTHON" -c \
    'from vpngw.config import Settings; Settings.load(); print("    ok   config validates")' \
    || die "the generated configuration is invalid; fix $ETC/vpngw.toml"

# ---------------------------------------------------------------------------
say "installing the fail-closed skeleton"

# Before the units are enabled and before forwarding is ever raised. From here
# on, an incomplete install is a box that drops rather than one that forwards.
PYTHONPATH="$PREFIX" "$PYTHON" - <<'PY' > "$ETC/killswitch.nft"
from vpngw.config import Settings
from vpngw.render.nftables import render_killswitch
print(render_killswitch(Settings.load()), end="")
PY
chmod 0644 "$ETC/killswitch.nft"

nft --check -f "$ETC/killswitch.nft" \
    || die "the generated kill-switch ruleset is invalid; refusing to continue"
ok "killswitch.nft validated by nft"

install -m 0644 "$SRC/debian/sysctl.d/99-vpngw.conf" /etc/sysctl.d/99-vpngw.conf
sysctl -q --system >/dev/null 2>&1 || true
ok "sysctl defaults (ip_forward stays 0 until the daemon loads a ruleset)"

# ---------------------------------------------------------------------------
say "network configuration"

if [[ "$NET_STACK" == networkd ]]; then
    install -d -m 0755 /etc/systemd/network
    COPIED=0
    for f in "$SRC"/debian/systemd-network/*.network "$SRC"/debian/systemd-network/*.netdev "$SRC"/debian/systemd-network/*.link; do
        [[ -e "$f" ]] || continue
        install -m 0644 "$f" /etc/systemd/network/
        COPIED=$((COPIED + 1))
    done
    ok "$COPIED systemd-networkd files"
    systemctl enable --now systemd-networkd >/dev/null 2>&1
    ok "systemd-networkd enabled"
else
    warn "ifupdown manages the network; /etc/network/interfaces is left alone."
    warn "The uplink keeps the address the installer gave it, and vpngw builds"
    warn "the client bridge itself on every start."
    warn "Interface names are not pinned by MAC in this mode. If the adapters"
    warn "ever swap order, wan_iface would point at the client segment - pin"
    warn "them with .link files once you have console access."
fi

if systemctl is-enabled systemd-resolved >/dev/null 2>&1; then
    systemctl disable --now systemd-resolved >/dev/null 2>&1 || true
    ok "systemd-resolved disabled"
fi

# Debian's own OpenVPN units would start anything in /etc/openvpn and fight us
# for the tun devices.
if systemctl is-enabled openvpn.service >/dev/null 2>&1; then
    systemctl disable --now openvpn.service >/dev/null 2>&1 || true
    ok "disabled openvpn.service (vpngw manages its own tunnels)"
fi

# ---------------------------------------------------------------------------
say "systemd units"

for unit in vpngw-killswitch.service vpngw.service vpngw-ovpn@.service \
            vpngw-dns@.service vpngw-proxy@.service vpngw-pxdns@.service; do
    install -m 0644 "$SRC/systemd/$unit" "/etc/systemd/system/$unit"
done

install -d -m 0755 /etc/systemd/system/vpngw.service.d
cat > /etc/systemd/system/vpngw.service.d/10-paths.conf <<EOF
[Service]
Environment=PYTHONPATH=$PREFIX
WorkingDirectory=$PREFIX
ExecStart=
ExecStart=$PYTHON -m vpngw.service
EOF

systemctl daemon-reload
systemctl enable vpngw-killswitch.service >/dev/null 2>&1
systemctl start  vpngw-killswitch.service
ok "kill switch loaded and enabled at boot"

systemctl enable vpngw.service >/dev/null 2>&1
ok "vpngw.service enabled"

# ---------------------------------------------------------------------------
say "preflight"

if ! PYTHONPATH="$PREFIX" "$PYTHON" -m vpngw.cli check; then
    warn "'vpngwctl check' reported problems - read them before starting"
fi

# The panel has no password until somebody sets one, and a gateway whose
# controls are open to whoever reaches the management network is not finished
# being installed.
if [[ -t 0 && -z "${VPNGW_NONINTERACTIVE:-}" ]]; then
    HAS_PW=$(PYTHONPATH="$PREFIX" "$PYTHON" -c \
        'from vpngw.db import Database; from vpngw import auth; print(int(auth.is_configured(Database())))' \
        2>/dev/null || echo 0)
    if [[ "$HAS_PW" != "1" ]]; then
        echo
        say "panel password"
        echo "  Set one now, or the first person to open the panel sets it."
        PYTHONPATH="$PREFIX" "$PYTHON" -m vpngw.cli passwd || \
            warn "no password set; anyone who can reach the panel can change anything"
    fi
fi

# ---------------------------------------------------------------------------
echo
# An example the operator can paste: the .11 host of their own client
# network, not of whatever the default happened to be.
EXAMPLE_CLIENT=$(python3 - "$LAN_CIDR" <<'PY'
import ipaddress, sys
try:
    net = ipaddress.ip_interface(sys.argv[1]).network
    print(next(h for i, h in enumerate(net.hosts()) if i == 10))
except Exception:
    print("10.10.0.11")
PY
)

say "installed"
cat <<EOF

  The kill switch is loaded. Nothing forwards yet, which is correct: there are
  no tunnels.

  Topology as installed:
    uplink        $WAN${WAN_CIDR:+  ($WAN_CIDR)}
    client side   $LAN  -> br-lan  $LAN_CIDR
    management    br-lan${MGMT:+, $MGMT}${ADMIN_WAN:+, $WAN}

  Next:
    1. Start the daemon:      systemctl start vpngw
    2. Import a tunnel:       vpngwctl tunnel import nl01 /root/mullvad-nl.conf
    3. Add a client:          vpngwctl client add pc01 $EXAMPLE_CLIENT --egress tunnel:nl01
    4. Check it:              vpngwctl status
    5. Prove it:              vpngwctl selftest --disrupt

  The panel answers only once the daemon is running: until then the boot
  skeleton keeps everything but SSH closed, because there is nothing to
  serve yet.

  Web UI: http://${LAN_CIDR%%/*}:8080 (from the LAN)${ADMIN_WAN:+  or  http://${WAN_CIDR%%/*}:8080 (from the uplink)}

  Step 5 is the one that matters. Until it passes, treat this gateway as
  untested rather than leak-proof.

EOF
