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
ADMIN_WAN="${VPNGW_ADMIN_WAN:-}"
if [[ -n "$MGMT" ]]; then
    ok "management interface: $MGMT"
else
    warn "no spare adapter for a management segment; the panel answers on the"
    warn "LAN bridge. If you administer from the uplink's network, answer yes"
    warn "below (or set VPNGW_ADMIN_WAN=1)."
fi

LAN_CIDR="${VPNGW_LAN_CIDR:-10.10.0.1/24}"
ok "client network: $LAN_CIDR"

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
    ask "Client network (address/prefix)" "$LAN_CIDR" LAN_CIDR

    echo
    echo "  Management: how you will reach SSH and the web panel."
    if [[ -n "$MGMT" ]]; then
        ask "Management interface (blank to use the uplink instead)" "$MGMT" MGMT
    fi
    echo "  The panel and SSH answer on the LAN bridge${MGMT:+ and $MGMT}."
    ask "Also answer on the uplink ($WAN)? [y/N]" "${ADMIN_WAN:+y}" ADMIN_WAN_ANSWER
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
    iproute2 iputils-ping curl ca-certificates tcpdump ethtool dnsutils
    netcat-openbsd python3 python3-fastapi python3-uvicorn python3-multipart
)
MISSING=()
for p in "${PKGS[@]}"; do
    dpkg -s "$p" >/dev/null 2>&1 || MISSING+=("$p")
done
if (( ${#MISSING[@]} )); then
    apt-get update -qq
    apt-get install -y -qq "${MISSING[@]}" || die "package installation failed"
    ok "installed: ${MISSING[*]}"
else
    ok "all packages already present"
fi

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

[[ -f "$SRC/README.md" ]] && cp "$SRC/README.md" /usr/share/doc/vpngw/
[[ -d "$SRC/docs" ]] && cp -r "$SRC/docs/." /usr/share/doc/vpngw/ 2>/dev/null || true

# ---------------------------------------------------------------------------
say "configuration"

if [[ -f "$ETC/vpngw.toml" ]]; then
    ok "$ETC/vpngw.toml exists, left alone"
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

for unit in vpngw-killswitch.service vpngw.service vpngw-ovpn@.service vpngw-dns@.service; do
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
    3. Add a client:          vpngwctl client add pc01 10.10.0.11 --egress tunnel:nl01
    4. Check it:              vpngwctl status
    5. Prove it:              vpngwctl selftest --disrupt

  Web UI: http://10.10.0.1:8080 (from the LAN)${ADMIN_WAN:+  or  http://${WAN_CIDR%%/*}:8080}

  Step 5 is the one that matters. Until it passes, treat this gateway as
  untested rather than leak-proof.

EOF
