#!/usr/bin/env bash
#
# Release checks that only mean something on a real gateway.
#
# The unit tests cover what can be checked without a kernel, and `vpngwctl
# selftest` measures a leak while everything is healthy. What neither covers is
# the claim this project actually makes:
#
#     the kill switch does not depend on the kill switch's own process
#
# Testing that means killing things. Everything here is destructive and
# recoverable, in that order: each check restores what it broke before the next
# one runs, and a rollback timer is armed first so a check that goes wrong
# cannot leave the box unreachable.
#
#   sudo tests/release_test.sh          # everything except the reboot check
#   sudo tests/release_test.sh --reboot # includes it; the box restarts
#
set -uo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
PASS=0; FAIL=0; SKIP=0

pass() { printf "  %sPASS%s  %-52s %s\n" "$GREEN" "$OFF" "$1" "${2:-}"; PASS=$((PASS+1)); }
fail() { printf "  %sFAIL%s  %-52s %s\n" "$RED" "$OFF" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
skip() { printf "  %sSKIP%s  %-52s %s\n" "$YELLOW" "$OFF" "$1" "${2:-}"; SKIP=$((SKIP+1)); }
say()  { printf "\n%s==>%s %s\n" "$BOLD" "$OFF" "$*"; }

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }
command -v vpngwctl >/dev/null || { echo "vpngw is not installed"; exit 1; }

STATE=/run/vpngw-release-test
mkdir -p "$STATE"

counter() { nft list counter inet vpngw "$1" 2>/dev/null | grep -oE 'packets [0-9]+' | grep -oE '[0-9]+' || echo 0; }
forward_policy() { nft list chain inet vpngw forward 2>/dev/null | grep -oE 'policy [a-z]+' | awk '{print $2}'; }
table_of() { vpngwctl tunnel list 2>/dev/null | awk -v s="$1" '$1==s {for(i=1;i<=NF;i++) if($i=="table") print $(i+1)}'; }

FIRST_TUNNEL=$(vpngwctl tunnel list 2>/dev/null | awk 'NR==1{print $1}')
CLIENT_IFACE=$(python3 - <<'PY' 2>/dev/null
from vpngw.config import Settings
print(Settings.load().net.client_interfaces()[0])
PY
)
WAN=$(python3 - <<'PY' 2>/dev/null
from vpngw.config import Settings
print(Settings.load().net.wan_iface)
PY
)

# ---------------------------------------------------------------------------
say "arming the rollback"
systemctl stop vpngw-panic.timer 2>/dev/null
systemd-run --on-active=20min --unit=vpngw-panic \
  /bin/sh -c 'systemctl start vpngw; nft delete table inet vpngw 2>/dev/null' >/dev/null 2>&1
echo "  if this script dies, vpngw is restarted in 20 minutes"

restore() {
    systemctl start vpngw >/dev/null 2>&1
    sleep 6
}
trap restore EXIT

# ---------------------------------------------------------------------------
say "1. the firewall outlives the control plane"

systemctl stop vpngw
sleep 3

[[ "$(forward_policy)" == "drop" ]] \
  && pass "forward chain still drops with vpngw stopped" \
  || fail "forward chain policy is '$(forward_policy)' with vpngw stopped"

if nft list set inet vpngw tun_ifaces >/dev/null 2>&1; then
    pass "ruleset is still loaded" "stopping the service does not flush it"
else
    fail "the ruleset disappeared when vpngw stopped"
fi

if [[ -n "$FIRST_TUNNEL" ]]; then
    if ip link show "wg-$FIRST_TUNNEL" >/dev/null 2>&1 || \
       ip link show "tun-$FIRST_TUNNEL" >/dev/null 2>&1; then
        pass "tunnels keep running" "an upgrade does not cut client traffic"
    else
        fail "the tunnel went down when vpngw stopped"
    fi
fi

# ---------------------------------------------------------------------------
say "2. a tunnel dying with no daemon to notice"

if [[ -z "$FIRST_TUNNEL" ]]; then
    skip "blackhole takes over" "no tunnel configured"
else
    TABLE=$(table_of "$FIRST_TUNNEL")
    IFACE=$(ip -br link show | awk '/^(wg|tun)-'"$FIRST_TUNNEL"'/ {print $1}' | head -1)
    if [[ -z "$TABLE" || -z "$IFACE" ]]; then
        skip "blackhole takes over" "could not resolve the tunnel's table"
    else
        ip link set "$IFACE" down 2>/dev/null
        sleep 2
        ROUTES=$(ip route show default table "$TABLE" 2>/dev/null)
        if [[ -n "$ROUTES" ]] && ! grep -qv blackhole <<<"$ROUTES"; then
            pass "blackhole is the only default left" "the kernel did this, not vpngw"
        else
            fail "table $TABLE still has a real default" "$(tr '\n' ' ' <<<"$ROUTES")"
        fi
        ip link set "$IFACE" up 2>/dev/null
    fi
fi

# ---------------------------------------------------------------------------
say "3. a client cannot escape while the daemon is dead"

NS=reltest
ip netns del $NS 2>/dev/null; ip link del rt-host 2>/dev/null
if [[ -z "$CLIENT_IFACE" ]] || ! ip link show "$CLIENT_IFACE" >/dev/null 2>&1; then
    skip "unregistered client is blocked" "no client interface"
else
    LAN_CIDR=$(python3 -c 'from vpngw.config import Settings; print(Settings.load().net.lan_cidr)' 2>/dev/null)
    TEST_IP=$(python3 - "$LAN_CIDR" <<'PY'
import ipaddress, sys
net = ipaddress.ip_interface(sys.argv[1]).network
print(f"{ipaddress.ip_address(net.broadcast_address) - 7}/{net.prefixlen}")
PY
)
    GW=$(python3 -c 'from vpngw.config import Settings; print(Settings.load().net.lan_address)' 2>/dev/null)

    ip netns add $NS
    ip link add rt-host type veth peer name rt-ns
    ip link set rt-ns netns $NS
    ip link set rt-host master "$CLIENT_IFACE" up 2>/dev/null || \
        ip link set rt-host up
    ip netns exec $NS ip link set lo up
    ip netns exec $NS ip addr add "$TEST_IP" dev rt-ns
    ip netns exec $NS ip link set rt-ns up
    ip netns exec $NS ip route add default via "$GW" 2>/dev/null

    BEFORE=$(cat "/sys/class/net/$WAN/statistics/tx_packets" 2>/dev/null || echo 0)
    timeout 12 tcpdump -i "$WAN" -n -w "$STATE/leak.pcap" \
        "host 203.0.113.77 or port 51888" >/dev/null 2>&1 &
    TCPD=$!
    sleep 2
    for _ in 1 2 3 4 5; do
        ip netns exec $NS sh -c 'echo x | timeout 1 nc -u -w1 203.0.113.77 51888' >/dev/null 2>&1
    done
    # Deliberately not `curl | grep -c ... || echo 0`: grep -c prints "0" *and*
    # exits 1 when nothing matches, so the fallback appends a second line and
    # the variable becomes "0\n0" - which compares unequal to "0" and reports a
    # leak that did not happen. A test that cries wolf is worse than no test.
    TRACE=$(ip netns exec $NS timeout 8 curl -s --max-time 6 \
            https://1.1.1.1/cdn-cgi/trace 2>/dev/null) || TRACE=""
    EXIT_IP=$(printf '%s' "$TRACE" | sed -n 's/^ip=//p' | head -1)
    sleep 1; kill $TCPD 2>/dev/null; wait $TCPD 2>/dev/null
    CAUGHT=$(tcpdump -r "$STATE/leak.pcap" -n 2>/dev/null | wc -l)

    [[ -z "$EXIT_IP" ]] \
      && pass "unregistered client cannot reach the internet" "daemon stopped throughout" \
      || fail "LEAKED - an unregistered client reached the internet as $EXIT_IP"
    [[ "$CAUGHT" == "0" ]] \
      && pass "no canary packet on the uplink" "0 captured on $WAN" \
      || fail "LEAKED - $CAUGHT packet(s) reached $WAN"

    ip netns del $NS 2>/dev/null; ip link del rt-host 2>/dev/null
fi

# ---------------------------------------------------------------------------
say "4. recovery"

systemctl start vpngw
sleep 8
[[ "$(systemctl is-active vpngw)" == "active" ]] \
  && pass "vpngw restarts cleanly" \
  || fail "vpngw did not come back"

if [[ -n "$FIRST_TUNNEL" ]]; then
    for _ in $(seq 1 12); do
        STATE_NOW=$(vpngwctl status 2>/dev/null | awk -v s="$FIRST_TUNNEL" '$2==s {print $1}')
        [[ "$STATE_NOW" == "up" ]] && break
        sleep 3
    done
    [[ "$STATE_NOW" == "up" ]] \
      && pass "tunnel is healthy again" "$FIRST_TUNNEL" \
      || fail "tunnel did not recover" "state: ${STATE_NOW:-unknown}"
fi

[[ "$(sysctl -n net.ipv4.ip_forward)" == "1" ]] \
  && pass "forwarding restored after start" \
  || fail "forwarding is still off after start"

# ---------------------------------------------------------------------------
say "5. boot-time posture"

BOOT=$(systemctl show vpngw-killswitch.service --property=Before --property=UnitFileState 2>/dev/null)
grep -q "network-pre.target" <<<"$BOOT" && grep -q "UnitFileState=enabled" <<<"$BOOT" \
  && pass "kill switch is ordered before the network and enabled" \
  || fail "kill switch boot ordering is wrong" "$BOOT"

grep -qE '^\s*net\.ipv4\.ip_forward\s*=\s*0' /etc/sysctl.d/99-vpngw.conf 2>/dev/null \
  && pass "sysctl ships forwarding off" "raised only after a ruleset loads" \
  || fail "/etc/sysctl.d/99-vpngw.conf does not disable forwarding at boot"

for k in arp_ignore arp_announce; do
  v=$(sysctl -n "net.ipv4.conf.all.$k" 2>/dev/null)
  case "$k:$v" in
    arp_ignore:1|arp_announce:2) pass "ARP flux guard: $k = $v" ;;
    *) fail "ARP flux guard: $k is $v" "two NICs on one segment will flap" ;;
  esac
done

nft list chain inet vpngw mangle_forward 2>/dev/null | grep -q maxseg \
  && pass "TCP MSS is clamped to the tunnel MTU" "large transfers will not stall" \
  || fail "no MSS clamp - HTTPS will hang while DNS works"

# ---------------------------------------------------------------------------
say "6. leak test"

if [[ -z "$FIRST_TUNNEL" ]]; then
    skip "vpngwctl selftest --disrupt" "no tunnel configured"
else
    OUT=$(vpngwctl selftest --disrupt --yes 2>&1)
    echo "$OUT" | sed 's/^/    /' | tail -20
    grep -q "no leak found" <<<"$OUT" \
      && pass "selftest reports no leak" \
      || fail "selftest found problems"
fi

# ---------------------------------------------------------------------------
if [[ "${1:-}" == "--reboot" ]]; then
    say "7. reboot"
    cat > /etc/systemd/system/vpngw-postboot.service <<'UNIT'
[Unit]
Description=vpngw post-reboot release check
After=multi-user.target
[Service]
Type=oneshot
ExecStart=/bin/sh -c 'sleep 25; { \
  echo "forward_policy=$(nft list chain inet vpngw forward | grep -oE \"policy [a-z]+\")"; \
  echo "killswitch=$(systemctl is-active vpngw-killswitch)"; \
  echo "vpngw=$(systemctl is-active vpngw)"; \
  echo "ip_forward=$(sysctl -n net.ipv4.ip_forward)"; \
  echo "tunnels=$(vpngwctl tunnel list | wc -l)"; \
  vpngwctl status; } > /run/vpngw-postboot.txt 2>&1'
[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable vpngw-postboot.service >/dev/null 2>&1
    echo "  rebooting; read /run/vpngw-postboot.txt when it comes back"
    trap - EXIT
    systemctl stop vpngw-panic.timer 2>/dev/null
    (sleep 2; reboot) &
    exit 0
fi

# ---------------------------------------------------------------------------
systemctl stop vpngw-panic.timer 2>/dev/null
systemctl reset-failed vpngw-panic.service 2>/dev/null
trap - EXIT

printf "\n%s==>%s %d passed, %d failed, %d skipped\n" "$BOLD" "$OFF" "$PASS" "$FAIL" "$SKIP"
if (( FAIL )); then
    printf "%sNot ready to ship.%s\n" "$RED" "$OFF"
    exit 1
fi
printf "%sRelease checks passed.%s\n" "$GREEN" "$OFF"
