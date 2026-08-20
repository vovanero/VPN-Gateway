#!/usr/bin/env bash
#
# Failover, measured rather than asserted.
#
# A pool is easy to make look right: the status page says "active: nl01" and
# everyone moves on. What matters is where a client's packets actually come out
# and how that changes when a member dies - so this attaches a real client and
# reads its public address at every step. Two tunnels in different countries
# make the answer unambiguous.
#
# What it checks:
#   * the pool picks the member you told it to prefer
#   * a client on the pool exits through that member
#   * killing it moves the client to the next one, and the exit address changes
#   * stickiness stops it flapping straight back
#   * killing every member blackholes the pool instead of falling back
#   * bringing one back restores service
#
#   sudo tests/pool_test.sh <tunnel-a> <tunnel-b>
#
set -uo pipefail

GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; BOLD=$'\033[1m'; OFF=$'\033[0m'
PASS=0; FAIL=0

pass() { printf "  %sPASS%s  %-46s %s\n" "$GREEN" "$OFF" "$1" "${2:-}"; PASS=$((PASS+1)); }
fail() { printf "  %sFAIL%s  %-46s %s\n" "$RED" "$OFF" "$1" "${2:-}"; FAIL=$((FAIL+1)); }
say()  { printf "\n%s==>%s %s\n" "$BOLD" "$OFF" "$*"; }

[[ $EUID -eq 0 ]] || { echo "run as root"; exit 1; }

A="${1:-}"; B="${2:-}"
if [[ -z "$A" || -z "$B" ]]; then
    mapfile -t TUNNELS < <(vpngwctl tunnel list 2>/dev/null | awk '{print $1}')
    A="${TUNNELS[0]:-}"; B="${TUNNELS[1]:-}"
fi
[[ -n "$A" && -n "$B" ]] || { echo "need two tunnels; pass them as arguments"; exit 1; }

POOL=ptest
NS=pooltest
VETH=pt-host
CLIENT_IFACE=$(python3 -c 'from vpngw.config import Settings; print(Settings.load().net.client_interfaces()[0])')
LAN_CIDR=$(python3 -c 'from vpngw.config import Settings; print(Settings.load().net.lan_cidr)')
GW=$(python3 -c 'from vpngw.config import Settings; print(Settings.load().net.lan_address)')
TEST_IP=$(python3 - "$LAN_CIDR" <<'PY'
import ipaddress, sys
net = ipaddress.ip_interface(sys.argv[1]).network
print(f"{ipaddress.ip_address(net.broadcast_address) - 9}")
PY
)

iface_of() { ip -br link show 2>/dev/null | awk '/^(wg|tun)-'"$1"'[ \t]/ {print $1}' | head -1; }
active_member() { vpngwctl status 2>/dev/null | awk -v p="$POOL" '$1==p {for(i=1;i<=NF;i++) if($i=="active:") print $(i+1)}'; }

exit_ip() {
    ip netns exec $NS timeout 14 curl -s --max-time 12 \
        https://1.1.1.1/cdn-cgi/trace 2>/dev/null | sed -n 's/^ip=//p' | head -1
}

# Failover is not instant by design: the health monitor needs fail_threshold
# consecutive misses before it calls a member down. Polling for the change is
# the honest way to measure it - a fixed sleep either flakes or hides how long
# it really took.
wait_for_exit_change() {
    local was="$1" deadline=$((SECONDS + ${2:-90})) now=""
    while (( SECONDS < deadline )); do
        now=$(exit_ip)
        [[ -n "$now" && "$now" != "$was" ]] && { echo "$now"; return 0; }
        sleep 3
    done
    echo "$now"
    return 1
}

cleanup() {
    ip netns del $NS 2>/dev/null
    ip link del $VETH 2>/dev/null
    vpngwctl client rm "$TEST_IP" >/dev/null 2>&1
    vpngwctl pool rm $POOL >/dev/null 2>&1
    for t in "$A" "$B"; do
        i=$(iface_of "$t"); [[ -n "$i" ]] && ip link set "$i" up 2>/dev/null
    done
    systemctl start vpngw >/dev/null 2>&1
}
trap cleanup EXIT

say "setup: pool '$POOL' with $A (preferred) then $B"
cleanup 2>/dev/null
vpngwctl pool create $POOL --strategy priority --sticky 30 --members "$A" "$B" >/dev/null 2>&1 \
  || { echo "could not create the pool"; exit 1; }

ip netns add $NS
ip link add $VETH type veth peer name pt-ns
ip link set pt-ns netns $NS
ip link set $VETH master "$CLIENT_IFACE" up
ip netns exec $NS ip link set lo up
ip netns exec $NS ip addr add "$TEST_IP/${LAN_CIDR#*/}" dev pt-ns
ip netns exec $NS ip link set pt-ns up
ip netns exec $NS ip route add default via "$GW"
vpngwctl client add pooltest "$TEST_IP" --egress pool:$POOL >/dev/null 2>&1
sleep 8

# ---------------------------------------------------------------------------
say "1. the preferred member carries the pool"

ACTIVE=$(active_member)
[[ "$ACTIVE" == "$A" ]] \
  && pass "pool selected the preferred member" "$A" \
  || fail "pool selected '$ACTIVE', expected '$A'"

EXIT_A=$(exit_ip)
[[ -n "$EXIT_A" ]] \
  && pass "client on the pool reaches the internet" "exits as $EXIT_A" \
  || fail "client on the pool has no internet"

# ---------------------------------------------------------------------------
say "2. the preferred member dies"

IFACE_A=$(iface_of "$A")
[[ -n "$IFACE_A" ]] || { echo "cannot find $A's interface"; exit 1; }
echo "  taking $IFACE_A down at $(date +%T)"
START=$SECONDS
ip link set "$IFACE_A" down

EXIT_B=$(wait_for_exit_change "$EXIT_A" 120)
TOOK=$((SECONDS - START))

if [[ -n "$EXIT_B" && "$EXIT_B" != "$EXIT_A" ]]; then
    pass "client moved to the other member" "$EXIT_A -> $EXIT_B in ${TOOK}s"
else
    fail "client did not fail over" "still ${EXIT_B:-unreachable} after ${TOOK}s"
fi

ACTIVE=$(active_member)
[[ "$ACTIVE" == "$B" ]] \
  && pass "pool reports the new member" "$B" \
  || fail "pool reports '$ACTIVE', expected '$B'"

# ---------------------------------------------------------------------------
say "3. stickiness"

echo "  bringing $IFACE_A back up"
ip link set "$IFACE_A" up
sleep 12
ACTIVE=$(active_member)
[[ "$ACTIVE" == "$B" ]] \
  && pass "does not switch back immediately" "stickiness is holding $B" \
  || fail "switched back to '$ACTIVE' before the sticky window elapsed"

# ---------------------------------------------------------------------------
say "4. every member down"

IFACE_B=$(iface_of "$B")
ip link set "$IFACE_A" down
ip link set "$IFACE_B" down
sleep 30

ACTIVE=$(active_member)
[[ -z "$ACTIVE" || "$ACTIVE" == "NONE" ]] \
  && pass "pool reports no healthy member" \
  || fail "pool still claims '$ACTIVE' with every member down"

POOL_TABLE=$(vpngwctl pool list 2>/dev/null | awk -v p="$POOL" '$1==p {for(i=1;i<=NF;i++) if($i=="table") print $(i+1)}')
if [[ -n "$POOL_TABLE" ]]; then
    ROUTES=$(ip route show default table "$POOL_TABLE" 2>/dev/null)
    if [[ -n "$ROUTES" ]] && ! grep -qv blackhole <<<"$ROUTES"; then
        pass "pool table fell back to blackhole" "table $POOL_TABLE"
    else
        fail "pool table $POOL_TABLE still has a real default" "$(tr '\n' ' ' <<<"$ROUTES")"
    fi
fi

STRANDED=$(exit_ip)
[[ -z "$STRANDED" ]] \
  && pass "client has no internet, and did not fall back to the uplink" \
  || fail "LEAKED - client still reached the internet as $STRANDED"

# ---------------------------------------------------------------------------
say "5. recovery"

ip link set "$IFACE_A" up
ip link set "$IFACE_B" up
BACK=$(wait_for_exit_change "" 120)
[[ -n "$BACK" ]] \
  && pass "service restored once a member returns" "exits as $BACK" \
  || fail "pool did not recover"

# ---------------------------------------------------------------------------
printf "\n%s==>%s %d passed, %d failed\n" "$BOLD" "$OFF" "$PASS" "$FAIL"
(( FAIL )) && exit 1
printf "%sFailover works.%s\n" "$GREEN" "$OFF"
