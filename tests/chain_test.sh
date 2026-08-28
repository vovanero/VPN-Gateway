#!/bin/bash
# Double VPN, proven on the wire.
#
# The chain's promise is about what each observer sees: the ISP only the
# entry hop, the internet only the exit hop. Both halves are measured here
# with tcpdump and a real exit-IP lookup - not inferred from configuration,
# which is how a chain that silently fell back to single-hop would pass.
#
# Uses the first chained tunnel it finds. Disruptive: takes the entry hop
# down for ~20 seconds, which blocks every client on the chain (that block
# is one of the things being verified).

set -u

BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; DIM=$'\e[2m'; OFF=$'\e[0m'
pass=0; fail=0
ok()      { pass=$((pass+1)); printf "  ${GREEN}PASS${OFF}  %-46s %s\n" "$1" "${2-}"; }
bad()     { fail=$((fail+1)); printf "  ${RED}FAIL${OFF}  %-46s %s\n" "$1" "${2-}"; }
section() { printf "\n${BOLD}==>${OFF} %s\n" "$1"; }

token() { cat /etc/vpngw/secrets/local.token 2>/dev/null; }
api()   { curl -s -m 10 -H "x-vpngw-token: $(token)" "http://127.0.0.1:8080$1"; }

# ---------------------------------------------------------------------------
# find the chain
# ---------------------------------------------------------------------------

STATUS=/tmp/chain_status.$$
api /api/status > "$STATUS"
eval "$(PYTHONPATH=/opt/vpngw python3 - "$STATUS" <<'PYCODE'
import json, sys
snap = json.load(open(sys.argv[1]))
by = {t["slug"]: t for t in snap["tunnels"]}
exit_t = next((t for t in snap["tunnels"] if t.get("via")), None)
if not exit_t:
    print("NO_CHAIN=1")
else:
    entry = by.get(exit_t["via"], {})
    def ep(t):
        eps = t.get("endpoints") or ["?"]
        return eps[0]
    print("EXIT_SLUG=" + exit_t["slug"])
    print("EXIT_IFACE=" + exit_t["iface"])
    print("EXIT_EP=" + ep(exit_t))
    print("ENTRY_SLUG=" + entry.get("slug", "?"))
    print("ENTRY_IFACE=" + entry.get("iface", "?"))
    print("ENTRY_EP=" + ep(entry))
PYCODE
)"
rm -f "$STATUS"
if [ -n "${NO_CHAIN:-}" ]; then
    echo "no chained tunnel configured - create one first:"
    echo "  vpngwctl tunnel set <exit> --via <entry>"
    exit 2
fi
[ -n "${EXIT_SLUG:-}" ] || exit 2

WAN=$(PYTHONPATH=/opt/vpngw python3 -c \
    'from vpngw import config; print(config.Settings.load().net.wan_iface)')

section "chain under test"
echo "  ${ENTRY_SLUG} (${ENTRY_EP}) -> ${EXIT_SLUG} (${EXIT_EP}), uplink ${WAN}"

# ---------------------------------------------------------------------------
section "1. the plumbing is what the design says"
# ---------------------------------------------------------------------------

MARK=$(wg show "$EXIT_IFACE" fwmark 2>/dev/null)
case "$MARK" in
    0x1*) ok "exit tunnel's socket carries an outer fwmark" "$MARK" ;;
    *)    bad "no outer fwmark on $EXIT_IFACE" "got '$MARK'" ;;
esac

if ip rule show | grep -q "fwmark $MARK/0x1ffff"; then
    ok "ip rule sends marked packets into the entry's table" \
       "$(ip rule show | grep "fwmark $MARK" | head -1 | tr -s ' ')"
else
    bad "no ip rule for $MARK"
fi

if nft list set inet vpngw vpn_endpoints | grep -q "${EXIT_EP%%:*}"; then
    bad "exit endpoint still on the WAN allow-list" \
        "a routing mistake could greet it in the clear"
else
    ok "exit endpoint is off the WAN allow-list" "confined to the tunnel path"
fi

# ---------------------------------------------------------------------------
section "2. what each observer sees"
# ---------------------------------------------------------------------------

CAP=/tmp/chain_capture.$$
timeout 10 tcpdump -ni "$WAN" udp 2>/dev/null > "$CAP" &
CAPPID=$!
sleep 1
CHAIN_EXIT=$(curl -s --max-time 7 --interface "$EXIT_IFACE" https://api.ipify.org)
wait "$CAPPID" 2>/dev/null

if [ -n "$CHAIN_EXIT" ]; then
    ok "traffic flows through the chain" "internet sees $CHAIN_EXIT"
else
    bad "nothing came back through the chain"
fi

ENTRY_HOST=${ENTRY_EP%%:*}
EXIT_HOST=${EXIT_EP%%:*}
TO_EXIT=$(grep -c "$EXIT_HOST" "$CAP" || true)
TO_ENTRY=$(grep -c "> $ENTRY_HOST" "$CAP" || true)
if [ "${TO_EXIT:-0}" -eq 0 ]; then
    ok "ISP never sees the exit provider" "0 packets to $EXIT_HOST on $WAN"
else
    bad "exit endpoint visible on the uplink" "$TO_EXIT packets to $EXIT_HOST"
fi
[ "${TO_ENTRY:-0}" -gt 0 ] \
    && ok "the entry hop is what actually carries it" \
          "$TO_ENTRY packets to $ENTRY_HOST" \
    || bad "no traffic to the entry endpoint either" "is anything moving?"
rm -f "$CAP"

# ---------------------------------------------------------------------------
section "3. the entry hop dies"
# ---------------------------------------------------------------------------
echo "  ${DIM}taking $ENTRY_IFACE down; clients on the chain lose the internet now${OFF}"

ip link set "$ENTRY_IFACE" down
sleep 8

CAP=/tmp/chain_kill.$$
timeout 8 tcpdump -ni "$WAN" "host $EXIT_HOST" 2>/dev/null > "$CAP" &
CAPPID=$!
BLOCKED=$(timeout 8 curl -s --max-time 6 --interface "$EXIT_IFACE" https://api.ipify.org || echo "")
wait "$CAPPID" 2>/dev/null

[ -z "$BLOCKED" ] \
    && ok "chain is blocked, not rerouted" "no answer through $EXIT_IFACE" \
    || bad "chain still reached the internet" "got $BLOCKED"

LEAK=$(grep -c . "$CAP" || true)
[ "${LEAK:-0}" -eq 0 ] \
    && ok "exit handshake did not fall back to the uplink" \
          "0 packets to $EXIT_HOST while the entry was dead" \
    || bad "exit endpoint leaked onto the uplink" "$LEAK packets"
rm -f "$CAP"

# ---------------------------------------------------------------------------
section "4. recovery"
# ---------------------------------------------------------------------------

ip link set "$ENTRY_IFACE" up
DEADLINE=$(( $(date +%s) + 60 ))
RECOVERED=""
while [ "$(date +%s)" -lt "$DEADLINE" ]; do
    RECOVERED=$(timeout 8 curl -s --max-time 6 --interface "$EXIT_IFACE" \
                https://api.ipify.org || echo "")
    [ -n "$RECOVERED" ] && break
    sleep 4
done
if [ "$RECOVERED" = "$CHAIN_EXIT" ] && [ -n "$RECOVERED" ]; then
    ok "chain recovered by itself" "exit is $RECOVERED again"
else
    bad "chain did not come back within 60s" "got '${RECOVERED:-nothing}'"
fi

printf "\n${BOLD}==>${OFF} %d passed, %d failed\n" "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
    printf "${GREEN}The double VPN holds.${OFF}\n"; exit 0
fi
printf "${RED}The chain is not sound.${OFF}\n"; exit 1
