#!/bin/bash
# Does the gateway come back from a cold boot, and is it fail-closed the whole
# way there?
#
# The interesting window is the one before the daemon exists. A gateway that
# only becomes safe once its own service is running has a hole every time it
# starts, and that hole is invisible from a running system - you have to
# reboot to see it. So this checks two separate things: that the box returns
# at all, and that nothing could have escaped while it was returning.
#
# Run as:  reboot_test.sh --before   (records state, then reboots)
#          reboot_test.sh --after    (compares, and reads the boot journal)

set -u

STATE=/var/lib/vpngw/reboottest
BOLD=$'\e[1m'; GREEN=$'\e[32m'; RED=$'\e[31m'; DIM=$'\e[2m'; OFF=$'\e[0m'
pass=0; fail=0

ok()      { pass=$((pass+1)); printf "  ${GREEN}PASS${OFF}  %-52s %s\n" "$1" "${2-}"; }
bad()     { fail=$((fail+1)); printf "  ${RED}FAIL${OFF}  %-52s %s\n" "$1" "${2-}"; }
section() { printf "\n${BOLD}==>${OFF} %s\n" "$1"; }
check()   { if [ "$1" = yes ]; then ok "$2" "${3-}"; else bad "$2" "${3-}"; fi; }
yesno()   { if "$@" >/dev/null 2>&1; then echo yes; else echo no; fi; }

token() { cat /etc/vpngw/secrets/local.token 2>/dev/null; }
api()   { curl -s -m 10 -H "x-vpngw-token: $(token)" "http://127.0.0.1:8080$1"; }

first_boot_stamp() {
    journalctl -b -u "$1" --no-pager -o short-unix 2>/dev/null \
        | grep -m1 -E "Started|Finished" | cut -d. -f1
}

record() {
    mkdir -p "$STATE"
    ip -br addr show | awk '{print $1, $3}' | sort > "$STATE/addrs"
    wg show interfaces 2>/dev/null | tr ' ' '\n' | grep . | sort > "$STATE/tunnels"
    api /api/status > "$STATE/status.json"

    PYTHONPATH=/opt/vpngw python3 - "$STATE" <<'PY'
import json, pathlib, sys
state = pathlib.Path(sys.argv[1])
try:
    snap = json.loads((state / "status.json").read_text())
except Exception:
    snap = {}
clients = sorted(f"{c.get('ip')} {c.get('egress_kind')}:{c.get('egress_slug')}"
                 for c in snap.get("clients", []))
(state / "clients").write_text("\n".join(clients) + "\n")
PY

    # A session issued now must still be valid after the reboot. Sessions live
    # in the database precisely so a restart does not sign the operator out,
    # and a cold boot is the strongest version of that test.
    PYTHONPATH=/opt/vpngw python3 - "$STATE" <<'PY'
import pathlib, sys
from vpngw import auth
from vpngw.db import Database
db = Database()
pathlib.Path(sys.argv[1], "session").write_text(auth.Sessions(db).issue())
db.close()
PY
}

# ---------------------------------------------------------------------------

if [ "${1-}" = "--before" ]; then
    section "recording state"
    record
    echo "  interfaces : $(wc -l < "$STATE/addrs")"
    echo "  tunnels    : $(tr '\n' ' ' < "$STATE/tunnels")"
    echo "  clients    : $(tr '\n' ' ' < "$STATE/clients")"
    echo "  session    : issued"
    echo
    echo "${DIM}rebooting now${OFF}"
    sync
    systemctl reboot
    exit 0
fi

if [ "${1-}" != "--after" ]; then
    echo "usage: $0 --before | --after" >&2
    exit 2
fi

[ -d "$STATE" ] || { echo "no recorded state; run --before first" >&2; exit 2; }

section "1. the box came back"
ok "rebooted" "up for $(cut -d. -f1 /proc/uptime)s"

NOW_ADDRS=$(ip -br addr show | awk '{print $1, $3}' | sort)
if [ "$NOW_ADDRS" = "$(cat "$STATE/addrs")" ]; then
    ok "every interface came back with the same address"
else
    bad "addresses changed across the reboot" \
        "$(diff "$STATE/addrs" <(echo "$NOW_ADDRS") | tr '\n' ' ')"
fi

section "2. fail-closed before the daemon existed"
# Compare journal timestamps rather than trusting the unit ordering to have
# been obeyed: the ordering is a request, the journal is what happened.
KS=$(first_boot_stamp vpngw-killswitch)
NET=$(first_boot_stamp networking)
DAEMON=$(first_boot_stamp vpngw)

if [ -n "$KS" ] && [ -n "$NET" ]; then
    if [ "$KS" -le "$NET" ]; then
        ok "the kill switch loaded before the network" "$((NET - KS))s ahead"
    else
        bad "the network came up first" "by $((KS - NET))s"
    fi
else
    bad "could not read the boot journal" "killswitch='$KS' networking='$NET'"
fi

if [ -n "$KS" ] && [ -n "$DAEMON" ]; then
    if [ "$KS" -le "$DAEMON" ]; then
        ok "the kill switch loaded before the daemon" "$((DAEMON - KS))s ahead"
    else
        bad "the daemon started before the kill switch" "by $((KS - DAEMON))s"
    fi
fi

if grep -qE '^net\.ipv4\.ip_forward[[:space:]]*=[[:space:]]*0' \
        /etc/sysctl.d/*vpngw*.conf 2>/dev/null; then
    ok "forwarding shipped off for the boot" "raised only after a ruleset loads"
else
    bad "forwarding was not off at boot"
fi

if [ "$(sysctl -n net.ipv4.ip_forward)" = "1" ]; then
    ok "forwarding is on now the ruleset is loaded"
else
    bad "forwarding never came on" "clients can reach nothing"
fi

REDIRECTS=""
for knob in /proc/sys/net/ipv4/conf/*/send_redirects; do
    [ "$(cat "$knob" 2>/dev/null)" = "0" ] && continue
    REDIRECTS="$REDIRECTS $(basename "$(dirname "$knob")")"
done
check "$([ -z "$REDIRECTS" ] && echo yes || echo no)" \
    "no interface teaches clients to bypass the gateway" \
    "${REDIRECTS:-clean}"

section "3. the firewall is armed"
if nft list chain inet vpngw forward 2>/dev/null | grep -q "policy drop"; then
    ok "forward chain still defaults to drop"
else
    bad "forward chain is not dropping by default"
fi

LEAKED=$(nft list counter inet vpngw wan_leak_drop 2>/dev/null \
         | grep -oE "packets [0-9]+" | awk '{print $2}')
check "$([ "${LEAKED:-1}" = "0" ] && echo yes || echo no)" \
    "nothing reached the uplink during the boot" \
    "wan_leak_drop=${LEAKED:-unknown}"

section "4. tunnels and clients returned by themselves"
sleep 2
NOW_TUN=$(wg show interfaces 2>/dev/null | tr ' ' '\n' | grep . | sort)
if [ "$NOW_TUN" = "$(cat "$STATE/tunnels")" ]; then
    ok "every tunnel came back" "$(echo "$NOW_TUN" | tr '\n' ' ')"
else
    bad "tunnels differ" \
        "was [$(tr '\n' ' ' < "$STATE/tunnels")] now [$(echo "$NOW_TUN" | tr '\n' ' ')]"
fi

api /api/status > /tmp/after-status.json 2>/dev/null
PYTHONPATH=/opt/vpngw python3 - "$STATE" <<'PY'
import json, pathlib, sys
G, R, O = "\033[32m", "\033[31m", "\033[0m"
state = pathlib.Path(sys.argv[1])
try:
    snap = json.load(open("/tmp/after-status.json"))
except Exception as exc:
    print(f"  {R}FAIL{O}  {'the daemon is not answering':52} {exc}")
    raise SystemExit(1)

now = sorted(f"{c.get('ip')} {c.get('egress_kind')}:{c.get('egress_slug')}"
             for c in snap.get("clients", []))
before = [l for l in state.joinpath("clients").read_text().splitlines() if l.strip()]
if now == before:
    print(f"  {G}PASS{O}  {'client assignments survived':52} {' '.join(now)}")
else:
    print(f"  {R}FAIL{O}  {'client assignments changed':52} was {before} now {now}")

up = [t["slug"] for t in snap.get("tunnels", []) if t.get("state") == "up"]
if up:
    print(f"  {G}PASS{O}  {'tunnels reconnected without help':52} {' '.join(up)}")
else:
    print(f"  {R}FAIL{O}  {'no tunnel came back up':52}")
    raise SystemExit(1)
PY
if [ $? -eq 0 ]; then pass=$((pass + 2)); else fail=$((fail + 1)); fi

section "5. state that had to survive"
VALID=$(PYTHONPATH=/opt/vpngw python3 - "$(cat "$STATE/session")" <<'PY'
import sys
from vpngw import auth
from vpngw.db import Database
db = Database()
print("yes" if auth.Sessions(db).valid(sys.argv[1]) else "no")
db.close()
PY
)
check "$VALID" "a panel session survived the reboot" \
    "issued before the reboot, still valid after it"

CONFIGURED=$(PYTHONPATH=/opt/vpngw python3 <<'PY'
from vpngw import auth
from vpngw.db import Database
db = Database()
print("yes" if auth.is_configured(db) else "no")
db.close()
PY
)
check "$CONFIGURED" "the admin password survived"

section "6. a client can reach the internet again"
TUN=$(wg show interfaces 2>/dev/null | tr ' ' '\n' | grep . | head -1)
WAN_IFACE=$(PYTHONPATH=/opt/vpngw python3 -c \
    'from vpngw import config; print(config.Settings.load().net.wan_iface)')
WAN_IP=$(ip -4 addr show "$WAN_IFACE" 2>/dev/null | grep -oP 'inet \K[\d.]+' | head -1)
EXIT=$(curl -s --max-time 20 --interface "$TUN" https://api.ipify.org 2>/dev/null)

if [ -n "$EXIT" ] && [ "$EXIT" != "$WAN_IP" ]; then
    ok "traffic leaves through the tunnel" "exit $EXIT, uplink $WAN_IP"
else
    bad "no tunnelled path after the reboot" "exit='${EXIT:-none}' uplink=$WAN_IP"
fi

printf "\n${BOLD}==>${OFF} %d passed, %d failed\n" "$pass" "$fail"
if [ "$fail" -eq 0 ]; then
    printf "${GREEN}The gateway survives a cold boot.${OFF}\n"
    exit 0
fi
printf "${RED}Reboot recovery is not clean.${OFF}\n"
exit 1
