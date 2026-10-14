# Changelog

## 2.8.4 - one command to install, and a self-test that waits for a proxy

**Installing is one command:**

```bash
curl -fsSL https://raw.githubusercontent.com/vovanero/VPN-Gateway/main/get.sh | bash
```

`get.sh` checks it is root on Debian 13, finds the newest release (never a
release candidate), downloads it and runs its installer, whose questions are
asked on the terminal even though the script arrived through a pipe. It
refuses a machine that already is a gateway - that one updates with
`vpngw-update`, through a tunnel - and refuses Ubuntu unless asked, because
the installer does not handle netplan yet and a wrong network on a remote
machine is a lockout. The whole script is functions until its last line, so a
download cut short runs nothing.

**Testing proxy exits with real proxies** - four free public ones behind a
WireGuard entry - found two things too strict and one message wrong:

- The self-test gave a request eight seconds and a lookup five. Through a
  proxy exit, measured at 2 to 5.5 seconds a request and about 2 a lookup,
  working proxies failed it. A proxy exit now gets 20 seconds.
- "Hard-coded public DNS is intercepted" used nslookup, which gives up after
  two seconds; it now uses dig with eight.
- A proxy that took every handshake but was too slow to carry a request read
  "the relay did not carry the probe", blaming the gateway. The diagnosis now
  sends the same request straight through the proxy, around the relay: if
  that fails too, it says the proxy is slow or overloaded; only if it works
  does it point at the relay.

## 2.8.3 - proxy exits work with a real proxy

The first test with a real proxy behind a real tunnel failed: "The proxy
answers, but the relay did not carry the probe." A trace inside the proxy's
namespace showed why. The health probe's connection and pxdns's lookups start
inside the namespace and are redirected into the relay, but the output hook
still sees them leaving through px0, not lo - so "oif lo accept" never matched
and the namespace dropped them. The probe could never pass, a working proxy
read as down and was taken out of routing, and its clients had no DNS. Client
connections themselves were unaffected; they arrive from outside and take a
different path.

- The namespace accepts connections redirected into its relay.
- A proxy that is already up is rebuilt when what runs in its namespace is not
  what this version builds - the ruleset, the relay's config, or its server's
  address. Without this, the fix above would only have reached proxies added
  after the update.

The negative tests had all passed: they used a proxy that never answers, and
the diagnosis, which connects without the relay, said so correctly. Only a
proxy that works could show that the relay never got a connection.

## 2.8.2 - the updater picks a tunnel the daemon has seen working

- Right after the daemon starts, every enabled tunnel is routed until its
  first probes are in, dead ones included. Run straight after a restart -
  after another update, say - `vpngw-update` picked a dead tunnel that came
  first in the list and stopped with "could not reach GitHub through fi02",
  a working tunnel beside it. It now asks the daemon which tunnels it has
  measured as up, waiting up to 30 seconds for the first measurements; with
  no daemon to ask, routed is still the test. The installer picks the same
  way.
- Installed now means installed. A package removed with its configuration
  kept still passed `dpkg -s`, so the installer would skip it for good - and
  2.8.1's redsocks repair could be fooled the same way.

## 2.8.1 - updating from 2.7.1 brings redsocks too

Updating a gateway from 2.7.1 to 2.8.0 left proxy exits unavailable: "redsocks
could not be installed". The 2.7.1 `vpngw-update` runs the new release's
installer, but it does not tell the installer which tunnel to fetch packages
through - only 2.8.0's does - so the installer fell back to plain apt, which
the armed kill switch blocks. And `vpngw-update` then said "already up to
date", leaving nothing to run.

- The installer now asks the installed gateway for a tunnel that is up when
  nobody passed one, by the same test `vpngw-update` uses, and fetches through
  it. An update from 2.7.1 straight to 2.8.1 installs redsocks.
- `vpngw-update` on a gateway that is up to date but has no redsocks installs
  the same release again, which fetches it - so the panel's advice, "vpngw-update
  installs it", is true again.

## 2.8.0 - proxies as an exit

A SOCKS5 or HTTP CONNECT proxy - a residential proxy, typically - can now be a
client's exit, the way a tunnel is. It is always chained behind a WireGuard or
OpenVPN tunnel: dialled directly, the proxy provider would see this gateway's
real address and the proxy login would cross the ISP's wire in the clear, so
there is no such mode and the model refuses to represent one.

**How it stays inside the kill switch.** Each proxy egress gets its own network
namespace, joined to the host by one veth, `px-<slug>`. The relay (redsocks)
runs inside it, unprivileged, with lo and that veth as its only interfaces. A
client's connection and the relay's connection to its server both cross the
host's forward chain, so the kill switch applies to them unchanged - and a
maintenance window, which opens only the host's own egress, cannot reach a
single proxied byte. The relay may reach exactly one address and port, its
server, and only through its entry tunnel; the host enforces that itself and
does not take the namespace's word for it. The gateway's own output chain is
byte-for-byte identical with or without proxies.

**TCP only.** A SOCKS5 or HTTP proxy carries TCP. Client UDP on a proxy egress
is refused with an ICMP error, so QUIC falls back to TCP at once; video calls,
games and VoIP do not work on such an exit, and the panel says so before a
client is assigned to one. DNS is resolved at the far end: the egress's
resolver asks over UDP, and inside the namespace that becomes TCP through the
proxy, so lookups exit where the traffic exits.

**When it breaks, it says where.** The health probe is an HTTPS request through
the relay, since ICMP does not cross a proxy. When it fails, a diagnosis run
inside the namespace speaks the proxy's protocol itself and says whether the
proxy did not answer, rejected the login, or refused to connect onward. The
login reaches redsocks as a systemd credential and the diagnosis on stdin -
never a command line - and no API returns it.

**Bounded cost.** Residential proxies are usually billed by the byte, so once
UP a proxy is re-measured every 30 s, and a DOWN one no more often: a dead
proxy must not hold the reconcile loop that every other tunnel's failover runs
in. A state on its way to changing - a first good probe after DOWN, a first
failure after UP - is measured every pass until it settles, and a relay
rebuilt with a new login, address or entry is measured on the same pass, so
the panel does not contradict a test that has just passed.

**In the panel.** "Add tunnel" has a Proxy tab. Paste what the provider gives
you - `socks5://user:pass@host:port`, `host:port:user:pass` - and it becomes
fields, with the password moved out of the address into a masked field at
once. "Route through" is required and lists only tunnels that can carry a
proxy, fastest first; there is no "directly". Add proxy saves it, tests it
through the chain, and keeps it only if it works: otherwise it is deleted
again and the form stays as it was, saying which link broke. Proxies appear
in the chains section, with Change entry in place of Unchain; in a group of
their own in the client exit list, with "TCP only" beside each and a notice
the moment one is picked; and as unpickable rows in the pool builder. A
proxy's drawer leads with what is wrong and the button that fixes it - Change
login when the login was rejected, Open the entry tunnel when that is down -
then draws the path hop by hop, red only where it broke.

**Proven, not claimed.** With a proxy as its exit, `vpngwctl selftest` adds
four checks, each watched on the uplink, inside the entry tunnel and on the
veth into the namespace: the client exits with the proxy's address and not
the entry's; the proxy server is reached through the entry and never appears
on the uplink; client UDP is refused and turns up nowhere; and a lookup of a
fresh name is answered without that name ever appearing as plain DNS past the
namespace. `--disrupt` then stops the relay - nothing may reach the internet
through the entry instead - and takes the entry down - the relay must not
reach for its server over the uplink - with the proxy's route kept in place,
so it is the namespace that refuses, not the routing blackhole. The panel's
leak test can now be pointed at any live exit, a proxy included.

**Found while proving it.** The resolver unit is bound to the relay and stops
with it; when the relay crashed and systemd restarted it, nothing restarted
the resolver, so the proxy stayed "up" - its probe asks for an address, not a
name - while every client of it had lost DNS. The relay unit now upholds its
resolver, and the health check also requires the resolver to be running.

**Also in this release.**

- The OpenVPN username and password from the import dialog travelled in the
  URL's query string. They now go in the request body, with the file.
- The page names `app.js` and `app.css` by their content. Browsers reuse those
  files for hours on a heuristic, which after an update ran an old script
  against a new page.
- The short-name fields' pattern was not valid under the `v` flag that current
  browsers compile patterns with, so it was dropped and checked nothing; the
  server's own check was the only one.
- A proxy that wants a login, and one that takes none, are told apart from a
  rejected password: three different fixes, three different messages.

redsocks is an optional package, installed through the tunnel `vpngw-update`
fetches the release through, over HTTPS, and checked by apt against the signed
index - on an armed gateway plain apt is blocked, and the plain-HTTP sources
would have read the package names out to the ISP.

Not in this release: proxies in pools, UDP, TLS to the proxy itself
(`https://` proxy URLs), and Shadowsocks or Trojan.

## 2.7.1 - the updater picks a tunnel that works

`vpngw-update` chose the first enabled tunnel whose interface existed. A
WireGuard device exists from the moment it is configured, handshake or not, so
on a gateway whose first tunnel had never connected the update failed with
"could not reach GitHub through fi02" - refusing safely, but refusing. The
comment above the code already said the test was "interface exists and the
table has a real default route"; the code only did the first half.

It now requires the route, the same "routed" test the panel shows. The README
bootstrap had the same flaw and the same fix. This is the bug fixed in the
self-test in 2.6.x, found again in a second place - so a test now checks every
place that picks a tunnel to use.

## 2.7.0 - three leaks closed before proxies arrive

Found by a six-lens leak audit with independent verification, and by the
design work for proxy egress. None of them put a client's real address on the
internet. All of them leaked something the gateway promises to keep, and the
first two went unnoticed because nothing tested for them.

**A chained tunnel's server name was looked up over the uplink.** The exit
provider's hostname went to the bootstrap DNS in plaintext - telling the ISP
exactly which provider sits behind the first hop, which is the one fact a
double VPN exists to hide. It leaked from three places, each now closed:

- vpngw's own resolution, at import and every fifteen minutes. Chained names
  are now asked of the parent egress's resolver, whose upstream already
  leaves through the tunnel. If it cannot answer, the name stays unresolved:
  there is no fallback to the uplink.
- `wg setconf`. WireGuard resolves a hostname `Endpoint` itself, through the
  system resolver, every time the tunnel comes up. A chained tunnel is now
  handed the address resolved through its parent and never a name; with no
  safe address it is not brought up at all, and comes up by itself once the
  parent can answer.
- OpenVPN, which does the same with `remote` lines. Named remotes on a
  chained tunnel are pinned to the resolved addresses, literal remotes are
  kept as they were, and with nothing safe left the tunnel does not start.

**A chained tunnel's endpoint briefly sat on the WAN allow-list.** The full
ruleset render and the incremental sync built `@vpn_endpoints` separately,
and only the sync left chained tunnels out - so every structural rebuild put
the exit provider's address on the list for one reconcile pass. Both now call
one function.

**An unregistered client could use any tunnel's DNS.** The DNAT that pins a
client to its own resolver keys on the client map, and a source missing from
it - never registered, disabled, or assigned to a tunnel that is off - simply
missed it. The input chain then accepted its query to any address in the
resolver range, so a machine the operator believed was fully blocked had a
working, two-way DNS channel and could pick its exit country by changing the
last octet. Resolver access now requires the client's fwmark, which exactly
the registered, assigned clients carry. The `dns_hijacked` counter, which
counted those misses as hijacks, now counts only real ones.

The self-test gains the check that would have caught it - "a client with no
exit cannot use any resolver" - which asks every live resolver directly from
the unassigned test client. The probe it already ran never asked a resolver.

**A row this version does not know no longer stops the daemon.** Rolling back
past a release that adds a tunnel kind used to leave rows that made every
`db.tunnels()` raise. Unknown kinds are now skipped, which is fail-closed:
their interfaces are never built and their clients are dropped. Shipped ahead
of proxy egress so that a later rollback is safe.

## 2.6.0 - the MTU is measured, and the exit address has a country

**The gateway measures the path instead of trusting the interface.** 2.5.0
derived a chained tunnel's MTU from the interface carrying it, which is right
until the uplink is itself a client of another gateway - the exact shape of a
two-machine double VPN. Locally everything reads 1500; the real limit was
1380, and the arithmetic answer was 80 bytes too generous.

That is not a slow tunnel, it is a dead one. Measured on the reference pair,
a fresh tunnel at the derived MTU:

    1420   download 0.00 Mbps   upload 0.00 Mbps
    1320   download 7.44 Mbps   upload 7.45 Mbps

So the tunnel's endpoint is now probed directly with DF pings, bisecting to
the byte, and the MTU comes from what actually got through. On the reference
pair it lands on 1320 for both tunnels in about eight seconds - the same
number that was found by hand.

- An endpoint that ignores ICMP is not read as a tiny path. That is a
  separate small probe, because "no answer" and "narrow path" are opposite
  conclusions drawn from the same silence.
- Results are cached per endpoint, so a reconcile pass does not re-probe, and
  a provider moving you to another server does.
- `vpngwctl tunnel set <slug> --mtu 0` hands the decision back to the
  gateway. It used to read as "no argument given" and silently keep whatever
  was set, so an operator who had pinned an MTU had no way to unpin it.

**The exit address carries a country**, looked up offline. `geoip-database`
and `geoip-bin` are now installed, and nothing leaves the machine to answer
the question - a privacy gateway should not be making a call about its own
exit address every time a dashboard refreshes.

The data is Debian's legacy GeoIP, frozen on 2019-12-24, so a lookup can be
out of date and has no way to know it. It is shown as a hint under the
address, never instead of it, and every kind of "we do not know" - no
database, private range, unknown range, failed lookup - renders as nothing
at all rather than a guess.

## 2.5.0 - a chained tunnel sizes itself to what carries it

A WireGuard tunnel took a flat 1420 MTU no matter what it rode on. For a
chained tunnel that is wrong by 100 bytes: its encrypted packets are 60 bytes
larger than the plaintext inside them, and they have to fit the parent tunnel,
which is typically 1380.

The failure is the nastiest kind. The tunnel comes up. The handshake
completes. `status` says up. Small packets work, so browsing looks fine and
the health probe passes. Large ones vanish. What an operator sees is a
download at full speed and an upload that does not move, with nothing in any
log to say why.

Measured on the reference pair, before and after, on a chained tunnel whose
parent is 1380:

    upload   0.87 Mbps  ->  5.44 Mbps
    download  110 Mbps  ->    88 Mbps

The MTU is now derived from whatever carries the tunnel - the parent tunnel
when chained, the uplink otherwise - minus the 60 bytes of overhead. 1420
stays the *ceiling* rather than becoming a starting point: a plain 1500-byte
uplink would allow 1440, but paths lie about their size often enough that
raising the default for everyone to gain 20 bytes is a bad trade. This only
ever moves the MTU down, and only when something says it must. An MTU the
operator set by hand is never overridden.

## 2.4.3 - a custom config without PersistentKeepalive could never come up

Import a hand-written WireGuard config with no `PersistentKeepalive` line and
you got an interface that was up, a peer that was configured, and zero bytes
transferred. Forever. No error, nothing in the log, `no handshake yet` in
`status` and no way to tell why.

It is a deadlock, and this gateway's own design closes it:

- WireGuard only handshakes when it has something to send.
- Nothing has anything to send until the tunnel is healthy.
- Health is measured by a probe *through* the tunnel.
- Until the tunnel is healthy its egress table holds a blackhole, by
  design - that is the kill switch - so the probe cannot get out.

The keepalive is the one thing that breaks the circle, and every provider
config we had shipped one, which is exactly why this survived four releases.
Mullvad, NordVPN, IVPN - all carry the line. A config written by hand, or by
a provider that leaves it out, does not.

`PersistentKeepalive` is now always sent, defaulting to 25 seconds when the
config does not name one; a config that *does* name one still wins. Existing
tunnels are fixed by the next render - no re-import.

Diagnosed on a live gateway: adding the keepalive by hand completed the
handshake in 11 seconds on a tunnel that had been down since import.

Also in this release, from the same session:

- `docs/operations.md` said the panel "is bound to the management interface
  only" and pointed at a host address from the three-adapter lab. It has not
  worked that way for some time: the panel listens everywhere and
  `admin_ifaces` decides who gets through. Rewritten, with the commands to
  check it.
- Two new troubleshooting entries for symptoms that read as hangs rather than
  failures: anything on the gateway reaching the internet (it is the kill
  switch; `vpngwctl maintenance` is the escape hatch), and updating a gateway
  that has no tunnel of its own.

## 2.4.2 - the installer stops asking apt for a package that does not exist

Two bugs a second machine found. Neither failed anything; both wasted an
operator's afternoon.

**`dnsutils` is not a package on Debian 13.** It is a name `bind9-dnsutils`
provides, so `dpkg -s dnsutils` never reports it installed - and install.sh
put it in the missing list on *every single run*, on a fully provisioned
gateway, and went to the mirrors for it. With the kill switch armed the
gateway's own egress is dropped by design, so `apt-get update` sits through
its timeouts before carrying on. An update that looks like it has hung is an
update people interrupt, which is exactly what happened. The installer now
asks for `bind9-dnsutils`, finds nothing missing, and never calls apt.

`dig` joins the `command -v` check, since the installer installs it.

**The summary described a machine that did not exist.** When `vpngw.toml`
already exists the installer keeps it - correctly - but then printed the
layout it had *detected*, not the one in force. On a box whose client network
is 10.0.0.1/24 the summary said 10.20.0.1/24 and pointed the operator at a
panel URL that answers nowhere. It now reads the kept config back through the
daemon's own parser before printing anything, so the summary and the daemon
cannot disagree.

Both are pinned by tests: no virtual package names in the package list, `dig`
in the tool check, and the config read back between "left alone" and the
summary.

## 2.4.1 - do not install 2.4.0

`vpngw/__init__.py` shipped empty in 2.4.0. An empty module imports fine and
fails at the first attribute, so every test passed and the daemon crashed on
its first `/api/status` with `module 'vpngw' has no attribute '__version__'`.

Caught in production by the thing built for it: `vpngw-update` saw the new
daemon fail to answer, restored 2.2.0 and said so. Nothing was lost.

The test suite now checks the bytes rather than only the parse - no shipped
`.py`, `.js`, `.css` or `.html` file may be zero-length, `__version__` must
exist, and it must match the newest heading in this file. That last one also
stops a stale version number making an up-to-date box offer to update forever.

This is the second time a bad edit has written a file to zero bytes and the
tests have shrugged (`app.js`, in 2.2.0). It is now the kind of mistake that
fails loudly.

## 2.4.0 - NordVPN asks for a token, and the updater installs itself

**NordVPN takes an access token now.** The old field wanted a WireGuard
private key, which meant installing NordVPN's own client on some other
machine, connecting it, and reading the key out of the running interface
with `wg show nordlynx private-key`. That was never necessary: NordVPN's API
hands the NordLynx key to anyone holding the account's access token, and the
token is a string you copy off the account page.

- The exchange happens once, at connect. What is written to
  `/etc/vpngw/secrets` is the same private key it always was.
- **The token is not stored.** It can manage the account; the key it buys
  can only build a tunnel, and a tunnel is all this box needs.
- The key field is still there, marked optional, for operators who already
  have one. `AuthField` grew a `required` flag so an either/or dialog is
  possible at all - before this, the login endpoint rejected any submission
  with an empty field, so a token-or-key choice could never have been
  submitted.
- The reply is parsed by field name first and by key *shape* second, so a
  rename at NordVPN costs nothing. A reply with no key at all names the
  fields it did contain - names only, since the values include the OpenVPN
  password.

**`install.sh` installs `vpngw-update`.** For three versions the updater
shipped inside the release you did not have yet, which is a fine way to make
a gateway unupdatable. Every install from here leaves the command on the box:

    vpngw-update --check
    vpngw-update

- `provider_login` no longer answers in Turkish.

## 2.3.0 — updating, without phoning home

`scripts/update.sh` fetches a new version **through a tunnel** and refuses to
run without one.

A panel button that polls GitHub was the obvious design and the wrong one: a
privacy gateway that reaches out on a timer tells whoever is watching that
this address runs a VPN gateway and which version, which is the sort of thing
the box exists to prevent. Updating is something the operator runs, not
something the box does.

- Both the name lookup and the download go through a tunnel's own resolver
  and interface, so GitHub sees the VPN exit rather than the uplink.
  Measured: zero packets to GitHub on the uplink during a fetch.
- **No firewall change.** The output chain already permits
  `oifname @tun_ifaces accept` — traffic leaving through a tunnel is safe
  because it is encrypted — so a gateway that never updates has no hole
  waiting to be used.
- The running tree is copied aside and a rollback timer armed *before*
  anything is replaced, the same commit-confirm shape as an uplink change.
  If the new daemon does not answer, the old one comes back by itself;
  `--rollback` does it on demand.
- Verified on the reference gateway by downgrading 2.2.0 → 2.1.0 and back:
  tunnels stayed up, client assignments, settings and the panel password all
  survived both directions.
- `--check` reports installed and available and changes nothing.

## 2.2.0 — the network, drawn

Overview could say a great deal about tunnels and nothing about the network
under them. On a fresh gateway it showed "Kill switch armed", four zeros and
an empty chart — accurate, and no help at all with the question an operator
actually opens the page to ask: is this thing connected?

- **The uplink is measured, link by link.** `wanhealth.py` probes carrier,
  address, upstream router, internet and DNS once per reconcile pass, with
  the same hysteresis as tunnel health, and reports *which link is the first
  to fail*. One green light would have to pick a meaning among several that
  come apart in practice, and be wrong the rest of the time.
- **A downstream success vouches for an upstream probe.** Found by running
  it: the reference gateway's own router drops ICMP addressed to itself while
  forwarding perfectly, so the first version reported a broken uplink on a
  box whose internet demonstrably worked. Traffic that arrives outranks a
  ping that does not — but only reachability probes may vouch, because a
  static address survives the cable being pulled and must not be allowed to
  prove the cable.
- **Overview opens with a drawing**: internet, the tunnel the traffic runs
  through, this gateway, and the clients — with live wires that animate while
  traffic moves, the exit address above the tunnel, and one sentence naming
  the break when there is one. Below it, uplink and client-network cards
  carrying protocol, address, gateway, DNS and client counts.
- No new fetch: the measurement rides the snapshot the panel already polls.
  `GET /api/network/wan`, written long ago and called by nothing, now serves
  the same record instead of a check that reported "unknown" forever on a
  DHCP uplink.
- `check_js.py` refuses a file under 2 KB. It called a truncated `app.js`
  "brackets balanced" — which is how a destroyed panel ships: the check ran,
  it passed, and nobody looked.

## 2.1.0 — a tunnel can be chained from its first packet

Asked by a user setting up a second provider for a double VPN: how do I
make sure the new provider never sees my real address, not even once?

The honest answer was that they could not, from the panel. An imported
tunnel was enabled immediately, so the reconcile loop's next pass sent a
handshake over the uplink and the new provider's relay logged the WAN
address before anything could be chained. Chaining afterwards does not
take that record back.

- **Import takes a parent.** The tunnel is created disabled, chained, and
  only then enabled — inside the one request, where no reconcile pass can
  observe the gap. Measured on the reference gateway with tcpdump: **zero
  packets** to the new provider on the uplink, at import and at rest.
- **A refused chain leaves the tunnel switched off**, rather than falling
  back to an unchained live tunnel — which would be the same leak with
  extra steps. The error says so.
- The import dialog offers "Route through", so the safe order is also the
  default one; `POST /api/tunnels/import` takes `via`.

Still true, and worth saying plainly: this hides your *network location*
from the exit provider, not your identity. The account number already
identifies you, and a chain only means something across two different
providers. Provisioning a tunnel through a provider's own API still
contacts that API from the uplink — import a config file obtained
elsewhere if that matters.

## 2.0.2

Reported by a user who could not get out of a corner the panel had put
them in.

- **"Remove account" had no endpoint behind it.** The panel called
  `POST /api/providers/{id}/logout`; the route was never written, so the
  button answered 404 for the life of the project. A provider account
  could be added from the panel but only removed with `vpngwctl` — and
  because a second account cannot be stored while the first one is, the
  operator was locked to whichever account they first typed in. The route
  now exists, forgets the credentials, closes the provider's API access,
  and leaves already-provisioned tunnels alone: they hold their own keys.
  A test now asserts that every provider path the panel calls exists in
  the API, so a UI-only route cannot go missing again.
- **Deleting something that was not there reported success.** All three
  delete endpoints answered 200 for an unknown id, so the panel said
  "Pool deleted" and refreshed while nothing had happened — worst exactly
  when something else is already wrong, such as a stale page or a slug
  that is not what the operator thinks it is. Each now looks the resource
  up and 404s, matching every other verb on the same paths.
- **Deleting a tunnel was a dead end.** Refusing to delete a tunnel a
  client still points at is correct — a dangling exit means a client with
  no internet — but the panel relayed the refusal as a toast and stopped
  there. It now names the blocker before asking: a double VPN that must be
  dissolved, a pool the tunnel belongs to, or the clients using it, and in
  the last case offers to unassign them as part of the delete.

## 2.0.0 — double VPN

Route one tunnel through another: the ISP sees only the entry hop, the
internet only the exit hop, and no single provider sees both who you are
and where you go.

- **Chains are a property, not an object.** A tunnel gains `via`; chained,
  its encrypted packets are fwmarked into the parent's routing table. The
  parent's existing blackhole extends the kill switch through the chain —
  a dead entry hop blocks the chain even with the daemon dead.
- **Confinement, measured.** A chained tunnel's endpoint leaves the WAN
  allow-list entirely. `tests/chain_test.sh` proves it with tcpdump: zero
  packets to the exit provider on the uplink, chain up or down (9/9 on the
  reference VM, with the v1 suites re-run green alongside).
- **Panel.** A Double VPN section draws each chain as a path — ISP → entry
  → exit → internet — with per-hop health, end-to-end latency, effective
  MTU, a two-dropdown builder and one-click dissolve. Client dropdowns
  label chained tunnels honestly: `ca01 — double VPN via nl01`.
- **Everything composes.** A chained tunnel is still a tunnel: pools accept
  it as a member, so `pool: [chain, single]` gives active/passive between
  double VPN and a plain fallback.
- MTU: derived from the parent when unset (each hop costs ~80 bytes), and
  MTU edits now land on live interfaces without a re-up.
- `vpngwctl tunnel set <exit> --via <entry>` / `--via -` from the CLI;
  ceiling of two hops enforced with cycle and endpoint-clash validation.
- Migration is one ALTER TABLE, run automatically and idempotently.

## 1.1.1

- **No history by default.** A privacy gateway should hold no record of its
  own network unless the operator turns recording on. The journal is silent,
  the Events table stops filling, and both are controlled from the panel:
  Settings → Privacy & logging, `none` (default) / `normal` / `high`. Client
  traffic — DNS queries, connections — was never logged at any level and
  still is not; this governs only the gateway's operational records.
- **Access-control changes apply immediately.** Management interfaces,
  client interfaces and client networks are now part of the ruleset
  fingerprint, so unticking WAN in the panel rebuilds the firewall on the
  spot instead of after the next restart — "saved" no longer means
  "will be true later".
- Management checkboxes are labelled by role (LAN / WAN / MGMT) with the
  interface name alongside, and the WAN row is marked *exposed*.
- README: a rendered diagram of per-interface management access.

## 1.1.0

Found by a user actually plugging a Windows client into the LAN side — which
is the test no amount of self-testing replaces.

- **The LAN bridge answers with the member NIC's MAC.** The kernel gives a new
  bridge a random address, and under Hyper-V that is fatal invisibly: with MAC
  spoofing off (the default), the virtual switch drops any frame whose source
  MAC is not the one it assigned to the vNIC. Inbound still arrives, so the
  gateway sees clients ARP for it — it just cannot answer. From the client
  that reads as "destination host unreachable" to an address that is provably
  up. The bridge MAC is now pinned to the member's, which also stops it
  drifting when the leak test attaches its veth.
- **Management access is per interface now, like a router.** `admin_cidr`
  (source-range filtering on the uplink) is gone; the panel and SSH answer on
  the interfaces listed in `admin_ifaces`, defaulting to the LAN bridge plus
  the management interface. Ticking the uplink is an explicit choice in the
  panel's Access control card. Old configs with `admin_cidr` still load.
- **cli2mark no longer rewrites every five seconds.** Marks were written as
  `0x0001` and read back from the kernel as `1`; the comparison saw a
  difference on every pass and deleted + re-added the whole map, leaving
  moments in which a client's packets carried no mark. Values are now compared
  canonically.
- **Client deletions are logged.** Two clients vanished with nothing in the
  event log to say so; the silence cost an hour of suspecting database
  corruption. Every removal now leaves a trace.
- README gained rendered diagrams (Mermaid) of the packet path, the
  kill-switch layers, DNS capture and pool failover.

## 1.0.0

First release. Verified end to end on Debian 13 under Hyper-V, with a Windows
client browsing through a commercial WireGuard provider and every suite green:
139 unit tests, 15 release checks, 14 leak checks, 9 pool-failover checks and
15 cold-boot checks.

### The gateway

- **Fail-closed by construction.** `forward` policy `drop`, forwarded traffic
  admitted only out `@tun_ifaces`, and a `blackhole default metric 1000` in
  every policy table so clients stop reaching the internet even when the daemon
  is dead, stopped, or was never started.
- **Per-client exits.** Each client is pinned to one tunnel or to a pool, by
  fwmark and its own routing table.
- **Pools with failover and stickiness.** Health is measured with hysteresis so
  a single lost probe does not move anyone; recovery does not immediately move
  them back.
- **WireGuard and OpenVPN side by side.** WireGuard is driven without
  `wg-quick`, and provider `.ovpn` directives that would rewrite the routing
  table or `/etc/resolv.conf` are stripped before use.
- **DNS that cannot escape its tunnel.** Every `:53` query is redirected to a
  per-egress resolver bound to that egress's source address, so a client
  hard-coding `8.8.8.8` is answered by the gateway rather than obeyed.
- **Providers.** Mullvad, NordVPN, IVPN and Surfshark, plus any WireGuard or
  OpenVPN config file.

### Panel

- Router-style Settings: live interface status, WAN with `Automatic (DHCP)` or
  `Static IP`, dotted subnet masks, a LAN card that shows the resulting network
  as you type, DHCP, and per-interface access control.
- **Commit-confirm for the uplink.** Applying a new WAN address arms a rollback
  first; the change becomes permanent only when someone reaches the panel on
  the new address and confirms. Nothing about it requires console access to
  undo.
- Password-protected, with sessions that survive a restart.
- Unregistered machines seen on a client interface are surfaced with a
  one-click Register button, because a blocked machine and a switched-off one
  look identical otherwise.

### Fixed during release testing

Each of these was found by running the thing rather than reading it.

- **ICMP redirects were being sent on every interface.** The kernel ORs
  `send_redirects` across `conf.all` and `conf.<iface>` rather than ANDing it,
  so setting only `conf.all = 0` left it on. Where clients share a segment with
  the real router — the common Hyper-V lab layout — the gateway was telling
  unregistered clients to route around it. Those clients then never reached the
  box again, so no rule saw them, no counter moved, and the leak test could not
  detect it. Now cleared per interface, shipped in the boot-time sysctls, and
  covered by a leak-test check.
- **`[wan]` and `[dhcp]` were written but never read.** `Settings.load()` was
  missing both sections, so uplink and DHCP settings saved from the panel
  reverted to their defaults on the next read — silently, and for the uplink
  the default is "use DHCP". Every section now round-trips, with a test that
  fails if a new one is added and forgotten.
- **The uplink was defined twice under ifupdown.** Debian's own
  `/etc/network/interfaces` defines the interface *and* sources
  `interfaces.d/*`, so the generated drop-in became a second definition that
  ifupdown ignored: every step reported success and the address never moved.
  The original stanza is now disabled reversibly.
- **`/etc/resolv.conf` was nobody's job.** With no `resolvconf` installed,
  `dns-nameservers` does nothing, and a DHCP run replaces the file with an
  empty template — after which the gateway cannot resolve the hostname of the
  next endpoint it is asked to connect to. The daemon now owns the file and
  points it at the bootstrap servers, which are the only ones the firewall
  lets it reach.
- **Panel sessions died on every restart.** They lived in memory, so an
  upgrade, a settings change, or a crash signed the operator out. They are now
  stored as hashes in the database and survive a cold boot.
- **`vpngwctl` locked itself out.** Once a panel password existed the CLI got
  401 — including `vpngwctl passwd`, the documented way back in after
  forgetting it. It now authenticates with a root-only token.
- **The panel polled from behind the sign-in card**, producing a console full
  of 401s and a "cannot reach the daemon" toast that blamed the wrong thing.
- **Empty required fields were outlined red before anyone typed in them**
  (`:invalid` → `:user-invalid`).
- **The LAN preview counted the gateway's own address as assignable**, so
  `10.10.0.1/24` advertised `10.10.0.1 – 10.10.0.254` as client range.
