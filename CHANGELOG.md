# Changelog

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
