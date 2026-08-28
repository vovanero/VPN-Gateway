# Changelog

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
