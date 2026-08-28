# v2 — chained tunnels (double / triple VPN)

The v2 headline: route one tunnel *through* another, so a client's traffic
enters the internet through two (or three) VPNs in series.

```
client → gateway → [entry: Mullvad SE] → [exit: IVPN CH] → internet
                    ISP sees only this    exit IP is this
```

What it buys: no single provider sees both who you are and where you go.
The entry provider knows your address but only sees encrypted traffic to the
exit provider; the exit provider sees your destinations but only the entry's
address as their source. Cross-provider chains are the point — two arms of
the same company share one legal jurisdiction and one logging policy.

What it does not buy: protection against browser fingerprinting, payment
trails, or an observer who can watch both ends at once. The docs will say so.

## Design: `via`, not a new object

A chain is not a new entity. A tunnel gains one optional field:

```
via = ""        # normal tunnel: encrypted packets leave over the WAN
via = "nl01"    # chained: encrypted packets leave through tunnel nl01
```

A chain of three is just `c.via = b`, `b.via = a`. Everything the tunnel
already owns — esid, routing table, resolver, health, pool membership,
client assignment — keeps working unchanged, because nothing about the
tunnel's *inside* changes; only where its *outside* goes.

Clients are assigned to the exit tunnel, exactly as they are assigned to any
tunnel today. Assigning a client to a chained tunnel is what "using the
chain" means.

## Mechanism

**Outer fwmark.** Every chained tunnel's encrypted (outer) packets are
marked by the tunnel's own socket — WireGuard's `FwMark`, OpenVPN's
`--mark`. Client esids live in the low 16 bits of the mark space; outer
marks are `0x10000 | esid`, a disjoint range, matched with mask `0x1ffff`.

**One ip rule per chained tunnel**, at priority 850 — after the
locally-connected rule (800), before every client rule (1001+):

```
fwmark 0x10000|esid / 0x1ffff  lookup <parent's table>
```

The parent's table already contains exactly the right thing: a default via
the parent interface at metric 100, and a blackhole at metric 1000. If the
parent dies, the kernel withdraws its route and the child's handshake
packets fall into the blackhole — the kill switch extends through the chain
without any new machinery, and without depending on the daemon being alive.
This is also wg-quick's own loop-prevention design; v1 drives WireGuard
without wg-quick, so the mark space was sitting unused.

**Endpoint confinement.** `@vpn_endpoints` (the WAN allow-list) only carries
the endpoints of tunnels *without* `via`. A chained tunnel's endpoint is
deliberately absent: its handshake is allowed out through `@tun_ifaces`
(already permitted) and nothing else, so it cannot escape to the uplink even
if the routing layer misbehaves. Metadata matters here — the ISP seeing a
handshake to the exit provider would break the chain's whole promise.

**MTU.** Each WireGuard layer costs 60–80 bytes. Chained tunnels compute
their MTU automatically from the parent's (`parent − 80`), the existing MSS
clamp handles TCP from there, and the health probe gains a DF-flagged
full-size ping so an MTU blackhole fails the health check instead of
presenting as "DNS works, HTTPS hangs".

**Health across the chain.** Each hop keeps its own health (handshake age +
probe through its interface — which for a chained tunnel already traverses
the parent). The steering step treats a tunnel as down when any ancestor is
down, so clients are blackholed promptly instead of waiting for the child's
handshake to age out.

## Limits and validation

- **Max 3 hops.** Each hop costs MTU, latency, and roughly half the
  remaining throughput. Two is the sweet spot; three is the ceiling.
- No cycles (`a.via = b`, `b.via = a` is refused), no self-reference.
- A chained tunnel's endpoint sharing an IP with a non-chained tunnel's is
  refused: the shared IP would have to stay on the WAN allow-list, which
  quietly weakens the confinement above.
- Deleting or disabling a tunnel that others ride through is refused while
  they do.

## Panel

A **Chains** section on the Tunnels page, drawn as the thing it is — a path:

```
[ ISP ] ──► [ nl01 ● 13ms ] ──► [ ca01 ● 149ms ] ──► [ internet · exit 149.22.81.199 ]
```

- Each hop is a node with its own live health dot, latency, and name; the
  exit node shows the measured exit IP. A sick hop is visibly the sick node.
- **Builder, diagram-style:** pick an exit tunnel, click *route through* to
  insert a parent, again for a third hop (the UI stops at three). Saving
  writes the `via` fields. Dissolving a chain is one click and touches
  nothing but `via`.
- The client-assignment dropdown labels chained tunnels as what they are:
  `ca01 — chain via nl01`.
- Effective MTU and summed latency shown per chain, because those are the
  two numbers that explain "why is it slower".

## Test plan

Unit: via validation (cycle, depth, missing parent), endpoint-set exclusion,
outer-rule rendering, MTU derivation, migration idempotence.

Live (`tests/chain_test.sh`):
1. chain up → netns client exits with the exit tunnel's IP
2. tcpdump on the uplink sees **only the entry's endpoint** — zero packets
   to the exit's endpoint (the chain-specific leak)
3. entry killed → client blackholed, nothing reaches the uplink, exit
   endpoint still absent from the uplink
4. entry restored → chain recovers without intervention
5. dissolve → tunnel reverts to a normal single-hop

## Order of work

1. Core: model + migration, fwmark plumbing (wg `FwMark`, ovpn `--mark`),
   outer ip rules, endpoint confinement, MTU derivation, ancestor-aware
   steering. `vpngwctl tunnel set <slug> --via <parent>`.
2. Panel: chain section + builder, per-hop health, dropdown labels.
3. `chain_test.sh` green on the reference VM.
4. Later, separately: chains as pool members verified end-to-end; DF probe
   in health; provider-native multihop (e.g. Mullvad's) as a shortcut.
