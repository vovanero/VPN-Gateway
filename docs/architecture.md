# Architecture

Why the pieces are shaped the way they are. If you only read one section, read
[Marks and tables](#marks-and-tables) — everything else follows from it.

---

## The shape of the problem

Ten client VMs, each needing a different internet exit, and an absolute rule
that none of them may reach the internet except through a tunnel.

Those two requirements pull in opposite directions. Per-client routing wants
flexibility: many paths, changing at runtime. The kill switch wants rigidity:
one path, and no fallback ever. A design that treats them separately ends up
with a firewall that permits what the routing table happens to do — which is
how most VPN routers end up failing open.

So they are the same mechanism here. A client's egress and the kill switch are
two readings of one number.

## Marks and tables

Every egress — a tunnel or a pool — gets an **egress selector id** (esid),
allocated once and never reused while it exists:

```
esid 0            unassigned. Forwarding this is a bug; the firewall drops it.
esid 1    .. 999  individual tunnels
esid 1000 .. 1999 pools
```

From that one number everything else is derived arithmetically, with no
bookkeeping to get out of sync:

| Derived from esid | Value | Where |
|---|---|---|
| fwmark | `esid` (low 16 bits) | `render/nftables.py` |
| routing table | `100 + esid` | `config.table_for()` |
| `ip rule` priority | `1000 + esid` (mark), `900 + esid` (resolver) | `net/routing.py` |
| DNS resolver address | `10.99.0.0/21 + esid` | `config.DnsSettings.resolver_ip()` |

Because the mapping is arithmetic rather than allocated, it survives a restart,
a database restore, and a hand-edited config. The price is that the resolver
subnet must be wide enough for the whole esid range — `Settings.validate()`
checks that at startup, which is how the original `/24` was caught.

### The path of a client packet

```
   client 10.10.0.11
        │
        │  br-lan
        ▼
   ┌──────────────────────────────────────────────┐
   │ prerouting (mangle)                          │
   │   meta mark set ip saddr map @cli2mark  → 1  │   stateless: looked up
   │   ct mark set meta mark                      │   on every packet
   └──────────────────────────────────────────────┘
        │
        ▼
   ┌──────────────────────────────────────────────┐
   │ ip rule  fwmark 1 → table 101                │
   │ table 101:  default dev wg-nl01 metric 100   │  ← tunnel alive
   │             blackhole default  metric 1000   │  ← the failsafe
   └──────────────────────────────────────────────┘
        │
        ▼
   ┌──────────────────────────────────────────────┐
   │ forward (policy drop)                        │
   │   oifname $WAN                        → drop │
   │   oifname != @tun_ifaces               → drop│
   │   iif $LAN oif @tun_ifaces mark != 0  → accept│
   └──────────────────────────────────────────────┘
        │
        ▼  wg-nl01, masqueraded
```

Classification is deliberately **stateless** — the source address is looked up
on every packet rather than pinned at flow start — so reassigning a client in
the UI takes effect on the next packet instead of whenever its flows expire.
The conntrack mark is maintained for one reason only: `conntrack -D -m <mark>`
on failover.

### Why pools cost nothing extra

A pool is an egress like a tunnel is: same esid space, same table, same mark.
The only difference is that its table's default route is repointed as members
come and go.

That means failover is one `ip route replace`, regardless of how many clients
are on the pool. Ten clients do not need ten updates, and there is no window
where half of them have moved. It also means "assign this client to a pool" and
"assign it to a tunnel" are literally the same code path — see `models.Egress`.

## The single writer

Everything that touches kernel state goes through one loop in one thread
(`reconciler.py`). The API and the CLI only write to the database and ask for a
reconcile; neither touches nftables or the routing table.

The behaviour of the box is therefore a function of its database, not of the
order in which somebody clicked things. A reconcile pass is idempotent, so
running it twice is harmless and running it after a crash is a repair.

Order within a pass is chosen so no step can open a gap:

1. **firewall** — before anything can route
2. **routes** — blackholes exist before real defaults do
3. **tunnels** — only now can traffic actually move
4. **health** — observe
5. **steering** — point tables at healthy tunnels, blackhole the rest
6. **resolvers** — last, they depend on the routes above

Step 2 before step 3 is the one that matters. A tunnel coming up before its
table has a blackhole would, for that instant, have a table with no default at
all — and a table with no default falls through to the main table, which
reaches the uplink.

### Structural versus element changes

Rebuilding the whole ruleset resets the nftables counters, and those counters
are the evidence the kill switch works. So the reconciler distinguishes:

* **structural** (a tunnel added or removed, settings changed) → re-render and
  swap the whole table in one atomic transaction.
* **element** (a client reassigned, an endpoint's address changed) → move set
  and map elements only, leaving counters intact.

Both are atomic. There is no moment where the table is absent or permissive.

## Failure modes, by design

| What fails | What happens | Why |
|---|---|---|
| A tunnel drops | Its clients lose the internet | Kernel withdraws the routes; blackhole remains |
| Every pool member drops | That pool's clients lose the internet | Pool table falls to its blackhole |
| `vpngw` crashes | Everything keeps working; nothing fails over | Firewall and routes are kernel state, not process state |
| `vpngw` never starts | Nothing forwards at all | Boot skeleton + `ip_forward=0` |
| The ruleset fails to compile | Previous ruleset stays loaded | `nft --check` before apply; failure is not "apply nothing" |
| The database is corrupt | Nothing forwards | No clients in the map means no marks means drop |

The pattern: **every failure reduces connectivity, never privacy.** There is no
state of this system in which a client silently gets a worse guarantee than it
had a moment ago.

## Component map

| Module | Responsibility | Notes |
|---|---|---|
| `config.py` | Paths, esid/table arithmetic, settings + validation | Validation refuses configs that would lock you out |
| `models.py` | Tunnels, pools, clients, health, `Egress` | Plain dataclasses; no ORM on an appliance |
| `db.py` | SQLite persistence, esid allocation, referential guards | Won't delete a tunnel clients still use |
| `render/nftables.py` | **The security boundary** | Read this one first |
| `render/openvpn.py` | Neutralises provider directives | Strips `redirect-gateway`, `route`, `up`/`down`, … |
| `tunnels/wg.py` | WireGuard without `wg-quick` | wg-quick's route/fwmark magic is what leaks |
| `tunnels/ovpn.py` | OpenVPN under systemd | Not `PartOf=vpngw` — tunnels outlive the control plane |
| `health.py` | Protocol hint, then bound probe, with hysteresis | `ping -I` uses SO_BINDTODEVICE: tests the tunnel, not the routing |
| `pools.py` | Member selection, stickiness | Returns `None` rather than a fallback when all are down |
| `dnsmgr.py` | One resolver per egress | `server=<up>@<source>` is what confines lookups |
| `reconciler.py` | The single writer | |
| `leaktest.py` | The proof harness | netns client + tcpdump + counters |
| `api.py`, `web/` | HTTP API and panel | Reachable from the management path only |

## Deliberate omissions

**No split tunnelling, no per-destination bypass.** See
[killswitch.md](killswitch.md#deliberately-not-supported-split-tunnelling). The
short version: a hole makes the guarantee unauditable and the leak test
unassertable.

**No IPv6 forwarding.** Carrying v6 would mean a second policy-routing plane
with its own tables, rules, and blackholes, and a v6 leak looks exactly like
working internet. Until that is built and tested, v6 is off at the sysctl, the
firewall, and the client interfaces.

**No ORM, no async framework in the data path.** Every dependency is another
import that can fail at boot and leave a gateway without a firewall. The
control plane uses FastAPI because a UI needs one; the reconciler is plain
threads and `subprocess`.

**No automatic recovery that relaxes anything.** When the generated ruleset is
rejected, vpngw logs it and keeps the old one. It never falls back to a simpler
ruleset, because the simpler ruleset is the dangerous one.
