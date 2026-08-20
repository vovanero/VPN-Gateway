/* vpngw admin panel.
 *
 * No framework, no build step, no dependencies. The gateway serves this from
 * its own filesystem with a restricted egress, so anything fetched from
 * elsewhere would be a page that breaks precisely when the network does.
 *
 * One state object, one render pass per poll. Every mutation goes through
 * `mutate()`, which shows a toast and refreshes, so no view can drift from
 * what the daemon actually reports.
 */
"use strict";

/* ── state ─────────────────────────────────────────────────────────────── */

const S = {
  snap: null,
  events: [],
  page: (location.hash || "#dashboard").slice(1),
  live: true,
  timer: null,
  filters: { clients: "", logs: "", logLevel: "all", tunnels: "" },
  selection: new Set(),
  drawerSlug: null,
  lastError: null,
  // Held in state rather than written straight into the DOM: the poll loop
  // re-renders the whole page every few seconds and would otherwise wipe the
  // report a second after it appeared.
  test: { status: "idle", checks: [], ok: null, error: null, at: null },
  providers: [],
  session: null,
  network: null,
  networkDirty: false,
  discovered: [],
  // Server catalogues are hundreds of entries and change rarely, so they are
  // fetched on demand and kept here rather than pulled in with every poll.
  providerView: { id: null, locations: [], countries: [], country: "",
                  city: "", devices: null, total: 0, loading: false },
};

const PAGES = {
  dashboard: ["Overview", "Live state of the gateway"],
  tunnels:   ["Tunnels", "VPN connections and their health"],
  pools:     ["Pools", "Exit groups with automatic failover"],
  providers: ["VPN providers", "Provider accounts and their servers"],
  clients:   ["Clients", "Machines on the client segment and their exits"],
  security:  ["Security", "Kill switch state and the leak test"],
  logs:      ["Events", "What the daemon has been doing"],
  settings:  ["Settings", "Interfaces, addressing and access"],
};

/* ── dom helpers ───────────────────────────────────────────────────────── */

const $ = (sel, root = document) => root.querySelector(sel);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "html") n.innerHTML = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  add(n, kids);
  return n;
}

function add(parent, kids) {
  for (const k of kids.flat(4)) {
    if (k === null || k === undefined || k === false || k === "") continue;
    parent.append(k.nodeType ? k : document.createTextNode(String(k)));
  }
}

const NS = "http://www.w3.org/2000/svg";
function svg(tag, attrs = {}, ...kids) {
  const n = document.createElementNS(NS, tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    n.setAttribute(k, v);
  }
  for (const k of kids.flat(3)) if (k) n.append(k);
  return n;
}

function icon(name, cls = "ic") {
  // The sprite is drawn on a 24x24 grid while .ic renders at 16px, so the
  // viewBox is what scales it. Without one the browser draws at 1:1 and clips
  // to the box, leaving the top-left corner of every glyph and nothing else.
  const s = svg("svg", { class: cls, viewBox: "0 0 24 24" });
  const u = document.createElementNS(NS, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}

/* ── formatting ────────────────────────────────────────────────────────── */

function bytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / Math.pow(1024, i);
  return `${v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}
const rate = (n) => (n ? bytes(n) + "/s" : "—");

function duration(sec) {
  if (!sec || sec < 0) return "—";
  sec = Math.floor(sec);
  const d = Math.floor(sec / 86400), h = Math.floor(sec / 3600) % 24;
  const m = Math.floor(sec / 60) % 60;
  if (d) return `${d}d ${h}h`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m`;
  return `${sec}s`;
}
const ago = (ts) => (ts ? duration(Date.now() / 1000 - ts) : "—");
const clock = (ts) =>
  new Date(ts * 1000).toLocaleTimeString([], { hour12: false });

const STATE_TR = {
  up: "up", down: "down", unknown: "measuring",
  disabled: "off", unassigned: "unassigned",
};

function pill(state, text) {
  return el("span", { class: "pill " + state },
    el("span", { class: "dot" }), text || STATE_TR[state] || state);
}

/* ── subnet masks ──────────────────────────────────────────────────────────
 *
 * Routers ask for a dotted mask, not a prefix length, and people who configure
 * networks for a living read 255.255.255.0 faster than /24. Both are offered:
 * the mask is what you pick, the prefix is what gets stored.
 */

const MASKS = [
  [30, "255.255.255.252", "2 hosts"],
  [29, "255.255.255.248", "6 hosts"],
  [28, "255.255.255.240", "14 hosts"],
  [27, "255.255.255.224", "30 hosts"],
  [26, "255.255.255.192", "62 hosts"],
  [25, "255.255.255.128", "126 hosts"],
  [24, "255.255.255.0", "254 hosts"],
  [23, "255.255.254.0", "510 hosts"],
  [22, "255.255.252.0", "1,022 hosts"],
  [21, "255.255.248.0", "2,046 hosts"],
  [20, "255.255.240.0", "4,094 hosts"],
  [16, "255.255.0.0", "65,534 hosts"],
  [12, "255.240.0.0", "1,048,574 hosts"],
  [8, "255.0.0.0", "16,777,214 hosts"],
];

const prefixToMask = (len) =>
  (MASKS.find((m) => m[0] === Number(len)) || [len, "255.255.255.0"])[1];

function splitCidr(text) {
  const [addr, len] = String(text || "").split("/");
  return { address: (addr || "").trim(), prefix: Number(len) || 24 };
}

const joinCidr = (address, prefix) => `${String(address).trim()}/${prefix}`;

/* ── IPv4 helpers ──────────────────────────────────────────────────────────
 *
 * Typing a network by hand is where configuration mistakes come from, and the
 * ones that matter here are silent: a /24 where you meant /16, a host address
 * where the field wants a network, an address that is not inside the range it
 * has to be inside. None of those look wrong. So every address field says what
 * it understood, and the form refuses to submit something it could not parse.
 */

function parseIPv4(text) {
  const m = String(text || "").trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  if (parts.some((p) => p > 255)) return null;
  return parts.reduce((acc, p) => acc * 256 + p, 0);
}

const toIPv4 = (n) =>
  [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");

/** Parse "10.10.0.1/24" into the facts a person needs to see. */
function cidrInfo(text) {
  const raw = String(text || "").trim();
  const [addrPart, lenPart] = raw.split("/");
  const addr = parseIPv4(addrPart);
  if (addr === null) return { ok: false, error: "not a valid IPv4 address" };
  if (lenPart === undefined || lenPart === "")
    return { ok: false, error: "missing prefix length, e.g. /24" };
  const len = Number(lenPart);
  if (!Number.isInteger(len) || len < 8 || len > 30)
    return { ok: false, error: "prefix length must be between 8 and 30" };

  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;
  const network = (addr & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const usable = Math.max(0, broadcast - network - 1);
  const isHost = addr !== network && addr !== broadcast;

  return {
    ok: true, addr, len, network, broadcast, usable, isHost,
    first: network + 1, last: broadcast - 1,
    networkText: `${toIPv4(network)}/${len}`,
    firstText: toIPv4(network + 1),
    lastText: toIPv4(broadcast - 1),
    contains: (other) => {
      const o = parseIPv4(other);
      return o !== null && o >= network && o <= broadcast;
    },
  };
}

/** A one-line summary shown under a CIDR field as it is typed. */
function describeCidr(text, { wantHost = true } = {}) {
  const info = cidrInfo(text);
  if (!info.ok) return { tone: "bad", text: info.error };
  const range = info.usable > 0
    ? `${info.firstText} – ${info.lastText}, ${info.usable.toLocaleString()} usable`
    : "no usable host addresses";
  if (wantHost && !info.isHost) {
    return {
      tone: "warn",
      text: `${info.networkText} — that is the ${
        info.addr === info.network ? "network" : "broadcast"
      } address; use one of ${range}`,
    };
  }
  return { tone: "ok", text: `network ${info.networkText} · ${range}` };
}

/** Attach live feedback to an address field. */
function withCidrHint(input, options = {}) {
  const note = el("small", { class: "cidr-note" }, "");
  const update = () => {
    const value = input.value.trim();
    if (!value) { note.textContent = ""; note.className = "cidr-note"; return; }
    const d = options.plain
      ? (parseIPv4(value) === null
          ? { tone: "bad", text: "not a valid IPv4 address" }
          : { tone: "ok", text: "" })
      : describeCidr(value, options);
    note.textContent = d.text;
    note.className = "cidr-note " + d.tone;
    input.setCustomValidity(d.tone === "bad" ? d.text : "");
  };
  input.addEventListener("input", update);
  update();
  return note;
}

/* ── api ───────────────────────────────────────────────────────────────── */

async function api(path, method = "GET", body = null) {
  const opts = { method, headers: {} };
  if (body !== null) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  if (res.status === 401 && path !== "/api/login") {
    checkSession();
    throw new Error("signed out");
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try { detail = (await res.json()).detail || detail; } catch (_) {}
    throw new Error(detail);
  }
  return res.status === 204 ? null : res.json();
}

/** Every state-changing call goes through here: one place for the toast, the
 *  error handling, and the refresh that proves the change actually landed. */
async function mutate(fn, okMessage) {
  try {
    const result = await fn();
    if (okMessage) toast("ok", okMessage);
    await refresh();
    return result;
  } catch (err) {
    toast("err", "That did not work", err.message);
    throw err;
  }
}

/* ── toasts ────────────────────────────────────────────────────────────── */

function toast(kind, title, detail) {
  const ic = kind === "ok" ? "check" : kind === "err" ? "alert" : "activity";
  const node = el("div", { class: "toast " + kind }, icon(ic),
    el("div", {}, el("b", {}, title), detail && el("small", {}, detail)));
  $("#toasts").append(node);
  setTimeout(() => {
    node.classList.add("out");
    setTimeout(() => node.remove(), 220);
  }, kind === "err" ? 7000 : 3600);
}

function confirmDialog(title, body, okLabel = "Delete") {
  return new Promise((resolve) => {
    $("#confirmTitle").textContent = title;
    $("#confirmBody").textContent = body;
    $("#confirmOk").textContent = okLabel;
    const dlg = $("#dlgConfirm");
    dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"),
      { once: true });
    dlg.showModal();
  });
}

/* ── charts ────────────────────────────────────────────────────────────── */

function sparkline(values, color) {
  const w = 100, h = 34;
  const pts = values.filter((v) => v !== null && v !== undefined);
  const node = svg("svg", { class: "spark", viewBox: `0 0 ${w} ${h}`,
                            preserveAspectRatio: "none" });

  // A tunnel that is down has a run of zeroes, which would draw as a solid
  // line pinned to the floor - indistinguishable at a glance from a live
  // tunnel that is merely idle. Draw nothing but a dashed baseline instead.
  if (pts.length < 2 || !pts.some((v) => v > 0)) {
    node.append(svg("line", { x1: 0, x2: w, y1: h - 3, y2: h - 3,
      stroke: "var(--border-2)", "stroke-width": 1.4, "stroke-dasharray": "3 4",
      vectorEffect: "non-scaling-stroke" }));
    return node;
  }

  const max = Math.max(...pts, 1);
  const step = w / (pts.length - 1);
  const y = (v) => h - 3 - (v / max) * (h - 6);
  const line = pts.map((v, i) => `${i ? "L" : "M"}${(i * step).toFixed(2)},${y(v).toFixed(2)}`).join("");

  node.append(svg("path", { class: "area", d: `${line}L${w},${h}L0,${h}Z`, fill: color }));
  node.append(svg("path", { class: "line", d: line, stroke: color }));
  return node;
}

/** Multi-series area chart with a time axis, used for aggregate throughput. */
function chart(series, { height = 168, unit = bytes } = {}) {
  const w = 720, h = height, pad = { l: 46, r: 8, t: 10, b: 20 };
  const node = svg("svg", { class: "chart", viewBox: `0 0 ${w} ${h}`,
                            preserveAspectRatio: "none" });
  const n = Math.max(...series.map((s) => s.values.length), 0);
  if (n < 2) {
    node.append(svg("text", { x: w / 2, y: h / 2, "text-anchor": "middle" },
      document.createTextNode("collecting data…")));
    return node;
  }

  const max = Math.max(1, ...series.flatMap((s) => s.values));
  const px = (i) => pad.l + (i / (n - 1)) * (w - pad.l - pad.r);
  const py = (v) => h - pad.b - (v / max) * (h - pad.t - pad.b);

  for (let g = 0; g <= 3; g++) {
    const v = (max / 3) * g;
    node.append(svg("line", { class: "gl", x1: pad.l, x2: w - pad.r,
                              y1: py(v), y2: py(v) }));
    const t = svg("text", { x: pad.l - 6, y: py(v) + 3, "text-anchor": "end" });
    t.append(document.createTextNode(g === 0 ? "0" : unit(v)));
    node.append(t);
  }

  for (const s of series) {
    const line = s.values
      .map((v, i) => `${i ? "L" : "M"}${px(i).toFixed(1)},${py(v).toFixed(1)}`)
      .join("");
    node.append(svg("path", { class: "area", fill: s.color,
      d: `${line}L${px(n - 1)},${h - pad.b}L${px(0)},${h - pad.b}Z` }));
    node.append(svg("path", { class: "line", d: line, stroke: s.color }));
  }
  return node;
}

const COLOR = {
  rx: "var(--accent)",
  tx: "var(--ok)",
  rtt: "var(--warn)",
};

/* ── page: dashboard ───────────────────────────────────────────────────── */

function renderDashboard(host) {
  const s = S.snap, t = s.totals, ks = s.killswitch;

  // Kill-switch hero. Worth stating plainly, because a rising block counter
  // reads like a problem when it is the opposite.
  const degraded = t.pools_degraded > 0 || (t.tunnels_total && !t.tunnels_up);
  const tone = ks.maintenance ? "warn" : degraded ? "warn" : "ok";
  const hero = el("div", { class: "hero " + tone },
    el("div", { class: "hero-icon" }, icon("shield", "ic")),
    el("div", { class: "hero-text" },
      el("h2", {}, ks.maintenance
        ? "Kill switch armed — maintenance window open"
        : "Kill switch armed"),
      el("p", {}, ks.leaked_packets === 0
        ? "No client packet has ever reached the uplink. Without a tunnel, no client reaches the internet at all."
        : `${ks.leaked_packets.toLocaleString()} forwarded packet(s) tried to leave via the uplink and were blocked. That is not a leak — it is the record of the kill switch doing its job.`),
      ks.maintenance && el("p", {},
        `The gateway's own egress is open for another ${Math.ceil(ks.maintenance_remaining / 60)} minute(s). Client traffic is unaffected.`)),
    el("div", { class: "hero-actions" },
      ks.maintenance
        ? el("button", { class: "btn", onclick: () => setMaintenance(null) },
            "Close maintenance")
        : el("button", { class: "btn", onclick: () => setMaintenance(30) },
            icon("clock"), "Maintenance"),
      el("button", { class: "btn primary", onclick: () => go("security") },
        icon("play"), "Leak test")));

  const tiles = el("div", { class: "grid g4" },
    statTile("Tunnels up", `${t.tunnels_up}`, `of ${t.tunnels_total} enabled`,
      t.tunnels_total && t.tunnels_up === t.tunnels_total ? "ok"
        : t.tunnels_up === 0 && t.tunnels_total ? "bad" : "warn", "tunnel"),
    statTile("Clients online", `${t.clients_online}`,
      `of ${t.clients_total} registered`,
      t.clients_blocked ? "warn" : "ok", "clients"),
    statTile("Download", rate(t.rx_rate), "across all tunnels", "", "down"),
    statTile("Upload", rate(t.tx_rate), "across all tunnels", "", "up"));

  // Aggregate throughput across every tunnel, aligned on sample index.
  const len = Math.max(0, ...s.tunnels.map((x) => x.history.length));
  const rx = [], tx = [];
  for (let i = 0; i < len; i++) {
    let r = 0, x = 0;
    for (const tn of s.tunnels) {
      const off = tn.history.length - len + i;
      if (off >= 0 && tn.history[off]) { r += tn.history[off].rx; x += tn.history[off].tx; }
    }
    rx.push(r); tx.push(x);
  }

  const throughput = el("div", { class: "card" },
    el("div", { class: "card-head" },
      el("div", {}, el("h3", {}, "Trafik"),
        el("p", {}, `last ${Math.round(len * s.system.probe_interval / 60)} minutes · one sample every ${s.system.probe_interval}s`))),
    el("div", { class: "card-body" },
      chart([{ values: rx, color: COLOR.rx }, { values: tx, color: COLOR.tx }]),
      el("div", { class: "legend" },
        el("span", {}, el("i", { style: `background:${COLOR.rx}` }), "download"),
        el("span", {}, el("i", { style: `background:${COLOR.tx}` }), "upload"))));

  const problems = [];
  if (!s.tunnels.length)
    problems.push(["No tunnels yet", "Import a .conf or .ovpn file. Until you do, no client can reach the internet.", "tunnel", () => openTunnelDialog()]);
  for (const p of s.pools)
    if (p.enabled && !p.active)
      problems.push([`Pool '${p.name}' has no healthy member`, `${p.clients} client(s) have no internet. They are not falling back to the uplink — that is the kill switch working.`, "pool", () => go("pools")]);
  for (const c of s.clients)
    if (c.enabled && !c.egress_slug)
      problems.push([`${c.name} (${c.ip}) has no exit`, "Traffic from a client with no exit assigned is dropped.", "clients", () => go("clients")]);
  for (const tn of s.tunnels)
    if (tn.enabled && tn.state === "down")
      problems.push([`'${tn.name}' is down`, tn.last_error || "The health probe failed.", "alert", () => openDrawer(tn.slug)]);

  add(host, [
    hero,
    tiles,
    el("div", { class: "section-title" }, "Traffic"),
    throughput,
    problems.length ? [
      el("div", { class: "section-title" }, `Needs attention (${problems.length})`),
      el("div", { class: "card" }, problems.slice(0, 6).map(([title, body, ic, act]) =>
        el("div", { class: "check warn", style: "padding:12px 16px;cursor:pointer",
                    onclick: act },
          el("span", { class: "mark" }, icon(ic)),
          el("div", {}, el("b", {}, title), el("span", {}, body)))))
    ] : [
      el("div", { class: "section-title" }, "Durum"),
      el("div", { class: "card" }, el("div", { class: "empty" },
        icon("check", "ic"), el("b", {}, "All good"),
        el("p", {}, "Every tunnel is up and every client has a working exit.")))
    ],
    el("div", { class: "section-title" }, "Tunnels"),
    s.tunnels.length
      ? el("div", { class: "grid g3" }, s.tunnels.map(tunnelCard))
      : el("div", { class: "card" }, emptyState("tunnel", "No tunnels",
          "Start with 'Add tunnel' in the top right.")),
  ]);
}

function statTile(label, value, foot, tone, ic) {
  return el("div", { class: "card stat " + (tone || "") },
    el("div", { class: "label" }, icon(ic), label),
    el("div", { class: "value" }, value),
    el("div", { class: "foot" }, foot));
}

function tunnelCard(t) {
  const state = t.enabled ? t.state : "disabled";
  const hist = t.history.map((h) => h.rx + h.tx);
  return el("div", { class: "card", style: "cursor:pointer",
                     onclick: () => openDrawer(t.slug) },
    el("div", { class: "card-head" },
      el("div", { style: "min-width:0" },
        el("h3", {}, t.name),
        el("p", { class: "mono" }, `${t.kind} · ${t.iface}`)),
      pill(state)),
    el("div", { class: "card-body", style: "padding:12px 16px" },
      sparkline(hist, state === "up" ? COLOR.tx : "var(--text-3)"),
      el("div", { class: "row", style: "margin-top:10px;font-size:12.5px" },
        el("span", { class: "mono", style: "color:var(--text-2)" },
          t.exit_ip || (t.enabled ? "measuring exit address…" : "disabled")),
        el("span", { class: "spacer" }),
        el("span", { style: "color:var(--text-3)" },
          t.rtt_ms ? `${Math.round(t.rtt_ms)} ms` : "—"))));
}

function emptyState(ic, title, body, action) {
  return el("div", { class: "empty" }, icon(ic, "ic"),
    el("b", {}, title), el("p", {}, body), action);
}

/* ── page: tunnels ─────────────────────────────────────────────────────── */

function renderTunnels(host) {
  const s = S.snap;
  const q = S.filters.tunnels.toLowerCase();
  const rows = s.tunnels.filter((t) =>
    !q || t.name.toLowerCase().includes(q) || t.slug.includes(q) ||
    (t.exit_ip || "").includes(q));

  add(host, [
    el("div", { class: "row wrap", style: "margin-bottom:16px" },
      searchBox("tunnels", "Search tunnels…"),
      el("span", { class: "spacer" }),
      el("button", { class: "btn primary", onclick: openTunnelDialog },
        icon("plus"), "Add tunnel")),

    !s.tunnels.length
      ? el("div", { class: "card" }, emptyState("tunnel", "No tunnels yet",
          "Import a WireGuard .conf or OpenVPN .ovpn file. Your provider's routing directives are neutralised automatically.",
          el("button", { class: "btn primary", onclick: openTunnelDialog },
            icon("plus"), "Import your first tunnel")))
      : el("div", { class: "card table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {},
            el("th", {}, "Tunnel"), el("th", {}, "State"), el("th", {}, "Exit address"),
            el("th", {}, "Latency"), el("th", {}, "Traffic"),
            el("th", {}, "Clients"), el("th", {}, "Activity"), el("th", {}, ""))),
          el("tbody", {}, rows.map(tunnelRow)))),
  ]);
}

function tunnelRow(t) {
  const state = t.enabled ? t.state : "disabled";
  const users = t.direct_clients + t.pool_clients;
  return el("tr", {},
    el("td", { class: "name" },
      el("button", { class: "linkish", onclick: () => openDrawer(t.slug) }, t.name),
      el("div", { class: "sub mono" }, `${t.kind} · ${t.iface}`)),
    el("td", { class: "tight" }, pill(state),
      t.enabled && t.state === "down" && t.last_error
        ? el("div", { class: "sub wrap" }, t.last_error) : null),
    el("td", { class: "mono" }, t.exit_ip || "—"),
    el("td", { class: "tight num" }, t.rtt_ms ? `${Math.round(t.rtt_ms)} ms` : "—"),
    el("td", { class: "tight num", style: "font-size:12.5px" },
      el("div", {}, "↓ " + rate(t.rx_rate)),
      el("div", { class: "sub" }, "↑ " + rate(t.tx_rate))),
    el("td", { class: "tight num" }, users || "—",
      t.pool_clients ? el("div", { class: "sub" }, `${t.pool_clients} via pools`) : null),
    el("td", { style: "width:120px" },
      sparkline(t.history.map((h) => h.rx + h.tx),
        state === "up" ? COLOR.tx : "var(--text-3)")),
    el("td", { class: "tight" }, el("div", { class: "row" },
      el("button", { class: "btn sm", title: t.enabled ? "Disable" : "Enable",
        onclick: () => toggleTunnel(t) }, icon("power")),
      el("button", { class: "btn sm danger", title: "Delete",
        onclick: () => removeTunnel(t) }, icon("trash")))));
}

/* ── page: pools ───────────────────────────────────────────────────────── */

function renderPools(host) {
  const s = S.snap;
  add(host, [
    el("div", { class: "row wrap", style: "margin-bottom:16px" },
      el("p", { style: "font-size:13px;color:var(--text-2);max-width:620px" },
        "A pool is an exit like a tunnel is: it has its own routing table, pointed at whichever member is healthy. When no member is healthy the pool closes — its clients do not fall back to the uplink."),
      el("span", { class: "spacer" }),
      el("button", { class: "btn primary", onclick: openPoolDialog,
        disabled: s.tunnels.length < 1 }, icon("plus"), "Create pool")),

    !s.pools.length
      ? el("div", { class: "card" }, emptyState("pool", "No pools",
          s.tunnels.length
            ? "Group several tunnels into one exit; when one drops, the next takes over automatically."
            : "Add at least one tunnel first.",
          s.tunnels.length ? el("button", { class: "btn primary", onclick: openPoolDialog },
            icon("plus"), "Create pool") : null))
      : el("div", { class: "grid g2" }, s.pools.map(poolCard)),
  ]);
}

function poolCard(p) {
  const byslug = Object.fromEntries(S.snap.tunnels.map((t) => [t.slug, t]));
  const dead = !p.active;

  const chain = el("div", { class: "chain" });
  p.members.forEach((m, i) => {
    const t = byslug[m.slug] || {};
    const isActive = m.slug === p.active;
    if (i) chain.append(el("div", { class: "chain-link" }));
    chain.append(el("div", {
      class: "chain-node" + (isActive ? " active" : "") +
             (m.state !== "up" ? " dead" : "") },
      el("span", { class: "rank" }, i + 1),
      el("div", { class: "grow" },
        el("div", {}, t.name || m.slug,
          isActive ? el("span", { class: "pill up", style: "margin-left:8px" },
            el("span", { class: "dot" }), "active") : null),
        el("div", { class: "sub mono", style: "font-size:11.5px;color:var(--text-3)" },
          `priority ${m.priority}${m.rtt_ms ? ` · ${Math.round(m.rtt_ms)} ms` : ""}`)),
      pill(m.state)));
  });

  return el("div", { class: "card" },
    el("div", { class: "card-head" },
      el("div", {}, el("h3", {}, p.name),
        el("p", {}, `${STRATEGY_TR[p.strategy] || p.strategy} · ${p.clients} client(s)`)),
      dead ? pill("down", "no member") : pill("up", "running")),
    el("div", { class: "card-body" },
      dead
        ? el("p", { style: "font-size:12.5px;color:var(--danger);margin-bottom:12px" },
            `No healthy member. The ${p.clients} client(s) on this pool have no internet — they are not falling back to the uplink.`)
        : el("p", { style: "font-size:12.5px;color:var(--text-3);margin-bottom:12px" },
            poolReason(p)),
      chain,
      el("div", { class: "row", style: "margin-top:14px" },
        el("span", { class: "mono", style: "font-size:11.5px;color:var(--text-3)" },
          `table ${p.table} · stickiness ${p.sticky_seconds}s`),
        el("span", { class: "spacer" }),
        el("button", { class: "btn sm", onclick: () => togglePool(p) },
          icon("power"), p.enabled ? "Disable" : "Enable"),
        el("button", { class: "btn sm danger", onclick: () => removePool(p) },
          icon("trash")))));
}

const STRATEGY_TR = {
  priority: "Priority order", latency: "Lowest latency",
  round_robin: "Round robin", random: "Random",
};

/** The daemon's selection reasons are internal English strings. Translate the
 *  ones a person would want to read and fall back to a plain member count for
 *  the steady state, rather than showing "unchanged" to a Turkish operator. */
function poolReason(p) {
  const r = p.reason || "";
  const steady = `${p.healthy_members} of ${p.members.length} members up`;
  if (!r || r === "unchanged" || r === "initial selection") return steady;
  let m = r.match(/^(\S+) went down, failing over to (\S+)$/);
  if (m) return `${m[1]} went down, failed over to ${m[2]}`;
  m = r.match(/holding (\S+) for another (\d+)s \(sticky\)/);
  if (m) return `holding ${m[1]} — stickiness expires in ${m[2]}s`;
  m = r.match(/^(\S+) not stable long enough to switch back$/);
  if (m) return `${m[1]} has not been healthy long enough to switch back`;
  m = r.match(/switching to preferred member (\S+)$/);
  if (m) return `switching back to preferred member ${m[1]}`;
  return steady;
}

/* ── page: clients ─────────────────────────────────────────────────────── */

function renderClients(host) {
  const s = S.snap;
  const q = S.filters.clients.toLowerCase();
  const rows = s.clients.filter((c) =>
    !q || c.name.toLowerCase().includes(q) || c.ip.includes(q) ||
    (c.egress_slug || "").includes(q));

  const anySelected = S.selection.size > 0;

  add(host, [
    el("div", { class: "row wrap", style: "margin-bottom:16px" },
      searchBox("clients", "Ad veya IP ara…"),
      anySelected && el("span", { class: "pill accent" },
        `${S.selection.size} selected`),
      anySelected && el("select", {
        style: "width:auto",
        onchange: (e) => { bulkAssign(e.target.value); e.target.value = ""; },
      }, el("option", { value: "" }, "Assign exit to selected…"), egressOptions("")),
      anySelected && el("button", { class: "btn sm ghost",
        onclick: () => { S.selection.clear(); render(); } }, "Clear selection"),
      el("span", { class: "spacer" }),
      el("button", { class: "btn primary", onclick: () => openClientDialog() },
        icon("plus"), "Add client")),

    !s.clients.length
      ? el("div", { class: "card" }, emptyState("clients", "No clients registered",
          `Add a record for each VM, using the static address you gave it. Gateway ${s.system.lan_gateway}, network ${s.system.lan_cidr}. Traffic from an unregistered machine is dropped.`,
          el("button", { class: "btn primary", onclick: () => openClientDialog() },
            icon("plus"), "Add your first client")))
      : el("div", { class: "card table-wrap" }, el("table", {},
          el("thead", {}, el("tr", {},
            el("th", { class: "tight" }, el("input", {
              type: "checkbox",
              checked: rows.length > 0 && S.selection.size === rows.length,
              onchange: (e) => {
                S.selection.clear();
                if (e.target.checked) rows.forEach((c) => S.selection.add(c.ip));
                render();
              } })),
            el("th", {}, "Client"), el("th", {}, "Address"), el("th", {}, "Exit"),
            el("th", {}, "State"), el("th", {}, "MAC"), el("th", {}, ""))),
          el("tbody", {}, rows.map(clientRow)))),

    el("p", { style: "font-size:12px;color:var(--text-3);margin-top:12px;max-width:640px" },
      `On each client VM: an address in ${s.system.lan_cidr}, gateway ${s.system.lan_gateway}, and any DNS server at all — every :53 query is intercepted and answered by the resolver belonging to that client's own tunnel.`),
  ]);

  renderDiscovered(host);
}

/* Machines seen on a client interface that nobody has registered. They are
   being dropped right now; this exists so that fact is visible rather than
   looking like a machine that is simply switched off. */
function renderDiscovered(host) {
  const found = S.discovered || [];
  if (!found.length) return;

  host.append(el("div", { class: "section-title" },
    `Seen but not registered (${found.length})`));
  host.append(el("div", { class: "card" },
    el("div", { class: "card-body" },
      el("p", { style: "font-size:12.5px;color:var(--text-2);line-height:1.55;margin-bottom:12px" },
        "These machines have appeared on a client interface and are not in the "
        + "register, so their traffic is being dropped. That is the intended "
        + "default — unknown means blocked — but it looks identical to a "
        + "machine that is switched off, which is why they are listed here."),
      el("div", { class: "table-wrap" }, el("table", {},
        el("thead", {}, el("tr", {},
          el("th", {}, "Address"), el("th", {}, "MAC"),
          el("th", {}, "Seen via"), el("th", {}, "Last seen"), el("th", {}, ""))),
        el("tbody", {}, found.map((d) =>
          el("tr", {},
            el("td", { class: "mono name" }, d.ip),
            el("td", { class: "mono", style: "font-size:11.5px" }, d.mac || "—"),
            el("td", {},
              d.using_gateway
                ? pill("unknown", "using this gateway")
                : pill("neutral", d.sources.join(", "))),
            el("td", { style: "font-size:12px;color:var(--text-3)" },
              ago(d.last_seen) + " ago"),
            el("td", { class: "tight" },
              el("button", { class: "btn sm primary",
                onclick: () => adoptClient(d) },
                icon("plus"), "Register"))))))))));
}

function adoptClient(found) {
  if (!S.snap) return;
  openClientDialog();
  const f = $("#formClient");
  f.ip.value = found.ip;
  f.name.value = found.ip.split(".").pop().padStart(2, "0")
    ? "pc" + found.ip.split(".").pop() : "";
  f.name.focus();
}

function clientRow(c) {
  const current = c.egress_slug ? `${c.egress_kind}:${c.egress_slug}` : "";
  return el("tr", { class: S.selection.has(c.ip) ? "selected" : "" },
    el("td", { class: "tight" }, el("input", {
      type: "checkbox", checked: S.selection.has(c.ip),
      onchange: (e) => {
        e.target.checked ? S.selection.add(c.ip) : S.selection.delete(c.ip);
        render();
      } })),
    el("td", { class: "name" }, c.name,
      c.notes && el("div", { class: "sub" }, c.notes)),
    el("td", { class: "mono" }, c.ip),
    el("td", {}, el("select", {
      style: "min-width:190px",
      onchange: (e) => assignClient(c.ip, e.target.value),
    }, egressOptions(current))),
    el("td", { class: "tight" },
      c.egress_state === "up" ? pill("up", "online")
      : c.egress_state === "unassigned" ? pill("down", "unassigned")
      : c.egress_state === "unknown" ? pill("unknown", "measuring")
      : pill("down", "blocked")),
    el("td", { class: "mono", style: "font-size:11.5px" }, c.mac || "—"),
    el("td", { class: "tight" }, el("div", { class: "row" },
      el("button", { class: "btn sm", title: "Edit",
        onclick: () => openClientDialog(c) }, icon("edit")),
      el("button", { class: "btn sm danger", title: "Delete",
        onclick: () => removeClient(c) }, icon("trash")))));
}

function egressOptions(selected) {
  const out = [el("option", { value: "", selected: selected === "" },
    "— no exit (blocked) —")];
  if (S.snap.tunnels.length) {
    const g = el("optgroup", { label: "Tunnels" });
    for (const t of S.snap.tunnels)
      g.append(el("option", { value: "tunnel:" + t.slug,
        selected: selected === "tunnel:" + t.slug },
        `${t.name}${t.enabled ? "" : " (disabled)"}`));
    out.push(g);
  }
  if (S.snap.pools.length) {
    const g = el("optgroup", { label: "Pools" });
    for (const p of S.snap.pools)
      g.append(el("option", { value: "pool:" + p.slug,
        selected: selected === "pool:" + p.slug }, p.name));
    out.push(g);
  }
  return out;
}

/* ── page: providers ───────────────────────────────────────────────────── */

function renderProviders(host) {
  const view = S.providerView;

  add(host, [
    el("div", { class: "row wrap", style: "margin-bottom:16px" },
      el("p", { style: "font-size:13px;color:var(--text-2);max-width:640px" },
        "For providers with an API, pick a server from the list and build the " +
        "tunnel in one click. For the rest, bulk-import the archive you " +
        "downloaded — the resulting tunnel is identical."),
      el("span", { class: "spacer" }),
      el("button", { class: "btn primary", onclick: openBundleDialog },
        icon("up"), "Bulk import")),

    el("div", { class: "grid g3" }, (S.providers || []).map(providerCard)),
  ]);

  if (!S.providers || !S.providers.length) {
    host.append(el("div", { class: "card" },
      emptyState("globe", "Could not load the provider list",
        "The daemon may be unreachable.")));
    return;
  }

  const active = S.providers.find((p) => p.id === view.id);
  // Providers whose catalogue is public can be browsed before you have an
  // account - seeing what is on offer before signing up is the point.
  if (!active || (!active.configured && active.locations_need_auth)) return;

  // ── server browser ──────────────────────────────────────────────────
  host.append(el("div", { class: "section-title" },
    `${active.name} servers`));
  if (!active.configured) {
    host.append(el("p", {
      style: "font-size:12.5px;color:var(--text-2);margin:-6px 0 12px" },
      "You can browse the catalogue without an account. Building a tunnel "
      + "needs one — ",
      el("button", { class: "linkish", onclick: () => openLoginDialog(active) },
        "connect now"), "."));
  }

  const controls = el("div", { class: "row wrap", style: "margin-bottom:12px" },
    el("select", {
      style: "width:auto;min-width:200px",
      onchange: (e) => { view.country = e.target.value; loadLocations(); },
    },
      el("option", { value: "" }, "All countries"),
      ...(view.countries || []).map((c) =>
        el("option", { value: c.code, selected: view.country === c.code },
          `${c.name}${c.code ? " (" + c.code.toUpperCase() + ")" : ""}`))),
    el("div", { class: "search", style: "max-width:220px" }, icon("search"),
      el("input", { type: "search", placeholder: "Search city…",
        value: view.city,
        oninput: (e) => { view.city = e.target.value; render(); } })),
    el("span", { class: "spacer" }),
    view.loading
      ? el("span", { class: "pill neutral" }, "loading…")
      : el("span", { style: "font-size:12px;color:var(--text-3)" },
          `${view.total || 0} servers`),
    el("button", { class: "btn sm", onclick: () => loadLocations(true) },
      icon("refresh"), "Refresh"));

  const needle = (view.city || "").toLowerCase();
  const rows = (view.locations || []).filter(
    (l) => !needle || l.city.toLowerCase().includes(needle));

  // Nothing fetched yet: ask, rather than fetching on the off-chance. The
  // request also opens this provider's API host in the firewall, so it should
  // follow a deliberate click.
  if (!view.loading && !view.locations.length) {
    host.append(el("div", { class: "card" }, el("div", { class: "card-body" },
      el("div", { class: "empty", style: "padding:28px 20px" },
        icon("globe", "ic"),
        el("b", {}, "Server catalogue not loaded"),
        el("p", {}, `Fetching it contacts ${active.name}'s API. Doing so also `
          + "allows HTTPS to that one host through the firewall, which stays "
          + "open until you remove the account."),
        el("button", { class: "btn primary", style: "margin-top:4px",
          onclick: () => loadLocations(true) },
          icon("down"), "Load server list")))));
    if (active.device_limit) renderDeviceSection(host, active, view);
    return;
  }

  host.append(controls);
  host.append(
    view.loading && !rows.length
      ? el("div", { class: "card" }, el("div", { class: "card-body" },
          el("div", { class: "skel", style: "height:120px" })))
      : rows.length
        ? el("div", { class: "card table-wrap" }, el("table", {},
            el("thead", {}, el("tr", {},
              el("th", {}, "Sunucu"), el("th", {}, "Konum"),
              el("th", {}, "Adres"), el("th", {}, ""), el("th", {}, ""))),
            el("tbody", {}, rows.slice(0, 200).map((l) => locationRow(active, l)))))
        : el("div", { class: "card" }, emptyState("globe", "No servers",
            "Nothing matches that filter.")));

  if (rows.length > 200) {
    host.append(el("p", { style: "font-size:12px;color:var(--text-3);margin-top:10px" },
      `Showing the first 200 of ${rows.length} matches. Narrow it down with the country or city filter.`));
  }

  if (active.device_limit) renderDeviceSection(host, active, view);
}

function renderDeviceSection(host, active, view) {
  {
    host.append(el("div", { class: "section-title" }, "Registered devices"));
    const devs = view.devices;
    host.append(el("div", { class: "card" },
      el("div", { class: "card-body" },
        el("p", { style: "font-size:12.5px;color:var(--text-2);margin-bottom:12px" },
          `${active.name} allows ${active.device_limit} devices per account. ` +
          "Each tunnel uses one; when you hit the limit, remove one here " +
          "before adding another."),
        devs === null
          ? el("button", { class: "btn sm", onclick: loadDevices },
              icon("refresh"), "Show devices")
          : devs.length
            ? el("div", {}, ...devs.map((d) =>
                el("div", { class: "row", style: "padding:7px 0;border-bottom:1px solid var(--border)" },
                  el("span", { class: "mono", style: "flex:1" },
                    d.name || d.id.slice(0, 12)),
                  el("span", { class: "mono", style: "color:var(--text-3)" },
                    d.ipv4 || ""),
                  el("button", { class: "btn sm danger",
                    onclick: () => removeDevice(active, d) }, icon("trash")))))
            : el("p", { style: "font-size:12.5px;color:var(--text-3)" },
                "no devices registered"),
        devs && devs.length
          ? el("p", { style: "font-size:12px;color:var(--text-3);margin-top:10px" },
              `${devs.length} of ${active.device_limit} in use`)
          : null)));
  }
}

const MODE_TAG = {
  api: "API",
  wireguard_key: "Your key",
};

function providerCard(p) {
  const selected = S.providerView.id === p.id;
  return el("div", {
    class: "card provider" + (selected ? " on" : ""),
    style: "cursor:pointer",
    onclick: () => selectProvider(p),
  },
    el("div", { class: "card-head" },
      el("div", { class: "row", style: "min-width:0;gap:10px" },
        el("div", { class: "provider-mark" }, p.name.slice(0, 2).toUpperCase()),
        el("div", { style: "min-width:0" },
          el("h3", {}, p.name),
          el("p", {}, p.supports.join(", ") +
            (p.device_limit ? ` · ${p.device_limit} devices` : "")))),
      p.configured ? pill("up", "connected") : pill("disabled", "not connected")),
    el("div", { class: "card-body", style: "padding:12px 16px" },
      el("div", { class: "row", style: "margin-bottom:8px" },
        el("span", { class: "mode-tag",
          title: p.credential_mode === "api"
            ? "Tunnels are provisioned through the provider's API"
            : "You paste a key once; the plugin supplies the server catalogue" },
          MODE_TAG[p.credential_mode] || p.credential_mode),
        !p.locations_need_auth
          ? el("span", { class: "mode-tag",
              title: "The server catalogue is public — browse before connecting" },
              "Open catalogue")
          : null),
      el("p", { class: "blurb", title: p.notes || "" }, p.notes || ""),
      el("div", { class: "actions" },
        p.configured
          ? [el("button", { class: "btn sm",
                onclick: (e) => { e.stopPropagation(); selectProvider(p); } },
              icon("globe"), "Servers"),
             el("button", { class: "btn sm danger",
                onclick: (e) => { e.stopPropagation(); providerLogout(p); } },
              "Remove account")]
          : [!p.locations_need_auth
              ? el("button", { class: "btn sm",
                  onclick: (e) => { e.stopPropagation(); selectProvider(p); } },
                  icon("globe"), "Browse servers")
              : null,
             el("button", { class: "btn sm primary",
                onclick: (e) => { e.stopPropagation(); openLoginDialog(p); } },
                "Connect")])));
}

function locationRow(provider, l) {
  return el("tr", {},
    el("td", { class: "name mono" }, l.id),
    el("td", {}, `${l.city}, ${l.country}`),
    el("td", { class: "mono" }, l.address),
    el("td", { class: "tight" },
      l.owned ? pill("up", "owned") : null,
      l.daita ? el("span", { class: "pill neutral", style: "margin-left:6px" },
        "DAITA") : null),
    el("td", { class: "tight" },
      provider.configured
        ? el("button", { class: "btn sm primary",
            onclick: (e) => addFromLocation(provider, l, e.target.closest("button")) },
            icon("plus"), "Build tunnel")
        : el("button", { class: "btn sm", disabled: true,
            title: "Connect the account first" },
            icon("plus"), "Build tunnel")));
}

/* ── provider actions ──────────────────────────────────────────────────── */

async function loadProviders() {
  try {
    S.providers = await api("/api/providers");
    const nav = $("#navProviders");
    if (nav) nav.textContent = S.providers.filter((p) => p.configured).length || "";
  } catch (err) {
    S.providers = S.providers || [];
  }
}

function selectProvider(p) {
  if (!p.configured && p.locations_need_auth) { openLoginDialog(p); return; }
  const view = S.providerView;
  if (view.id !== p.id) {
    // Deliberately does not fetch. Selecting a card is "show me this
    // provider", not "download eight thousand servers" - and the fetch also
    // opens a firewall hole, which should follow from something the operator
    // actually asked for.
    Object.assign(view, { id: p.id, locations: [], countries: [], country: "",
                          city: "", devices: null, total: 0, loading: false });
  }
  render();
}

async function loadLocations(force) {
  const view = S.providerView;
  if (!view.id) return;
  if (view.loading && !force) return;
  view.loading = true;
  render();
  try {
    const params = new URLSearchParams();
    if (view.country) params.set("country", view.country);
    const data = await api(
      `/api/providers/${view.id}/locations?` + params.toString());
    view.locations = data.locations;
    view.total = data.total;
    if (data.countries && data.countries.length) view.countries = data.countries;
  } catch (err) {
    toast("err", "Could not fetch servers", err.message);
    view.locations = [];
  } finally {
    view.loading = false;
    render();
  }
}

async function loadDevices() {
  const view = S.providerView;
  if (!view.id) return;
  try {
    const data = await api(`/api/providers/${view.id}/devices`);
    view.devices = data.devices;
  } catch (err) {
    toast("err", "Could not fetch devices", err.message);
    view.devices = [];
  }
  render();
}

async function removeDevice(provider, device) {
  const ok = await confirmDialog(
    "Remove this device?",
    `${device.name || device.id} will be removed. Any tunnel using this device ` +
    "will stop working.");
  if (!ok) return;
  await mutate(
    () => api(`/api/providers/${provider.id}/devices/${device.id}`, "DELETE"),
    "Device removed");
  loadDevices();
}

async function addFromLocation(provider, location, button) {
  if (button) { button.disabled = true; button.textContent = "building…"; }
  try {
    const res = await api(`/api/providers/${provider.id}/tunnels`, "POST", {
      location_id: location.id,
      prefix: location.country_code || provider.id.slice(0, 2),
      name: `${location.city}, ${location.country}`,
    });
    toast("ok", `Tunnel built: ${res.slug}`, `${res.name} — ${res.endpoint}`);
    S.providerView.devices = null;
    await refresh();
  } catch (err) {
    toast("err", "Could not build the tunnel", err.message);
  } finally {
    if (button) { button.disabled = false; }
    render();
  }
}

async function providerLogout(p) {
  const ok = await confirmDialog(
    `Remove the ${p.name} account?`,
    "The stored credentials are deleted and the firewall hole for this " +
    "provider's API closes. Tunnels already built from it keep working.",
    "Remove");
  if (!ok) return;
  await mutate(() => api(`/api/providers/${p.id}/logout`, "POST", {}),
    `${p.name} account removed`);
  if (S.providerView.id === p.id) S.providerView.id = null;
  await loadProviders();
  render();
}

/* ── provider dialogs ──────────────────────────────────────────────────── */

let loginProvider = null;

function openLoginDialog(p) {
  loginProvider = p;
  $("#loginTitle").textContent = `Connect your ${p.name} account`;
  $("#loginNotes").textContent = p.notes || "";
  $("#loginFields").replaceChildren(...p.auth_fields.map((f) =>
    el("label", { class: "field" },
      el("span", {}, f.label, f.secret ? "" : ""),
      el("input", {
        name: f.key, type: f.secret ? "password" : "text",
        placeholder: f.placeholder || "", autocomplete: "off", required: true,
      }),
      f.help ? el("small", {}, f.help) : null)));
  $("#dlgProviderLogin").showModal();
}

$("#formProviderLogin").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value === "cancel" || !loginProvider) return;
  const body = {};
  for (const f of loginProvider.auth_fields) {
    body[f.key] = ev.target.elements[f.key].value.trim();
  }
  const p = loginProvider;
  try {
    const res = await api(`/api/providers/${p.id}/login`, "POST", body);
    ev.target.reset();
    toast("ok", `${p.name}: connected`,
      Object.entries(res.account || {})
        .filter(([, v]) => v !== null && v !== "")
        .map(([k, v]) => `${k}: ${v}`).join(" · ") || undefined);
    await loadProviders();
    const fresh = S.providers.find((x) => x.id === p.id);
    if (fresh) selectProvider(fresh);
  } catch (err) {
    toast("err", "Could not connect", err.message);
  }
});

function openBundleDialog() {
  const f = $("#formBundle");
  f.reset();
  $("#bundleLabel").textContent = "Drop a file here, or click to choose";
  $("#bundleZone").classList.remove("filled");
  $("#bundlePlan").replaceChildren();
  $("#dlgBundle").showModal();
}

$("#formBundle").addEventListener("submit", (ev) => {
  if (ev.submitter?.value === "cancel") return;
  runBundle(false);
});
$("#bundlePreview").addEventListener("click", () => runBundle(true));

async function runBundle(preview) {
  const f = $("#formBundle");
  const file = f.file.files[0];
  if (!file) { toast("err", "No file selected"); return; }

  const params = new URLSearchParams({
    prefix: f.prefix.value || "vpn",
    limit: String(Number(f.limit.value) || 0),
    disabled: f.disabled.checked ? "true" : "false",
    dry_run: preview ? "true" : "false",
  });
  const body = new FormData();
  body.append("file", file);

  const box = $("#bundlePlan");
  box.replaceChildren(el("p", { class: "hint" }, "reading…"));
  try {
    const res = await fetch("/api/tunnels/import-bundle?" + params,
                            { method: "POST", body });
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    const data = await res.json();
    box.replaceChildren(bundlePlanView(data));
    if (!data.dry_run) {
      toast("ok", `Imported ${data.imported} tunnel(s)`,
        data.without_endpoint.length
          ? `no endpoint resolved for: ${data.without_endpoint.join(", ")}`
          : undefined);
      $("#dlgBundle").close();
      await refresh();
    }
  } catch (err) {
    box.replaceChildren(el("p", { style: "color:var(--danger);font-size:13px" },
      err.message));
  }
}

function bundlePlanView(data) {
  const wrap = el("div", { style: "margin-top:14px" });
  wrap.append(el("p", { style: "font-size:12.5px;color:var(--text-2)" },
    `${data.plan.length} tunnel(s) will be imported` +
    (data.skipped.length ? `, ${data.skipped.length} skipped` : "")));
  if (data.plan.length) {
    wrap.append(el("div", { class: "picker", style: "margin-top:8px" },
      ...data.plan.slice(0, 60).map((p) =>
        el("div", { class: "picker-row" },
          el("span", { class: "mono", style: "width:70px" }, p.slug),
          el("span", { class: "grow" }, p.name),
          el("span", { style: "font-size:11.5px;color:var(--text-3)" }, p.kind)))));
  }
  for (const s of data.skipped.slice(0, 8)) {
    wrap.append(el("p", {
      style: "font-size:11.5px;color:var(--warn);margin-top:6px" },
      `skipped — ${s.source}: ${s.problem}`));
  }
  return wrap;
}

{
  const dz = $("#bundleZone"), input = dz.querySelector("input");
  const setLabel = () => {
    const f = input.files[0];
    $("#bundleLabel").textContent =
      f ? f.name : "Drop a file here, or click to choose";
    dz.classList.toggle("filled", !!f);
  };
  input.addEventListener("change", setLabel);
  ["dragenter", "dragover"].forEach((e) => dz.addEventListener(e, (ev) => {
    ev.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((e) => dz.addEventListener(e, (ev) => {
    ev.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (ev) => {
    if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; setLabel(); }
  });
}

/* ── page: security ────────────────────────────────────────────────────── */

function renderSecurity(host) {
  const s = S.snap, ks = s.killswitch, c = s.counters;

  const counterRows = [
    ["wan_leak_drop", "Forwarded traffic aimed at the uplink", "What the kill switch caught. A number above zero is not a leak — it is the record of attempts that were stopped, usually a client retrying while its tunnel reconnects.", "danger"],
    ["nontunnel_drop", "Aimed at a non-tunnel interface", "Anything leaving by a route that is not on the allow-list.", "danger"],
    ["unclassified_drop", "Client with no exit", "Machines that are unregistered, or assigned to an exit that is switched off.", "warn"],
    ["forwarded_new", "New flows admitted to a tunnel", "Ordinary traffic.", "ok"],
    ["dns_hijacked", "DNS queries intercepted", "Redirected to the resolver for that client's own tunnel, whatever address the client was configured with.", "ok"],
    ["host_egress_drop", "The gateway's own blocked traffic", "Strict host egress. If a tunnel will not connect, look here — its endpoint address may not be on the allow-list.", "warn"],
  ];

  add(host, [
    el("div", { class: "card", style: "margin-bottom:20px" },
      el("div", { class: "card-head" },
        el("div", {}, el("h3", {}, "Leak test"),
          el("p", {}, "Attaches a real network client to the client bridge, generates traffic, and measures whether anything reaches the uplink.")),
        el("div", { class: "row" },
          el("button", { class: "btn", disabled: S.test.status === "running",
            onclick: () => runSelftest(false) }, icon("play"), "Run test"),
          el("button", { class: "btn danger", disabled: S.test.status === "running",
            onclick: () => runSelftest(true) }, icon("alert"), "Disruptive test"))),
      el("div", { class: "card-body" },
        el("p", { style: "font-size:12.5px;color:var(--text-2);line-height:1.6;margin-bottom:14px" },
          "The disruptive test actually takes the tunnel down and measures what escapes in that window — with nftables counters and with tcpdump on the uplink, because those two do not share a failure mode. Clients on that tunnel lose connectivity for roughly twenty seconds."),
        testReport())),

    el("div", { class: "section-title" }, "Firewall counters"),
    el("div", { class: "card table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {},
        el("th", {}, "Counter"), el("th", {}, "Packets"), el("th", {}, "Bytes"),
        el("th", {}, "What it means"))),
      el("tbody", {}, counterRows.map(([key, label, help]) => {
        const v = c[key] || { packets: 0, bytes: 0 };
        return el("tr", {},
          el("td", {}, label, el("div", { class: "sub mono" }, key)),
          el("td", { class: "tight num" }, v.packets.toLocaleString("tr-TR")),
          el("td", { class: "tight num" }, bytes(v.bytes)),
          el("td", { style: "font-size:12.5px;color:var(--text-2)" }, help));
      })))),

    el("div", { class: "section-title" }, "Configuration"),
    el("div", { class: "grid g2" },
      el("div", { class: "card" }, el("div", { class: "card-body" },
        el("h3", { style: "font-size:13.5px;margin-bottom:10px" }, "Strict host egress"),
        el("p", { style: "font-size:12.5px;color:var(--text-2);line-height:1.55" },
          ks.strict_host_egress
            ? "On. The gateway itself may only reach the VPN endpoints it was configured with, plus the bootstrap resolvers. Use a maintenance window to run apt."
            : "Off. The gateway's own traffic is unrestricted. Client traffic is unaffected — the forward chain is closed either way."),
        el("div", { class: "row", style: "margin-top:14px" },
          ks.maintenance
            ? el("button", { class: "btn", onclick: () => setMaintenance(null) },
                `Close maintenance (${Math.ceil(ks.maintenance_remaining / 60)} min left)`)
            : el("button", { class: "btn", onclick: () => setMaintenance(30) },
                icon("clock"), "Open for 30 minutes")))),
      el("div", { class: "card" }, el("div", { class: "card-body" },
        el("h3", { style: "font-size:13.5px;margin-bottom:10px" }, "Network"),
        el("dl", { class: "kv" },
          el("dt", {}, "Client network"), el("dd", {}, s.system.lan_cidr),
          el("dt", {}, "Gateway"), el("dd", {}, s.system.lan_gateway),
          el("dt", {}, "Uplink"), el("dd", {}, s.system.wan_iface),
          el("dt", {}, "Management"), el("dd", {}, s.system.mgmt_iface || "—"),
          el("dt", {}, "Resolver subnet"), el("dd", {}, s.system.resolver_subnet),
          el("dt", {}, "Version"), el("dd", {}, s.system.version))))),

    el("div", { class: "section-title" }, "Inspect the ruleset"),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      el("p", { style: "font-size:12.5px;color:var(--text-2);margin-bottom:12px" },
        "You do not have to take our word for it — read the generated nftables ruleset in full."),
      el("a", { class: "btn", href: "/api/ruleset", target: "_blank" },
        icon("logs"), "Open the ruleset"))),
  ]);
}

function testReport() {
  const t = S.test;

  if (t.status === "running")
    return el("div", { class: "row", style: "gap:11px" },
      el("div", { class: "skel", style: "width:20px;height:20px;border-radius:50%" }),
      el("span", { style: "font-size:13px;color:var(--text-2)" },
        "Running — takes about a minute…"));

  if (t.status === "error")
    return el("p", { style: "color:var(--danger);font-size:13px" },
      "Test error: " + t.error);

  if (t.status === "idle")
    return el("p", { style: "font-size:12.5px;color:var(--text-3);line-height:1.6" },
      "Not run yet. Until this passes, treat the gateway as untested rather than leak-proof.");

  return el("div", {},
    el("div", { class: "hero " + (t.ok ? "ok" : "bad"),
                style: "margin-bottom:14px;padding:14px 16px" },
      el("div", { class: "hero-icon" }, icon(t.ok ? "check" : "alert")),
      el("div", { class: "hero-text" },
        el("h2", {}, t.ok ? "No leak found" : "CRITICAL FAILURE"),
        el("p", {}, t.ok
          ? "Under every condition measured, no client traffic left outside a tunnel."
          : "Do not treat this gateway as leak-proof. Read the failed checks below."),
        el("p", { style: "font-size:11.5px" }, `run at ${clock(t.at)}`))),
    ...t.checks.map((c) => el("div", {
      class: "check " + (c.passed ? "pass" : c.critical ? "fail" : "warn") },
      el("span", { class: "mark" }, icon(c.passed ? "check" : "x")),
      el("div", {}, el("b", {}, CHECK_TR[c.id] || c.name),
        c.detail && el("span", {}, c.detail)))));
}

/* The daemon reports each check with a stable id plus an English name, so the
 * CLI stays readable in a log while the panel can speak Turkish. An unknown id
 * falls back to the English name rather than disappearing. */
const CHECK_TR = {
  tunnel_carries: "The tunnel actually carries traffic",
  exit_not_uplink: "The exit address is not the uplink's",
  no_leak_healthy: "Nothing reached the uplink while the tunnel was up",
  unassigned_blocked: "A client with no exit cannot reach the internet",
  ipv6_blocked: "IPv6 cannot escape",
  dns_intercepted: "Hard-coded public DNS is intercepted",
  dns_is_ours: "The answering resolver is ours",
  boot_order: "The kill switch loads before the network at boot",
  sysctl_forward_off: "Forwarding is off in the boot-time defaults",
  disrupt_skipped: "Kill switch under tunnel failure (skipped)",
  disrupt_no_targets: "Kill switch under tunnel failure",
  disrupt_unreachable: "The internet is unreachable while the tunnel is down",
  disrupt_tcpdump: "No packet reached the uplink (tcpdump)",
  disrupt_counters: "The attempt was recorded by the firewall",
  disrupt_blackhole: "The routing table fell back to its blackhole",
};

async function runSelftest(disrupt) {
  const s = S.snap;
  const enabled = s.tunnels.filter((t) => t.enabled);
  if (!enabled.length) { toast("err", "No enabled tunnel"); return; }

  if (disrupt) {
    const ok = await confirmDialog("Run the disruptive test?",
      `'${enabled[0].name}' will actually be taken down while we measure whether anything escapes to the uplink. Clients on it lose connectivity for roughly twenty seconds.`,
      "Run it");
    if (!ok) return;
  }

  S.test = { status: "running", checks: [], ok: null, error: null, at: null };
  render();

  try {
    const res = await api("/api/selftest", "POST", {
      egress_kind: "tunnel", egress_slug: enabled[0].slug, disrupt });
    S.test = { status: "done", checks: res.checks, ok: res.ok, error: null,
               at: Date.now() / 1000 };
    toast(res.ok ? "ok" : "err",
      res.ok ? "Test passed" : "Test failed",
      res.ok ? "No leak found." : "There are critical failures.");
  } catch (err) {
    S.test = { status: "error", checks: [], ok: false, error: err.message,
               at: Date.now() / 1000 };
    toast("err", "Could not run the test", err.message);
  }
  await refresh();
}

/* ── page: logs ────────────────────────────────────────────────────────── */

function renderLogs(host) {
  const q = S.filters.logs.toLowerCase();
  const lvl = S.filters.logLevel;
  const rows = S.events.filter((e) =>
    (lvl === "all" || e.level === lvl) &&
    (!q || e.message.toLowerCase().includes(q) || e.source.toLowerCase().includes(q)));

  add(host, [
    el("div", { class: "row wrap", style: "margin-bottom:16px" },
      searchBox("logs", "Search events…"),
      el("div", { class: "seg" }, ["all", "info", "warning", "error"].map((k) =>
        el("button", { class: lvl === k ? "on" : "",
          onclick: () => { S.filters.logLevel = k; render(); } },
          { all: "All", info: "Info", warning: "Warning", error: "Error" }[k]))),
      el("span", { class: "spacer" }),
      el("span", { style: "font-size:12px;color:var(--text-3)" },
        `${rows.length} events`)),

    el("div", { class: "card" }, rows.length
      ? rows.map((e) => el("div", { class: "logline " + e.level },
          el("time", {}, clock(e.ts)),
          el("span", { class: "lvl" }, e.level.slice(0, 4)),
          el("span", { class: "src" }, e.source),
          el("span", { class: "msg" }, e.message)))
      : emptyState("logs", "Nothing to show", "No event matches that filter.")),
  ]);
}

function searchBox(key, placeholder) {
  return el("div", { class: "search" }, icon("search"),
    el("input", { type: "search", placeholder, value: S.filters[key],
      oninput: (e) => { S.filters[key] = e.target.value; render(); } }));
}

/* ── drawer ────────────────────────────────────────────────────────────── */

function openDrawer(slug) { S.drawerSlug = slug; renderDrawer(); }
function closeDrawer() {
  S.drawerSlug = null;
  $("#drawer").classList.add("hidden");
  $("#drawerBackdrop").classList.add("hidden");
}

function renderDrawer() {
  if (!S.drawerSlug || !S.snap) return;
  const t = S.snap.tunnels.find((x) => x.slug === S.drawerSlug);
  if (!t) return closeDrawer();

  $("#drawer").classList.remove("hidden");
  $("#drawerBackdrop").classList.remove("hidden");
  $("#drawerTitle").textContent = t.name;
  $("#drawerSub").textContent = `${t.iface} · tablo ${t.table} · mark ${t.mark}`;

  const rttSeries = t.history.map((h) => h.rtt || 0);
  const body = $("#drawerBody");
  body.replaceChildren();
  add(body, [
    el("div", { class: "row", style: "margin-bottom:16px" },
      pill(t.enabled ? t.state : "disabled"),
      t.routed ? pill("neutral", "routed")
               : pill("unknown", "no route"),
      el("span", { class: "spacer" }),
      el("button", { class: "btn sm", onclick: () => toggleTunnel(t) },
        icon("power"), t.enabled ? "Disable" : "Enable")),

    !t.routed && t.enabled ? el("p", {
      style: "font-size:12.5px;color:var(--warn);background:var(--warn-soft);padding:10px 12px;border-radius:6px;margin-bottom:16px;line-height:1.5" },
      "This tunnel's routing table has no real default route left, only its blackhole. Clients assigned to it have no internet — which is the intended behaviour, not a fault.") : null,

    el("div", { class: "section-title" }, "Latency"),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      chart([{ values: rttSeries, color: COLOR.rtt }],
            { height: 130, unit: (v) => Math.round(v) + "ms" }))),

    el("div", { class: "section-title" }, "Traffic"),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      chart([{ values: t.history.map((h) => h.rx), color: COLOR.rx },
             { values: t.history.map((h) => h.tx), color: COLOR.tx }],
            { height: 130 }),
      el("div", { class: "legend" },
        el("span", {}, el("i", { style: `background:${COLOR.rx}` }), "download " + rate(t.rx_rate)),
        el("span", {}, el("i", { style: `background:${COLOR.tx}` }), "upload " + rate(t.tx_rate))))),

    el("div", { class: "section-title" }, "Details"),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      el("dl", { class: "kv" },
        el("dt", {}, "Kind"), el("dd", {}, t.kind),
        el("dt", {}, "Interface"), el("dd", {}, t.iface),
        el("dt", {}, "Exit address"), el("dd", {}, t.exit_ip || "—"),
        el("dt", {}, "Latency"), el("dd", {}, t.rtt_ms ? Math.round(t.rtt_ms) + " ms" : "—"),
        el("dt", {}, "Up for"), el("dd", {}, t.up_since ? ago(t.up_since) : "—"),
        el("dt", {}, "MTU"), el("dd", {}, t.mtu || "default"),
        el("dt", {}, "DNS"), el("dd", {}, t.dns.join(", ") || "none pushed"),
        el("dt", {}, "Direct clients"), el("dd", {}, String(t.direct_clients)),
        el("dt", {}, "Via pools"), el("dd", {}, String(t.pool_clients)),
        el("dt", {}, "Member of"), el("dd", {}, t.in_pools.join(", ") || "—"),
        el("dt", {}, "Endpoints"), el("dd", {}, t.endpoints.join(", ") || "—"),
        el("dt", {}, "Endpoint names"), el("dd", {}, t.endpoint_hosts.join(", ") || "—"),
        t.last_error ? el("dt", {}, "Last error") : null,
        t.last_error ? el("dd", { style: "color:var(--danger)" }, t.last_error) : null))),

    !t.endpoints.length ? el("p", {
      style: "font-size:12.5px;color:var(--danger);margin-top:14px;line-height:1.5" },
      "No endpoint address resolved. Under strict host egress the firewall will not let this tunnel connect — the blocked packets show up in the host_egress_drop counter.") : null,

    el("div", { class: "row", style: "margin-top:22px" },
      el("span", { class: "spacer" }),
      el("button", { class: "btn danger", onclick: () => removeTunnel(t) },
        icon("trash"), "Delete tunnel")),
  ]);
}

/* ── actions ───────────────────────────────────────────────────────────── */

const toggleTunnel = (t) =>
  mutate(() => api("/api/tunnels/" + t.slug, "PATCH", { enabled: !t.enabled }),
    `'${t.name}' ${t.enabled ? "disabled" : "enabled"}`);

async function removeTunnel(t) {
  const users = t.direct_clients + t.pool_clients;
  const ok = await confirmDialog(`Delete '${t.name}'?`,
    users ? `${users} client(s) use this tunnel. Move them to another exit first.`
          : "Its config file and keys are deleted too. This cannot be undone.");
  if (!ok) return;
  await mutate(() => api("/api/tunnels/" + t.slug, "DELETE"), "Tunnel deleted");
  if (S.drawerSlug === t.slug) closeDrawer();
}

const togglePool = (p) =>
  mutate(() => api("/api/pools/" + p.slug, "PATCH", { enabled: !p.enabled }),
    `'${p.name}' ${p.enabled ? "disabled" : "enabled"}`);

async function removePool(p) {
  const ok = await confirmDialog(`Delete the '${p.name}' pool?`,
    p.clients ? `${p.clients} client(s) use this pool. Move them first.`
              : "The pool goes; its member tunnels are left alone.");
  if (ok) await mutate(() => api("/api/pools/" + p.slug, "DELETE"), "Pool deleted");
}

const assignClient = (ip, egress) =>
  mutate(() => api("/api/clients/" + ip, "PATCH", { egress: egress || "none" }),
    egress ? "Exit updated" : "Client blocked (no exit assigned)");

async function bulkAssign(egress) {
  if (!egress && egress !== "") return;
  const ips = [...S.selection];
  await mutate(async () => {
    for (const ip of ips)
      await api("/api/clients/" + ip, "PATCH", { egress: egress || "none" });
  }, `Updated the exit for ${ips.length} client(s)`);
  S.selection.clear();
}

async function removeClient(c) {
  const ok = await confirmDialog(`Delete '${c.name}'?`,
    `${c.ip} is removed from the register. Traffic from an unregistered client is dropped.`);
  if (ok) await mutate(() => api("/api/clients/" + c.ip, "DELETE"), "Client deleted");
}

const setMaintenance = (minutes) =>
  mutate(() => api("/api/maintenance", "POST", { minutes }),
    minutes ? `Maintenance window open for ${minutes} minutes` : "Maintenance window closed");

/* ── dialogs ───────────────────────────────────────────────────────────── */

function openTunnelDialog() {
  const f = $("#formTunnel");
  f.reset();
  $("#dropLabel").textContent = "Drop a file here, or click to choose";
  $("#dropzone").classList.remove("filled");
  $("#dlgTunnel").showModal();
}

$("#formTunnel").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value === "cancel") return;
  const f = ev.target;
  const file = f.file.files[0];
  if (!file) { toast("err", "No file selected"); return; }

  const params = new URLSearchParams({
    slug: f.slug.value.toLowerCase(), name: f.name.value,
    auth_user: f.auth_user.value, auth_pass: f.auth_pass.value });
  const body = new FormData();
  body.append("file", file);

  try {
    const res = await fetch("/api/tunnels/import?" + params, { method: "POST", body });
    if (!res.ok) throw new Error((await res.json()).detail || res.statusText);
    const data = await res.json();
    toast("ok", `Imported '${data.slug}'`, `interface ${data.iface}`);
    if (!data.endpoints.length) {
      toast("err", "No endpoint resolved",
        "Under strict host egress the firewall will not let this tunnel connect. Check DNS.");
    }
    await refresh();
  } catch (err) {
    toast("err", "Import failed", err.message);
  }
});

// Drag and drop onto the file field.
{
  const dz = $("#dropzone"), input = dz.querySelector("input");
  const setLabel = () => {
    const f = input.files[0];
    $("#dropLabel").textContent = f ? f.name : "Drop a file here, or click to choose";
    dz.classList.toggle("filled", !!f);
  };
  input.addEventListener("change", setLabel);
  ["dragenter", "dragover"].forEach((e) => dz.addEventListener(e, (ev) => {
    ev.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((e) => dz.addEventListener(e, (ev) => {
    ev.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (ev) => {
    if (ev.dataTransfer.files.length) { input.files = ev.dataTransfer.files; setLabel(); }
  });
}

/** The lowest address in the client network that nothing is using yet.
 *
 *  Starts at .10 rather than .1: the low addresses are where people put
 *  things by hand, and handing out .2 for a new laptop is a good way to
 *  collide with a printer somebody numbered years ago. */
function nextFreeClientIp() {
  if (!S.snap) return "";
  const info = cidrInfo(S.snap.system.lan_cidr);
  if (!info.ok) return "";
  const taken = new Set([
    ...S.snap.clients.map((c) => c.ip),
    ...(S.discovered || []).map((d) => d.ip),
    S.snap.system.lan_gateway,
  ]);
  for (let n = info.network + 10; n < info.broadcast; n++) {
    const candidate = toIPv4(n);
    if (!taken.has(candidate)) return candidate;
  }
  return "";
}

let editingClient = null;
let clientHintAttached = false;

function openClientDialog(client) {
  editingClient = client || null;
  const f = $("#formClient");
  f.reset();
  $("#clientDlgTitle").textContent = client ? "Edit client" : "Add client";

  if (!clientHintAttached) {
    clientHintAttached = true;
    const note = withCidrHint(f.ip, { plain: true });
    f.ip.parentElement.append(note);

    const suggest = el("button", {
      type: "button", class: "suggest",
      onclick: () => {
        const ip = nextFreeClientIp();
        if (!ip) { toast("err", "No free address in the client network"); return; }
        f.ip.value = ip;
        f.ip.dispatchEvent(new Event("input"));
      },
    }, "use next free");
    f.ip.parentElement.querySelector("span").append(suggest);

    // A registered address that is not on the client network will never match
    // anything: say so at the point of typing rather than after saving.
    f.ip.addEventListener("input", () => {
      const value = f.ip.value.trim();
      if (!value || parseIPv4(value) === null || !S.snap) return;
      const nets = [S.snap.system.lan_cidr];
      const inside = nets.some((n) => {
        const i = cidrInfo(n);
        return i.ok && i.contains(value);
      });
      if (!inside) {
        note.textContent = `outside ${S.snap.system.lan_cidr} — allowed only `
          + "if that range is listed under Settings › Client networks";
        note.className = "cidr-note warn";
      }
    });
  }
  $("#clientEgress").replaceChildren(...egressOptions(
    client && client.egress_slug ? `${client.egress_kind}:${client.egress_slug}` : ""));
  if (client) {
    f.name.value = client.name;
    f.ip.value = client.ip;
    f.ip.readOnly = true;
    f.notes.value = client.notes || "";
  } else {
    f.ip.readOnly = false;
  }
  $("#dlgClient").showModal();
}

$("#formClient").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value === "cancel") return;
  const f = ev.target;
  const [kind, slug] = (f.egress.value || ":").split(":");
  try {
    if (editingClient) {
      await api("/api/clients/" + editingClient.ip, "PATCH", {
        name: f.name.value, notes: f.notes.value,
        egress: f.egress.value || "none" });
      toast("ok", "Client updated");
    } else {
      await api("/api/clients", "POST", {
        name: f.name.value, ip: f.ip.value,
        egress_kind: kind || "tunnel", egress_slug: slug || "",
        notes: f.notes.value });
      toast("ok", `Added '${f.name.value}'`, `${f.ip.value} registered`);
    }
    await refresh();
  } catch (err) {
    toast("err", "Could not save", err.message);
  }
});

let poolOrder = [];
function openPoolDialog() {
  poolOrder = S.snap.tunnels.map((t) => ({ slug: t.slug, name: t.name, on: false }));
  $("#formPool").reset();
  renderPoolPicker();
  $("#dlgPool").showModal();
}

function renderPoolPicker() {
  const host = $("#poolPicker");
  const chosen = poolOrder.filter((m) => m.on);
  const byslug = Object.fromEntries((S.snap?.tunnels || []).map((t) => [t.slug, t]));

  const rows = poolOrder.map((m, i) => {
    const t = byslug[m.slug] || {};
    const rank = m.on ? chosen.indexOf(m) + 1 : null;
    const move = (delta) => {
      const j = i + delta;
      if (j < 0 || j >= poolOrder.length) return;
      [poolOrder[j], poolOrder[i]] = [poolOrder[i], poolOrder[j]];
      renderPoolPicker();
    };
    return el("div", { class: "picker-row" + (m.on ? "" : " off") },
      el("input", { type: "checkbox", checked: m.on, id: "pm-" + m.slug,
        onchange: (e) => { m.on = e.target.checked; renderPoolPicker(); } }),
      // The rank is what "priority" means; showing 1st/2nd rather than a
      // number makes it obvious which one carries the pool by default.
      el("span", { class: "order" }, rank ? ordinal(rank) : "—"),
      el("label", { class: "grow", for: "pm-" + m.slug,
                    style: "cursor:pointer;min-width:0" },
        el("div", {}, m.name),
        el("div", { class: "mono",
                    style: "font-size:11px;color:var(--text-3)" },
          [m.slug, t.exit_ip, t.rtt_ms ? Math.round(t.rtt_ms) + " ms" : null]
            .filter(Boolean).join(" · "))),
      t.state ? pill(t.enabled ? t.state : "disabled") : null,
      el("button", { type: "button", class: "btn sm ghost", disabled: i === 0,
        title: "Move up", onclick: () => move(-1) }, "↑"),
      el("button", { type: "button", class: "btn sm ghost",
        disabled: i === poolOrder.length - 1,
        title: "Move down", onclick: () => move(1) }, "↓"));
  });

  host.replaceChildren(...rows);
  const summary = $("#poolSummary");
  if (summary) {
    summary.textContent = chosen.length
      ? `${chosen[0].name} carries the pool; ${
          chosen.length > 1
            ? chosen.slice(1).map((m) => m.name).join(", ") + " take over if it drops"
            : "nothing takes over if it drops"}`
      : "Pick at least one tunnel.";
    summary.className = "cidr-note " + (chosen.length > 1 ? "ok" : "warn");
  }
}

const ordinal = (n) =>
  n + (["th", "st", "nd", "rd"][(n % 100 - 20) % 10] || ["th", "st", "nd", "rd"][n] || "th");

$("#formPool").addEventListener("submit", async (ev) => {
  if (ev.submitter?.value === "cancel") return;
  const f = ev.target;
  const members = poolOrder.filter((m) => m.on)
    .map((m, i) => ({ slug: m.slug, priority: (i + 1) * 10 }));
  if (!members.length) { toast("err", "Select at least one member"); return; }
  try {
    await api("/api/pools", "POST", {
      slug: f.slug.value.toLowerCase(), name: f.name.value,
      strategy: f.strategy.value, sticky_seconds: Number(f.sticky.value),
      members });
    toast("ok", `Created pool '${f.slug.value}'`,
      `${members.length} members, ${STRATEGY_TR[f.strategy.value].toLowerCase()}`);
    await refresh();
  } catch (err) {
    toast("err", "Could not create it", err.message);
  }
});

/* ── page: settings ────────────────────────────────────────────────────── */

function renderSettings(host) {
  const n = S.network;
  if (!n) {
    add(host, [el("div", { class: "card" }, el("div", { class: "card-body" },
      el("div", { class: "skel", style: "height:200px" })))]);
    loadNetwork().then(() => render());
    return;
  }

  const net = n.settings.net, wan = n.settings.wan, dhcp = n.settings.dhcp;
  const lan = splitCidr(net.lan_cidr);
  const wanStatic = splitCidr(wan.address || "0.0.0.0/24");

  // Roles are what an operator thinks in; interface names are an
  // implementation detail they have to map onto them. Show both.
  const roleOf = (name) => {
    if (name === net.wan_iface) return ["WAN", "Uplink to the internet"];
    if (name === net.lan_member) return ["LAN", "Faces the client machines"];
    if (name === net.mgmt_iface) return ["MGMT", "Management only"];
    return ["—", "Unassigned"];
  };

  add(host, [
    /* ── an applied-but-unconfirmed uplink outranks everything else ── */
    wanPendingBanner(),

    /* ── live interface status ─────────────────────────────────────── */
    el("div", { class: "section-title" }, "Interface status"),
    el("div", { class: "card table-wrap" }, el("table", {},
      el("thead", {}, el("tr", {},
        el("th", {}, "Interface"), el("th", {}, "Role"), el("th", {}, "Link"),
        el("th", {}, "IPv4"), el("th", {}, "Purpose"))),
      el("tbody", {}, n.all_interfaces.map((name) => {
        const live = n.interfaces[name] || {};
        const [role, purpose] = roleOf(name);
        return el("tr", {},
          el("td", { class: "mono name" }, name),
          el("td", { class: "tight" },
            role === "—" ? el("span", { class: "mode-tag" }, "unused")
                         : el("span", { class: "pill accent" }, role)),
          el("td", { class: "tight" },
            live.exists === false ? pill("down", "missing")
              : live.up ? pill("up", "up") : pill("unknown", "down")),
          el("td", { class: "mono" },
            (live.addresses || []).join(", ") || "—"),
          el("td", { style: "font-size:12.5px;color:var(--text-3)" }, purpose));
      })))),

    el("form", { id: "formNetwork", oninput: markNetworkDirty,
                 onchange: markNetworkDirty,
                 onsubmit: (e) => { e.preventDefault(); saveNetwork(); } },

      /* ── WAN ─────────────────────────────────────────────────────── */
      el("div", { class: "section-title" }, "WAN — internet connection"),
      el("div", { class: "card" },
        el("div", { class: "card-head" },
          el("div", {}, el("h3", {}, "Uplink"),
            el("p", {}, "The only interface that reaches the internet "
              + "directly. The firewall names it explicitly as somewhere "
              + "forwarded traffic may never go.")),
          el("span", { class: "mono", style: "font-size:12px;color:var(--text-3)" },
            (n.interfaces[net.wan_iface]?.addresses || []).join(", ") || "no address")),
        el("div", { class: "card-body" },
          settingRow("Interface", "Which adapter faces the internet.",
            el("select", { name: "wan_iface" },
              ...ifaceOptions(n, net.wan_iface, false))),
          settingRow("Connection type", "How this interface gets its address.",
            el("select", { name: "wan_mode",
                           onchange: (e) => toggleStaticWan(e.target.value) },
              el("option", { value: "dhcp", selected: wan.mode === "dhcp" },
                "Automatic (DHCP)"),
              el("option", { value: "static", selected: wan.mode === "static" },
                "Static IP"))),
          el("div", { id: "wanStatic",
                      class: wan.mode === "static" ? "" : "hidden" },
            settingRow("IP address", "This machine's address on the uplink.",
              addressField("wan_address", wanStatic.address, "192.168.1.10")),
            settingRow("Subnet mask", "",
              maskSelect("wan_prefix", wanStatic.prefix)),
            settingRow("Default gateway",
              "The router this machine sends internet traffic to. It must be "
              + "inside the subnet above, or the box comes up with an address "
              + "and no way off it.",
              addressField("wan_gateway", wan.gateway, "192.168.1.1"))),
          settingRow("DNS servers",
            "Used only to look up VPN endpoint names before any tunnel exists. "
            + "Under strict host egress these are the only resolvers this "
            + "machine may reach. Comma separated.",
            listAddressField("dns_bootstrap",
              (n.settings.dns.bootstrap || []).join(", "), "1.1.1.1, 9.9.9.9")))),

      /* ── LAN ─────────────────────────────────────────────────────── */
      el("div", { class: "section-title" }, "LAN — client network"),
      el("div", { class: "card" },
        el("div", { class: "card-head" },
          el("div", {}, el("h3", {}, "Client segment"),
            el("p", {}, "Where the machines you want tunnelled live. Any "
              + "private range works.")),
          el("span", { class: "mono", style: "font-size:12px;color:var(--text-3)" },
            `${S.snap ? S.snap.totals.clients_total : 0} registered`)),
        el("div", { class: "card-body" },
          settingRow("Interface", "The adapter facing the clients. vpngw "
            + "enslaves it into the bridge below.",
            el("select", { name: "lan_member" },
              ...ifaceOptions(n, net.lan_member, false))),
          settingRow("Bridge name",
            "vpngw builds this bridge so a second client adapter can be added "
            + "later without redesigning anything.",
            el("input", { name: "lan_bridge", value: net.lan_bridge,
                          placeholder: "br-lan" })),
          settingRow("IP address",
            "The gateway's own address here. Clients use it as their default "
            + "route.",
            addressField("lan_address", lan.address, "10.10.0.1")),
          settingRow("Subnet mask", "", maskSelect("lan_prefix", lan.prefix,
            () => updateLanPreview())),
          el("div", { class: "setting-row" },
            el("div", {}, el("b", {}, "Resulting network")),
            el("div", {}, el("div", { id: "lanPreview", class: "cidr-note ok" }))))),

      /* ── DHCP ────────────────────────────────────────────────────── */
      el("div", { class: "section-title" }, "DHCP server"),
      el("div", { class: "card" }, el("div", { class: "card-body" },
        settingRow("Serve DHCP on the LAN",
          "Off by default: statically addressed clients need nothing handed "
          + "out, and a second DHCP server on a segment that already has one "
          + "breaks it.",
          el("select", { name: "dhcp_enabled",
                         onchange: (e) => toggleDhcp(e.target.value) },
            el("option", { value: "false", selected: !dhcp.enabled }, "Disabled"),
            el("option", { value: "true", selected: dhcp.enabled }, "Enabled"))),
        el("div", { id: "dhcpFields", class: dhcp.enabled ? "" : "hidden" },
          settingRow("Address pool",
            "Leave both blank to derive the pool from the LAN network.",
            el("div", { class: "row" },
              addressField("dhcp_start", dhcp.range_start, n.dhcp_range[0] || ""),
              el("span", { style: "color:var(--text-3)" }, "to"),
              addressField("dhcp_end", dhcp.range_end, n.dhcp_range[1] || ""))),
          settingRow("Lease time", "Hours before a client must renew.",
            el("input", { name: "dhcp_lease", type: "number", min: 1, max: 720,
                          value: dhcp.lease_hours }))))),

      /* ── access ──────────────────────────────────────────────────── */
      el("div", { class: "section-title" }, "Access control"),
      el("div", { class: "card" }, el("div", { class: "card-body" },
        settingRow("Management interface",
          "A dedicated adapter for SSH and this panel — the strongest option, "
          + "because neither clients nor the uplink can reach it at all.",
          el("select", { name: "mgmt_iface" },
            ...ifaceOptions(n, net.mgmt_iface, true))),
        settingRow("Admin source range",
          "Used when there is no management interface: SSH and this panel are "
          + "accepted on the uplink from this range only. Narrow it to your "
          + "own address with /32 if you can.",
          networkField("admin_cidr", net.admin_cidr, "192.168.1.0/24")),

        el("div", { class: "setting-row" },
          el("div", {}, el("b", {}, "Accept clients from"),
            el("small", {}, "Interfaces whose traffic is treated as client "
              + "traffic. Adding the uplink supports clients that share its "
              + "subnet; they stay confined to their tunnel, but they could "
              + "reach the real router directly and nothing here would see it.")),
          el("div", {}, ...n.all_interfaces.concat([net.lan_bridge])
            .filter((v, i, a) => a.indexOf(v) === i)
            .map((name) => el("label", {
              style: "display:flex;gap:8px;align-items:center;padding:4px 0;"
                   + "font-size:13px;cursor:pointer" },
              el("input", {
                type: "checkbox", name: "cif_" + name, style: "width:auto",
                checked: (net.client_ifaces || []).length
                  ? net.client_ifaces.includes(name)
                  : name === net.lan_bridge,
              }),
              el("span", { class: "mono" }, name),
              name === net.wan_iface
                ? el("span", { class: "mode-tag" }, "uplink") : null)))),

        settingRow("Client networks",
          "Address ranges a client may be registered from. Leave blank to "
          + "allow the LAN network only.",
          listNetworkField("client_cidrs",
            (net.client_cidrs || []).join(", "), net.lan_cidr)))),

      /* ── apply ───────────────────────────────────────────────────── */
      el("div", { class: "apply-bar", id: "applyBar" },
        el("div", { id: "applyNote", style: "font-size:12.5px;color:var(--text-2)" },
          "No unsaved changes."),
        el("span", { class: "spacer" }),
        el("button", { class: "btn", type: "button",
          onclick: () => { S.network = null; S.networkDirty = false; render(); } },
          "Revert"),
        el("button", { class: "btn primary", type: "submit", id: "applyBtn",
          disabled: true }, icon("check"), "Apply"))),

    /* ── password ──────────────────────────────────────────────────── */
    el("div", { class: "section-title" }, "Administrator password"),
    el("div", { class: "card" }, el("div", { class: "card-body" },
      el("p", { style: "font-size:12.5px;color:var(--text-2);line-height:1.55;margin-bottom:14px" },
        S.session && S.session.password_set
          ? "Changing it signs out every open session, including this one."
          : "No password is set. Anyone who can reach this panel can change "
            + "anything on the gateway — the firewall is currently the only lock."),
      el("form", { id: "formPassword",
                   onsubmit: (e) => { e.preventDefault(); savePassword(); } },
        S.session && S.session.password_set
          ? el("label", { class: "field" }, el("span", {}, "Current password"),
              el("input", { name: "current", type: "password", required: true,
                            autocomplete: "current-password" }))
          : null,
        el("div", { class: "field-row" },
          el("label", { class: "field" }, el("span", {}, "New password"),
            el("input", { name: "new", type: "password", required: true,
                          minlength: 8, autocomplete: "new-password" })),
          el("label", { class: "field" }, el("span", {}, "Repeat"),
            el("input", { name: "repeat", type: "password", required: true,
                          autocomplete: "new-password" }))),
        el("button", { class: "btn primary", type: "submit" },
          icon("lock"), "Set password")))),
  ]);

  updateLanPreview();
}

/* ── settings building blocks ──────────────────────────────────────────── */

function settingRow(title, help, control) {
  return el("div", { class: "setting-row" },
    el("div", {}, el("b", {}, title), help && el("small", {}, help)),
    el("div", {}, control));
}

function ifaceOptions(n, selected, allowEmpty) {
  const out = allowEmpty ? [el("option", { value: "" }, "— none —")] : [];
  const names = n.all_interfaces.slice();
  if (selected && !names.includes(selected)) names.push(selected);
  for (const name of names) {
    const live = n.interfaces[name] || {};
    const state = live.exists === false ? " (missing)" : live.up ? "" : " (down)";
    out.push(el("option", { value: name, selected: name === selected },
                name + state));
  }
  return out;
}

function maskSelect(name, prefix, onChange) {
  return el("select", { name, onchange: () => onChange && onChange() },
    ...MASKS.map(([len, mask, hosts]) =>
      el("option", { value: len, selected: Number(prefix) === len },
        `${mask}  /${len}  —  ${hosts}`)));
}

/** A plain host address, validated as you type. */
function addressField(name, value, placeholder) {
  const input = el("input", { name, value: value ?? "",
                              placeholder: placeholder || "" });
  const note = el("small", { class: "cidr-note" }, "");
  const update = () => {
    const v = input.value.trim();
    if (!v) { note.textContent = ""; note.className = "cidr-note";
              input.setCustomValidity(""); return; }
    const ok = parseIPv4(v) !== null;
    note.textContent = ok ? "" : "not a valid IPv4 address";
    note.className = "cidr-note " + (ok ? "ok" : "bad");
    input.setCustomValidity(ok ? "" : "invalid address");
  };
  input.addEventListener("input", update);
  update();
  const wrap = el("div", {}, input, note);
  return wrap;
}

/** An address with a prefix, e.g. an admin range. */
function networkField(name, value, placeholder) {
  const input = el("input", { name, value: value ?? "",
                              placeholder: placeholder || "" });
  const wrap = el("div", {}, input);
  wrap.append(withCidrHint(input, { wantHost: false }));
  return wrap;
}

function listAddressField(name, value, placeholder) {
  const input = el("input", { name, value, placeholder });
  const note = el("small", { class: "cidr-note" }, "");
  const update = () => {
    const items = input.value.split(",").map((s) => s.trim()).filter(Boolean);
    const bad = items.filter((i) => parseIPv4(i) === null);
    note.textContent = bad.length ? `not an address: ${bad.join(", ")}` : "";
    note.className = "cidr-note " + (bad.length ? "bad" : "ok");
    input.setCustomValidity(bad.length ? "invalid address" : "");
  };
  input.addEventListener("input", update);
  update();
  return el("div", {}, input, note);
}

function listNetworkField(name, value, placeholder) {
  const input = el("input", { name, value, placeholder });
  const note = el("small", { class: "cidr-note" }, "");
  const update = () => {
    const items = input.value.split(",").map((s) => s.trim()).filter(Boolean);
    if (!items.length) { note.textContent = ""; note.className = "cidr-note";
                         input.setCustomValidity(""); return; }
    const bad = items.filter((i) => !cidrInfo(i).ok);
    note.textContent = bad.length
      ? `not a network: ${bad.join(", ")}`
      : items.map((i) => cidrInfo(i).networkText).join(" · ");
    note.className = "cidr-note " + (bad.length ? "bad" : "ok");
    input.setCustomValidity(bad.length ? "invalid network" : "");
  };
  input.addEventListener("input", update);
  update();
  return el("div", {}, input, note);
}

function toggleStaticWan(mode) {
  const box = $("#wanStatic");
  if (box) box.classList.toggle("hidden", mode !== "static");
}

function toggleDhcp(value) {
  const box = $("#dhcpFields");
  if (box) box.classList.toggle("hidden", value !== "true");
}

/** Show what the LAN address and mask actually add up to. */
function updateLanPreview() {
  const f = $("#formNetwork");
  const out = $("#lanPreview");
  if (!f || !out) return;
  const info = cidrInfo(joinCidr(f.lan_address.value, f.lan_prefix.value));
  if (!info.ok) {
    out.textContent = info.error;
    out.className = "cidr-note bad";
    return;
  }
  // The gateway holds one address in this range, so it is not one a client
  // can be given. Saying "clients 10.10.0.1 - 10.10.0.254" when .1 is the
  // gateway itself is the kind of off-by-one that only shows up as a duplicate
  // address weeks later.
  const gw = parseIPv4(f.lan_address.value);
  let first = info.first, last = info.last, note = "";
  if (gw !== null && gw >= info.first && gw <= info.last) {
    if (gw === info.first) first = info.first + 1;
    else if (gw === info.last) last = info.last - 1;
    else note = ` except ${toIPv4(gw)}`;
  }
  const count = Math.max(0, last - first + 1) - (note ? 1 : 0);
  out.textContent = count > 0
    ? `${info.networkText} · clients ${toIPv4(first)} – ${toIPv4(last)}`
      + `${note} · ${count.toLocaleString()} assignable`
    : `${info.networkText} · no room for a client after the gateway`;
  out.className = "cidr-note " + (info.isHost && count > 0 ? "ok" : "warn");
  if (!info.isHost) {
    out.textContent += " — the gateway cannot use the network or broadcast address";
  }
}

/** Nothing is written until something actually changed. */
function markNetworkDirty() {
  S.networkDirty = true;
  const btn = $("#applyBtn");
  const note = $("#applyNote");
  if (btn) btn.disabled = false;
  if (note) {
    const f = $("#formNetwork");
    const changesWan = f && S.network &&
      (f.wan_iface.value !== S.network.settings.net.wan_iface ||
       f.wan_mode.value !== S.network.settings.wan.mode);
    note.textContent = changesWan
      ? "Unsaved changes, including the uplink — applying that can cut this "
        + "session off."
      : "Unsaved changes.";
    note.style.color = changesWan ? "var(--warn)" : "var(--text-2)";
  }
  updateLanPreview();
}

async function loadNetwork() {
  try {
    S.network = await api("/api/network");
  } catch (err) {
    toast("err", "Could not load network settings", err.message);
  }
}

async function saveNetwork() {
  const f = $("#formNetwork");
  const list = (v) => v.split(",").map((x) => x.trim()).filter(Boolean);

  const clientIfaces = [...f.querySelectorAll("input[name^=cif_]")]
    .filter((c) => c.checked)
    .map((c) => c.name.slice(4));

  const body = {
    net: {
      wan_iface: f.wan_iface.value,
      lan_member: f.lan_member.value,
      lan_bridge: f.lan_bridge.value.trim(),
      lan_cidr: joinCidr(f.lan_address.value, f.lan_prefix.value),
      mgmt_iface: f.mgmt_iface.value,
      admin_cidr: f.admin_cidr.value.trim(),
      client_ifaces: clientIfaces,
      client_cidrs: list(f.client_cidrs.value),
    },
    wan: {
      mode: f.wan_mode.value,
      address: f.wan_mode.value === "static"
        ? joinCidr(f.wan_address.value, f.wan_prefix.value) : "",
      gateway: f.wan_mode.value === "static" ? f.wan_gateway.value.trim() : "",
    },
    dhcp: {
      enabled: f.dhcp_enabled.value === "true",
      range_start: f.dhcp_start.value.trim(),
      range_end: f.dhcp_end.value.trim(),
      lease_hours: Number(f.dhcp_lease.value) || 12,
    },
    dns: { bootstrap: list(f.dns_bootstrap.value) },
  };

  // Changing the uplink can cut off the session doing the changing, so it is
  // never a silent save.
  const wanChanged = S.network &&
    (body.net.wan_iface !== S.network.settings.net.wan_iface ||
     body.wan.mode !== S.network.settings.wan.mode ||
     body.wan.address !== (S.network.settings.wan.address || ""));

  let res;
  try {
    res = await api("/api/network", "POST", body);
  } catch (err) {
    toast("err", "Rejected", err.message);
    return;
  }
  S.networkDirty = false;
  S.network = null;

  if (!wanChanged) {
    toast("ok", "Network settings saved", res.note);
    await refresh();
    render();
    return;
  }

  // Saved, but the interface still holds the old address. Applying it is a
  // separate, deliberate step because it is the one change that can end the
  // session making it.
  const where = body.wan.mode === "static"
    ? body.wan.address : "whatever DHCP hands out";
  const ok = await confirmDialog(
    "Apply the new uplink now?",
    `The settings are saved. Applying moves ${body.net.wan_iface} to ${where}, `
    + "which will end this session if you are connected over that address — "
    + "the panel will simply stop responding. "
    + "That is recoverable: the previous configuration comes back on its own "
    + "after 5 minutes unless you reach the panel on the new address and "
    + "confirm. Nothing is permanent until you do.",
    "Apply now");
  if (!ok) {
    toast("ok", "Saved, not applied",
          `${body.net.wan_iface} keeps its current address until you apply.`);
    await refresh();
    render();
    return;
  }

  try {
    await api("/api/network/wan/apply", "POST", { rollback_minutes: 5 });
    toast("ok", "Applied — confirm within 5 minutes",
          "If this page still works, press Keep. Otherwise do nothing and the "
          + "old address returns by itself.");
  } catch (err) {
    // A failure here usually means the box moved and this request never got
    // an answer, which is exactly the case the timer covers.
    toast("warn", "No answer after applying",
          "Reach the panel on the new address to keep the change; otherwise "
          + "the old one returns within 5 minutes.");
  }
  await refresh();
  render();
}

/** The commit-confirm banner: a change is live but not yet permanent.
 *
 *  The countdown comes from the daemon rather than from this page, because
 *  applying an address change usually drops the session that applied it. The
 *  page that needs to show this banner is normally a fresh load that never
 *  saw the apply happen.
 */
function wanPendingBanner() {
  const left = S.network ? Number(S.network.rollback_seconds || 0) : 0;
  if (left === 0) return null;
  // -1 means the daemon knows a change is pending but not how long is left.
  // Still show the banner: hiding it would let a working change revert simply
  // because nobody was told they had to keep it.
  const when = left < 0 ? "shortly"
    : `in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
  return el("div", { class: "card", id: "wanPending",
                     style: "border-color:var(--warn);background:var(--warn-soft)" },
    el("div", { class: "card-body",
                style: "display:flex;align-items:center;gap:14px;flex-wrap:wrap" },
      el("div", { style: "flex:1;min-width:260px" },
        el("b", {}, "The uplink change is not permanent yet"),
        el("div", { style: "font-size:12.5px;color:var(--text-2);margin-top:3px" },
          `Reverting ${when} unless you keep it. You are reading this, `
          + "so the new address works.")),
      el("button", { class: "btn", type: "button",
        onclick: () => mutate(
          () => api("/api/network/wan/revert", "POST", {}),
          "Previous uplink restored").then(() => { S.network = null; render(); }) },
        "Revert now"),
      el("button", { class: "btn primary", type: "button",
        onclick: async () => {
          await mutate(() => api("/api/network/wan/confirm", "POST", {}),
                       "Uplink change kept");
          S.network = null; render();
        } }, icon("check"), "Keep this address")));
}

async function savePassword() {
  const f = $("#formPassword");
  if (f.new.value !== f.repeat.value) {
    toast("err", "The two entries do not match"); return;
  }
  try {
    await api("/api/password", "POST", {
      current: f.current ? f.current.value : "",
      new: f.new.value,
    });
    toast("ok", "Password set", "Every session was signed out.");
    setTimeout(() => location.reload(), 900);
  } catch (err) {
    toast("err", "Could not set the password", err.message);
  }
}

/* ── login gate ────────────────────────────────────────────────────────── */

async function checkSession() {
  try {
    S.session = await api("/api/session");
  } catch (err) {
    S.session = { password_set: false, authenticated: true };
  }
  const gate = $("#gate");
  const firstRun = !S.session.password_set;
  if (S.session.authenticated && !firstRun) { gate.classList.add("hidden"); return true; }
  if (S.session.authenticated && firstRun) { gate.classList.add("hidden"); return true; }

  $("#gateTitle").textContent = firstRun ? "Choose a password" : "Sign in";
  $("#gateHint").textContent = firstRun
    ? "This gateway has no panel password yet. Anyone who can reach this page "
      + "can change anything on it, so set one now."
    : "This panel is reachable from the management network only. The password "
      + "is a second lock, not the first.";
  $("#gateRepeatWrap").classList.toggle("hidden", !firstRun);
  gate.classList.remove("hidden");
  $("#formGate").querySelector("input[name=password]").focus();
  return false;
}

document.getElementById("formGate").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = ev.target;
  const err = $("#gateError");
  err.classList.add("hidden");
  const firstRun = !$("#gateRepeatWrap").classList.contains("hidden");
  if (firstRun && f.password.value !== f.repeat.value) {
    err.textContent = "The two entries do not match.";
    err.classList.remove("hidden");
    return;
  }
  try {
    await api("/api/login", "POST", { password: f.password.value });
    f.reset();
    $("#gate").classList.add("hidden");
    await checkSession();
    await loadProviders();
    await refresh();
  } catch (e) {
    err.textContent = e.message;
    err.classList.remove("hidden");
  }
});

/* ── render ────────────────────────────────────────────────────────────── */

const RENDERERS = {
  dashboard: renderDashboard, tunnels: renderTunnels, pools: renderPools,
  providers: renderProviders,
  settings: renderSettings,
  clients: renderClients, security: renderSecurity, logs: renderLogs,
};

function go(page) {
  S.page = page;
  location.hash = "#" + page;
  S.selection.clear();
  // The provider catalogue is not part of the status poll, so fetch it the
  // first time somebody actually looks at the page.
  if (page === "providers" && !S.providers.length) loadProviders().then(render);
  render();
}

/* Pages that are a form rather than a live view. The poll loop must not
   rebuild these: a page that redraws every three seconds throws away whatever
   you were halfway through typing. */
const STATIC_PAGES = new Set(["settings"]);

/** Settings is normally left alone by the poll loop - it is a form, and
 *  redrawing a form throws away what is being typed into it. The one
 *  exception is a countdown that is telling the operator how long they have
 *  to confirm: a frozen clock there is worse than a lost keystroke. */
function settingsNeedsTicking() {
  return S.page === "settings" && S.network
      && Number(S.network.rollback_seconds || 0) !== 0;
}

/** True when the operator is in the middle of something a redraw would ruin.
 *
 *  Rebuilding the DOM under an open <select> closes it, and under a focused
 *  input it loses the caret and anything typed since the last tick. Both look
 *  like the panel fighting you, and both are entirely avoidable: a poll that
 *  finds the page busy can simply wait for the next one. */
function pageIsBusy() {
  const active = document.activeElement;
  if (!active || active === document.body) return false;
  if (!/^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) return false;
  return !!active.closest(".page, dialog, .drawer");
}

function render(options = {}) {
  if (!S.snap) return;
  if (options.poll) {
    if (STATIC_PAGES.has(S.page) && !settingsNeedsTicking()) return;
    if (pageIsBusy()) return;
  }
  const [title, sub] = PAGES[S.page] || PAGES.dashboard;
  $("#pageTitle").textContent = title;
  $("#pageSub").textContent = sub;

  for (const btn of document.querySelectorAll(".nav-item"))
    btn.classList.toggle("active", btn.dataset.page === S.page);
  for (const sec of document.querySelectorAll(".page"))
    sec.classList.toggle("hidden", sec.id !== "page-" + S.page);

  const t = S.snap.totals;
  $("#navTunnels").textContent = `${t.tunnels_up}/${t.tunnels_total}`;
  $("#navPools").textContent = S.snap.pools.length || "";
  $("#navClients").textContent = t.clients_total || "";
  $("#navClients").classList.toggle("alert", t.clients_blocked > 0);
  $("#navTunnels").classList.toggle("alert",
    t.tunnels_total > 0 && t.tunnels_up < t.tunnels_total);

  $("#brandVersion").textContent = "v" + S.snap.system.version;
  $("#sysLan").textContent = S.snap.system.lan_cidr;
  $("#sysUptime").textContent = duration(S.snap.system.uptime);

  const primary = $("#btnPrimary");
  const PRIMARY = {
    tunnels: ["Add tunnel", openTunnelDialog],
    pools: ["Create pool", openPoolDialog],
    clients: ["Add client", () => openClientDialog()],
    providers: ["Bulk import", openBundleDialog],
    settings: [null, null],
    security: [null, null],
    logs: [null, null],
  };
  const [label, action] = PRIMARY[S.page] || ["Add tunnel", openTunnelDialog];
  // Pages with nothing to create hide the button rather than offering an
  // action that belongs to a different page.
  primary.classList.toggle("hidden", !label);
  if (label) {
    primary.lastChild.textContent = label;
    primary.onclick = action;
  }

  const host = $("#page-" + S.page);
  host.replaceChildren();
  RENDERERS[S.page](host);
  if (S.drawerSlug) renderDrawer();
}

/** True while the sign-in card is covering the page. */
const signedOut = () => !$("#gate").classList.contains("hidden");

async function refresh(options = {}) {
  // Polling from behind the sign-in card only produces 401s: a console full
  // of errors, and a "cannot reach the daemon" toast that blames the wrong
  // thing on a page whose whole job is to say you are not signed in.
  if (signedOut()) return;
  try {
    const [snap, events, found] = await Promise.all([
      api("/api/status"),
      api("/api/events?limit=200").catch(() => S.events),
      api("/api/discovered").catch(() => S.discovered),
    ]);
    S.snap = snap;
    S.events = events;
    S.discovered = found || [];
    const nav = $("#navClients");
    if (nav && S.discovered.length) {
      nav.textContent = `${snap.totals.clients_total}+${S.discovered.length}`;
      nav.classList.add("alert");
    }
    if (S.lastError) { toast("ok", "Reconnected to the daemon"); S.lastError = null; }
    render(options);
  } catch (err) {
    // Being signed out is not the daemon being down, and saying so sends
    // people to look at the service when the answer is on screen already.
    if (err.message === "signed out") return;
    if (!S.lastError) {
      S.lastError = err.message;
      toast("err", "Cannot reach the daemon", err.message);
    }
  }
}

/* ── wiring ────────────────────────────────────────────────────────────── */

document.querySelectorAll(".nav-item").forEach((b) =>
  b.addEventListener("click", () => go(b.dataset.page)));

$("#btnRefresh").addEventListener("click", () => {
  api("/api/reconcile", "POST", {}).catch(() => {});
  refresh();
});

$("#liveToggle").addEventListener("click", () => {
  S.live = !S.live;
  $("#liveToggle").classList.toggle("paused", !S.live);
  $("#liveText").textContent = S.live ? "live" : "paused";
  $("#liveToggle").title = S.live ? "Pause auto-refresh" : "Resume auto-refresh";
  if (S.live) refresh();
});

$("#drawerClose").addEventListener("click", closeDrawer);
$("#drawerBackdrop").addEventListener("click", closeDrawer);

/* Three states, matching the CSS: "dark" and "light" stamp data-theme on the
 * root, "system" removes it so prefers-color-scheme decides. The button shows
 * which state it is in rather than guessing an icon for it. */
const THEMES = [
  ["system", "system", "clock"],
  ["light", "light", "sun"],
  ["dark", "dark", "moon"],
];

function applyTheme(name) {
  const [key, label, ic] = THEMES.find((t) => t[0] === name) || THEMES[0];
  if (key === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = key;
  localStorage.setItem("vpngw-theme", key);
  $("#themeIcon").replaceChildren(icon(ic));
  $("#themeLabel").textContent = label;
}

$("#themeToggle").addEventListener("click", () => {
  const current = localStorage.getItem("vpngw-theme") || "system";
  const i = THEMES.findIndex((t) => t[0] === current);
  applyTheme(THEMES[(i + 1) % THEMES.length][0]);
});
applyTheme(localStorage.getItem("vpngw-theme") || "system");

window.addEventListener("hashchange", () => {
  const p = location.hash.slice(1);
  if (PAGES[p] && p !== S.page) { S.page = p; render(); }
});

document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && S.drawerSlug) closeDrawer();
  if (ev.key === "/" && !/^(INPUT|SELECT|TEXTAREA)$/.test(ev.target.tagName)) {
    const box = document.querySelector(".page:not(.hidden) .search input");
    if (box) { ev.preventDefault(); box.focus(); }
  }
});

if (!PAGES[S.page]) S.page = "dashboard";
checkSession().then((ok) => {
  if (!ok) return;
  loadProviders().then(() => { if (S.snap) render(); });
  refresh();
});
setInterval(() => { if (S.live && !document.hidden) refresh({ poll: true }); }, 3000);

// A pending uplink change is on a wall-clock timer the daemon owns, so the
// countdown has to be re-read rather than decremented locally.
setInterval(() => {
  if (!S.live || document.hidden) return;
  if (S.page !== "settings" || pageIsBusy()) return;
  if (!S.network || Number(S.network.rollback_seconds || 0) === 0) return;
  loadNetwork().then(() => render({ poll: true }));
}, 3000);
