"""HTTP API and web UI.

Reachable only from the management interface: the input chain drops port 8080
from the client bridge and from the uplink, so the surface here is the Windows
host and nothing else. That is the security boundary - an optional token adds a
second one for anyone who wants it, but the firewall is what is actually
holding the line.

Every mutating endpoint writes to the database and asks the reconcile loop to
run. None of them touches the kernel directly.
"""

from __future__ import annotations

import hmac
import logging
from pathlib import Path

from fastapi import (
    Body, FastAPI, Header, HTTPException, Request, Response, UploadFile,
)
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from . import auth, config
from .models import (
    Client,
    EgressKind,
    Pool,
    PoolMember,
    PoolStrategy,
    Tunnel,
    TunnelKind,
    ValidationError,
)

log = logging.getLogger("vpngw.api")

WEB = Path(__file__).parent / "web"


SESSION_COOKIE = "vpngw_session"
# Reachable without a session: the login exchange itself, and the question
# "does this gateway even have a password yet".
OPEN_PATHS = {"/api/login", "/api/session"}


def create_app(service) -> FastAPI:
    app = FastAPI(title="VPN Gateway", docs_url="/api/docs", redoc_url=None)
    db = service.db
    # Read through the service rather than captured once: a settings change
    # must be visible to the very next request, or the panel re-reads and
    # reports the operator's change as missing.
    class _Live:
        def __getattr__(self, name):
            return getattr(service.settings, name)

        def to_dict(self):
            return service.settings.to_dict()

    settings = _Live()
    token = getattr(settings.api, "token", "")
    sessions = auth.Sessions(db)
    service.sessions = sessions

    def authorised(request: Request) -> bool:
        # A gateway with no password set is not locked: the firewall is what
        # admits you, and refusing to serve the page that lets you set one
        # would leave a fresh install unmanageable.
        if not auth.is_configured(db):
            return True
        if sessions.valid(request.cookies.get(SESSION_COOKIE)):
            return True
        supplied = request.headers.get("x-vpngw-token")
        if bool(token) and supplied == token:
            return True
        # The on-box CLI, which only root can authenticate as. Without this
        # `vpngwctl passwd` - the way back in after a forgotten password -
        # would be locked behind the password it exists to reset.
        local = config.local_token()
        return bool(local) and bool(supplied) and hmac.compare_digest(supplied, local)

    @app.middleware("http")
    async def require_session(request: Request, call_next):
        path = request.url.path
        if path.startswith("/api/") and path not in OPEN_PATHS:
            if not authorised(request):
                return JSONResponse(status_code=401,
                                    content={"detail": "authentication required"})
        return await call_next(request)

    def authorise(_supplied: str | None = None) -> None:
        """Retained so endpoints read the same; the middleware above is what
        actually enforces access, in one place rather than per route."""
        return None

    def touched():
        service.request_reconcile()
        return {"ok": True}

    if (WEB / "static").is_dir():
        app.mount("/static", StaticFiles(directory=WEB / "static"), name="static")

    @app.exception_handler(ValidationError)
    async def _validation(_request: Request, exc: ValidationError):
        return JSONResponse(status_code=400, content={"detail": str(exc)})

    # -- UI ----------------------------------------------------------------

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        page = WEB / "templates" / "index.html"
        if not page.exists():
            return "<h1>VPN Gateway</h1><p>UI assets are missing.</p>"
        return page.read_text(encoding="utf-8")

    # -- authentication ----------------------------------------------------

    @app.get("/api/session")
    def session_state(request: Request) -> dict:
        """Whether a password exists and whether this caller is past it.

        Open on purpose: the UI has to know which of three screens to show -
        first-run setup, login, or the panel - before it has any credential.
        Nothing here reveals anything a caller could not learn by trying.
        """
        return {
            "password_set": auth.is_configured(db),
            "authenticated": authorised(request),
        }

    @app.post("/api/login")
    def login(request: Request, response: Response, body: dict = Body(...)) -> dict:
        source = request.client.host if request.client else "?"
        wait = sessions.throttled(source)
        if wait:
            raise HTTPException(
                status_code=429,
                detail=f"too many attempts; try again in {wait} seconds")

        if not auth.is_configured(db):
            # First run: the first password submitted becomes the password.
            # Anyone who can reach this endpoint is already past the firewall,
            # so there is nobody else to authenticate against.
            try:
                auth.set_password(db, body.get("password", ""))
            except auth.AuthError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
        elif not auth.check_password(db, body.get("password", "")):
            sessions.note_failure(source)
            db.log_event("warning", "auth", f"failed login from {source}")
            raise HTTPException(status_code=401, detail="wrong password")

        token_value = sessions.issue()
        response.set_cookie(
            SESSION_COOKIE, token_value, httponly=True, samesite="strict",
            max_age=auth.SESSION_TTL, path="/",
        )
        db.log_event("info", "auth", f"signed in from {source}")
        return {"ok": True}

    @app.post("/api/logout")
    def logout(request: Request, response: Response) -> dict:
        sessions.revoke(request.cookies.get(SESSION_COOKIE))
        response.delete_cookie(SESSION_COOKIE, path="/")
        return {"ok": True}

    @app.post("/api/password")
    def change_password(request: Request, body: dict = Body(...)) -> dict:
        # Changing it requires proving the current one, even with a valid
        # session: a session left open on somebody's desk should not be enough
        # to lock the owner out of their own gateway.
        if auth.is_configured(db):
            if not auth.check_password(db, body.get("current", "")):
                raise HTTPException(status_code=401,
                                    detail="the current password is wrong")
        try:
            auth.set_password(db, body.get("new", ""))
        except auth.AuthError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        sessions.revoke_all()
        return {"ok": True, "note": "every session was signed out"}

    # -- read --------------------------------------------------------------

    @app.get("/api/status")
    def status(x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        return service.snapshot()

    @app.get("/api/events")
    def events(limit: int = 100,
               x_vpngw_token: str | None = Header(default=None)) -> list[dict]:
        authorise(x_vpngw_token)
        return db.events(min(limit, 500))

    @app.get("/api/ruleset", response_class=PlainTextResponse)
    def ruleset(x_vpngw_token: str | None = Header(default=None)) -> str:
        """The exact ruleset currently generated, for anyone who wants to read
        the firewall rather than take our word for it."""
        authorise(x_vpngw_token)
        from .render import nftables
        return nftables.render(
            settings, db.tunnels(), db.pools(), db.clients(),
            maintenance=service.reconciler.maintenance_active(),
        )

    # -- tunnels -----------------------------------------------------------

    @app.post("/api/tunnels/import")
    async def import_tunnel(
        slug: str, file: UploadFile, name: str = "", kind: str = "",
        auth_user: str = "", auth_pass: str = "",
        x_vpngw_token: str | None = Header(default=None),
    ) -> dict:
        authorise(x_vpngw_token)
        from .importers import (
            ImportError_, ovpn_endpoint_hosts, parse_openvpn, parse_wireguard,
            resolve_endpoints, wg_endpoint_hosts,
        )
        import json as _json

        text = (await file.read()).decode(errors="replace")
        detected = kind or (
            "wireguard" if "[Interface]" in text and "PrivateKey" in text
            else "openvpn"
        )
        config.SECRETS_DIR.mkdir(parents=True, exist_ok=True)
        config.SECRETS_DIR.chmod(0o700)

        try:
            if detected == "wireguard":
                spec = parse_wireguard(text)
                hosts = wg_endpoint_hosts(spec)
                stored = config.SECRETS_DIR / f"{slug}.json"
                config.write_secret(stored, _json.dumps(spec.to_dict(), indent=2))
                dns, mtu = spec.dns, spec.mtu
            else:
                spec = parse_openvpn(text)
                hosts = ovpn_endpoint_hosts(spec)
                stored = config.SECRETS_DIR / f"{slug}.ovpn"
                config.write_secret(stored, text)
                dns, mtu = [], 0
        except ImportError_ as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        if auth_user:
            config.write_secret(config.SECRETS_DIR / f"{slug}.auth",
                                f"{auth_user}\n{auth_pass}\n")

        addrs, names = resolve_endpoints(hosts)
        tunnel = db.add_tunnel(Tunnel(
            slug=slug, name=name or slug, kind=TunnelKind(detected),
            esid=db.next_tunnel_esid(), config_path=str(stored),
            mtu=mtu, dns=dns, endpoints=addrs, endpoint_hosts=names,
        ))
        db.log_event("info", tunnel.slug, f"imported ({detected})")
        touched()
        return {"slug": tunnel.slug, "iface": tunnel.iface,
                "endpoints": addrs, "unresolved": names}

    @app.patch("/api/tunnels/{slug}")
    def patch_tunnel(slug: str, body: dict = Body(...),
                     x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        t = db.tunnel(slug)
        if not t:
            raise HTTPException(status_code=404, detail="unknown tunnel")
        if "enabled" in body:
            t.enabled = bool(body["enabled"])
        if "name" in body:
            t.name = str(body["name"])
        if "mtu" in body:
            t.mtu = int(body["mtu"])
        db.update_tunnel(t)
        return touched()

    @app.delete("/api/tunnels/{slug}")
    def delete_tunnel(slug: str,
                      x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        db.delete_tunnel(slug)
        for suffix in (".json", ".ovpn", ".auth"):
            (config.SECRETS_DIR / f"{slug}{suffix}").unlink(missing_ok=True)
        return touched()

    # -- pools -------------------------------------------------------------

    @app.post("/api/pools")
    def create_pool(body: dict = Body(...),
                    x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        members = [
            PoolMember(m["slug"], int(m.get("priority", (i + 1) * 10)))
            for i, m in enumerate(body.get("members", []))
        ]
        pool = db.add_pool(Pool(
            slug=body["slug"], name=body.get("name") or body["slug"],
            esid=db.next_pool_esid(),
            strategy=PoolStrategy(body.get("strategy", "priority")),
            sticky_seconds=int(body.get("sticky_seconds", 60)),
            rotate_seconds=int(body.get("rotate_seconds", 300)),
            members=members,
        ))
        touched()
        return {"slug": pool.slug, "table": pool.table}

    @app.patch("/api/pools/{slug}")
    def patch_pool(slug: str, body: dict = Body(...),
                   x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        pool = db.pool(slug)
        if not pool:
            raise HTTPException(status_code=404, detail="unknown pool")
        if "enabled" in body:
            pool.enabled = bool(body["enabled"])
        if "name" in body:
            pool.name = str(body["name"])
        if "strategy" in body:
            pool.strategy = PoolStrategy(body["strategy"])
        if "sticky_seconds" in body:
            pool.sticky_seconds = int(body["sticky_seconds"])
        if "members" in body:
            pool.members = [
                PoolMember(m["slug"], int(m.get("priority", 100)))
                for m in body["members"]
            ]
        db.update_pool(pool)
        return touched()

    @app.delete("/api/pools/{slug}")
    def delete_pool(slug: str,
                    x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        db.delete_pool(slug)
        return touched()

    # -- clients -----------------------------------------------------------

    @app.post("/api/clients")
    def create_client(body: dict = Body(...),
                      x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        client = Client(
            name=body["name"], ip=body["ip"], mac=body.get("mac", ""),
            egress_kind=EgressKind(body.get("egress_kind", "tunnel")),
            egress_slug=body.get("egress_slug", ""),
            notes=body.get("notes", ""),
        )
        client.check_in_lan(settings.net.client_networks())
        db.add_client(client)
        db.log_event("info", client.ip, f"client {client.name} added")
        touched()
        return {"ip": client.ip}

    @app.patch("/api/clients/{ip}")
    def patch_client(ip: str, body: dict = Body(...),
                     x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        client = db.client(ip)
        if not client:
            raise HTTPException(status_code=404, detail="unknown client")
        if "egress" in body:
            raw = body["egress"] or ""
            if raw in ("", "none"):
                client.egress_slug = ""
            else:
                kind, _, slug = raw.partition(":")
                client.egress_kind = EgressKind(kind)
                client.egress_slug = slug
        if "enabled" in body:
            client.enabled = bool(body["enabled"])
        if "name" in body:
            client.name = str(body["name"])
        if "notes" in body:
            client.notes = str(body["notes"])
        db.update_client(client)
        db.log_event("info", client.ip,
                     f"egress -> {client.egress_kind.value}:"
                     f"{client.egress_slug or 'none'}")
        return touched()

    @app.delete("/api/clients/{ip}")
    def delete_client(ip: str,
                      x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        db.delete_client(ip)
        return touched()

    # -- operations --------------------------------------------------------

    @app.post("/api/reconcile")
    def reconcile(x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        return touched()

    # -- network -----------------------------------------------------------

    @app.get("/api/network")
    def network_state(x_vpngw_token: str | None = Header(default=None)) -> dict:
        from .net import ifaces

        live = {}
        for name in {settings.net.wan_iface, settings.net.lan_bridge,
                     settings.net.lan_member, settings.net.mgmt_iface}:
            if name:
                live[name] = {
                    "exists": ifaces.exists(name),
                    "up": ifaces.is_up(name),
                    "addresses": sorted(ifaces.addresses(name)),
                }
        from .net import apply as netapply

        return {
            "settings": settings.to_dict(),
            "interfaces": live,
            "all_interfaces": sorted(ifaces.physical_names()),
            "dhcp_range": list(_dhcp_range_or_empty(settings)),
            # Survives the page reload an address change usually forces: the
            # banner has to come back on its own, or nobody confirms and a
            # working change reverts for no reason.
            "rollback_seconds": netapply.rollback_seconds_left(),
        }

    def _dhcp_range_or_empty(s):
        try:
            return s.dhcp_range()
        except Exception:
            return ("", "")

    @app.post("/api/network")
    def network_update(body: dict = Body(...),
                       x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Rewrite the network settings and apply them.

        Validated and written atomically before anything is applied. A config
        that would leave no way to administer this box is refused here rather
        than discovered after the ruleset loads, when there would be no way
        left to fix it.
        """
        import dataclasses

        current = config.Settings.load()
        sections = {"net": config.NetSettings, "wan": config.WanSettings,
                    "dhcp": config.DhcpSettings, "dns": config.DnsSettings}
        updates = {}
        for name, klass in sections.items():
            incoming = body.get(name)
            if not isinstance(incoming, dict):
                continue
            existing = getattr(current, name)
            fields = {}
            for key, value in incoming.items():
                if key not in klass.__dataclass_fields__:
                    raise HTTPException(status_code=400,
                                        detail=f"[{name}] unknown key {key!r}")
                fields[key] = tuple(value) if isinstance(value, list) else value
            updates[name] = dataclasses.replace(existing, **fields)

        candidate = dataclasses.replace(current, **updates)
        try:
            candidate.validate()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        candidate.write()
        service.reload_settings()
        db.log_event("warning", "network",
                     "network settings changed; restart to apply fully")
        service.request_reconcile()
        return {
            "ok": True,
            "restart_required": True,
            "note": "Saved. Interface and DHCP changes take effect after "
                    "'systemctl restart vpngw'.",
        }

    @app.get("/api/network/wan")
    def wan_state(x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Whether an uplink change is applied, and whether one is on a timer."""
        from .net import apply as netapply

        return {
            "stack": netapply.stack(),
            "rollback_pending": netapply.rollback_pending(),
            "rollback_seconds": netapply.rollback_seconds_left(),
            "live": netapply.verify(settings.wan.gateway),
        }

    @app.post("/api/network/wan/apply")
    def wan_apply(body: dict = Body(default={}),
                  x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Apply the saved uplink configuration to the interface itself.

        Separate from saving because this is the one change that can cut off
        the connection making it. A rollback is armed first, so a mistake
        undoes itself rather than requiring console access - which, on a VM in
        another building, may mean a trip.
        """
        from .net import apply as netapply

        minutes = int(body.get("rollback_minutes") or 5)
        if not 1 <= minutes <= 60:
            raise HTTPException(status_code=400,
                                detail="rollback_minutes must be 1-60")
        current = config.Settings.load()
        try:
            result = netapply.apply_wan(
                current.net.wan_iface, current.wan.mode, current.wan.address,
                current.wan.gateway, list(current.dns.bootstrap),
                rollback_minutes=minutes)
        except netapply.ApplyError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        db.log_event("warning", "network",
                     f"uplink applied; reverts in {minutes} min unless confirmed")
        return {"ok": True, **result}

    @app.post("/api/network/wan/confirm")
    def wan_confirm(x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Keep the change. Only reachable over the new address, which is the
        point: reaching this endpoint is the proof that it works."""
        from .net import apply as netapply

        if not netapply.rollback_pending():
            return {"ok": True, "note": "Nothing was waiting to be confirmed."}
        netapply.cancel_rollback()
        db.log_event("info", "network", "uplink change confirmed")
        return {"ok": True, "note": "Uplink change kept."}

    @app.post("/api/network/wan/revert")
    def wan_revert(x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Put the previous uplink back now instead of waiting for the timer."""
        from .net import apply as netapply

        if not netapply.rollback_pending():
            raise HTTPException(status_code=400,
                                detail="no uplink change is waiting to revert")
        netapply.rollback_now()
        db.log_event("warning", "network", "uplink change reverted by request")
        return {"ok": True, "note": "Previous uplink restored."}

    @app.get("/api/discovered")
    def discovered(x_vpngw_token: str | None = Header(default=None)) -> list[dict]:
        """Machines seen on a client interface that are not registered.

        They are being dropped right now - this endpoint exists so that fact
        is visible instead of looking like a machine that is simply switched
        off.
        """
        from .net import nft
        return service.reconciler.discovery.report(nft.counters())

    # -- providers ---------------------------------------------------------

    @app.get("/api/providers")
    def list_providers(x_vpngw_token: str | None = Header(default=None)) -> list[dict]:
        authorise(x_vpngw_token)
        from . import providers as registry
        from .providers import store

        have = set(store.configured())
        allowed = set(service.reconciler.enabled_providers())
        return [{
            "id": p.id,
            "name": p.name,
            "notes": p.notes,
            "supports": [k.value for k in p.supports],
            "device_limit": p.device_limit,
            "locations_need_auth": p.locations_need_auth,
            "credential_mode": p.credential_mode,
            "help_url": p.help_url,
            "configured": p.id in have,
            "api_allowed": p.id in allowed,
            "auth_fields": [
                {"key": f.key, "label": f.label, "secret": f.secret,
                 "help": f.help, "placeholder": f.placeholder}
                for f in p.auth_fields
            ],
        } for p in registry.all_providers()]

    @app.post("/api/providers/{provider_id}/enable")
    def enable_provider(provider_id: str,
                        x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Open the firewall to one provider's API.

        Separate from storing credentials because it has to happen *first* -
        under strict host egress the very first login request would otherwise
        be dropped by our own output chain, and the error would point at the
        provider rather than at us.
        """
        authorise(x_vpngw_token)
        from . import providers as registry

        registry.get(provider_id)          # rejects unknown ids
        service.reconciler.enable_provider(provider_id)
        return {"ok": True,
                "allowlist": service.reconciler._api_endpoints}

    @app.post("/api/providers/{provider_id}/disable")
    def disable_provider(provider_id: str,
                         x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        service.reconciler.disable_provider(provider_id)
        return {"ok": True}

    @app.post("/api/providers/{provider_id}/login")
    def provider_login(provider_id: str, body: dict = Body(...),
                       x_vpngw_token: str | None = Header(default=None)) -> dict:
        """Store the credentials the operator typed into the panel.

        The credential arrives from the browser, is verified against the
        provider once, and is written to /etc/vpngw/secrets/ mode 0600. It is
        never logged, never echoed back, and never returned by any endpoint.
        """
        authorise(x_vpngw_token)
        from . import providers as registry
        from .providers import ProviderError, store

        provider = registry.get(provider_id)
        creds = {f.key: str(body.get(f.key, "")).strip()
                 for f in provider.auth_fields}
        missing = [f.label for f in provider.auth_fields if not creds[f.key]]
        if missing:
            raise HTTPException(status_code=400,
                                detail=f"eksik alan: {', '.join(missing)}")

        # The API host must pass our own firewall before the first request.
        service.reconciler.enable_provider(provider_id)
        try:
            session = provider.login(creds)
            info = provider.account_info(session)
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        store.save_credentials(provider_id, creds)
        store._save_session(provider_id, session)
        db.log_event("info", "provider", f"{provider_id} account connected")
        return {"ok": True, "account": info}

    @app.get("/api/providers/{provider_id}/locations")
    def provider_locations(provider_id: str, country: str = "", city: str = "",
                           limit: int = 400,
                           x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        from . import providers as registry
        from .cli import _filter_country
        from .providers import ProviderError, store

        provider = registry.get(provider_id)

        # Fetching a catalogue means reaching the provider's API, which strict
        # host egress blocks until that host is on the allow-list. Opening it
        # here rather than only on login is what makes "browse before you sign
        # up" work at all - and it is an explicit request from the operator,
        # not something that happens on page load.
        service.reconciler.enable_provider(provider_id)

        try:
            session = (store.session_for(provider)
                       if provider.locations_need_auth else None)
            locations = provider.locations(session)
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        countries = sorted({
            (l.extra.get("country_code", ""), l.country) for l in locations
        }, key=lambda c: c[1])

        if country:
            locations = _filter_country(locations, country)
        if city:
            needle = city.lower()
            locations = [l for l in locations if needle in l.city.lower()]

        return {
            "total": len(locations),
            "countries": [{"code": c, "name": n} for c, n in countries],
            "locations": [{
                "id": l.id, "country": l.country, "city": l.city,
                "address": l.address, "owned": l.owned,
                "country_code": l.extra.get("country_code", ""),
                "daita": l.extra.get("daita", False),
            } for l in locations[:limit]],
        }

    @app.post("/api/providers/{provider_id}/tunnels")
    def provider_add_tunnel(provider_id: str, body: dict = Body(...),
                            x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        from . import providers as registry
        from .cli import _next_slug, _tunnel_from_remote
        from .providers import ProviderError, store

        provider = registry.get(provider_id)
        location_id = body.get("location_id", "")
        if not location_id:
            raise HTTPException(status_code=400, detail="location_id required")

        try:
            session = store.session_for(provider)
            match = [l for l in provider.locations(session) if l.id == location_id]
            if not match:
                raise HTTPException(status_code=404,
                                    detail=f"unknown server {location_id}")
            location = match[0]
            remote = provider.provision(session, location, TunnelKind.WIREGUARD)
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc))

        slug = (body.get("slug") or "").strip() or _next_slug(
            db, body.get("prefix") or location.extra.get("country_code")
            or provider.id[:2])
        tunnel = _tunnel_from_remote(
            db, slug, body.get("name") or location.label, remote)
        db.log_event("info", tunnel.slug,
                     f"provisioned from {provider.name} ({location.id})")
        touched()
        return {"slug": tunnel.slug, "iface": tunnel.iface,
                "name": tunnel.name, "endpoint": remote.endpoint}

    @app.get("/api/providers/{provider_id}/devices")
    def provider_devices(provider_id: str,
                         x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        from . import providers as registry
        from .providers import ProviderError, store

        provider = registry.get(provider_id)
        try:
            devices = provider.devices(store.session_for(provider))
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"devices": devices, "limit": provider.device_limit}

    @app.delete("/api/providers/{provider_id}/devices/{device_id}")
    def provider_device_rm(provider_id: str, device_id: str,
                           x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        from . import providers as registry
        from .providers import ProviderError, store

        provider = registry.get(provider_id)
        try:
            provider.remove_device(store.session_for(provider), device_id)
        except ProviderError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        return {"ok": True}

    @app.post("/api/tunnels/import-bundle")
    async def import_bundle(
        file: UploadFile, prefix: str = "vpn", dry_run: bool = False,
        limit: int = 0, disabled: bool = False,
        x_vpngw_token: str | None = Header(default=None),
    ) -> dict:
        """Import a whole archive of configs at once.

        Parsed entirely before anything is written: a half-imported bundle is
        worse than none, and the operator gets to see the plan first.
        """
        authorise(x_vpngw_token)
        import tempfile

        from . import bundle as bundle_mod
        from .importers import ImportError_

        suffix = Path(file.filename or "bundle").suffix or ".zip"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(await file.read())
            tmp_path = Path(tmp.name)
        try:
            try:
                candidates = bundle_mod.scan(tmp_path)
            except ImportError_ as exc:
                raise HTTPException(status_code=400, detail=str(exc))

            usable = [c for c in candidates if c.usable]
            skipped = [{"source": c.source, "problem": c.problem}
                       for c in candidates if not c.usable]
            if limit:
                usable = usable[:limit]

            bundle_mod.assign_slugs(
                usable, prefix, {t.slug for t in db.tunnels()})
            plan = [{"slug": c.slug, "name": c.display, "kind": c.kind.value,
                     "source": c.source} for c in usable]

            if dry_run:
                return {"dry_run": True, "plan": plan, "skipped": skipped}

            created = bundle_mod.commit(db, usable, enabled=not disabled)
            db.log_event("info", "bundle",
                         f"imported {len(created)} tunnel(s) from "
                         f"{file.filename}")
            touched()
            return {
                "dry_run": False, "plan": plan, "skipped": skipped,
                "imported": len(created),
                "without_endpoint": [t.slug for t in created if not t.endpoints],
            }
        finally:
            tmp_path.unlink(missing_ok=True)

    @app.post("/api/maintenance")
    def maintenance(body: dict = Body(...),
                    x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        service.reconciler.set_maintenance(body.get("minutes"))
        return {"active": service.reconciler.maintenance_active(),
                "remaining": service.reconciler.maintenance_remaining()}

    @app.post("/api/selftest")
    def selftest(body: dict = Body(...),
                 x_vpngw_token: str | None = Header(default=None)) -> dict:
        authorise(x_vpngw_token)
        from .leaktest import LeakTest

        kind = EgressKind(body.get("egress_kind", "tunnel"))
        slug = body.get("egress_slug", "")
        if not slug:
            raise HTTPException(status_code=400, detail="egress_slug required")
        report = LeakTest(service).run(
            kind, slug, disrupt=bool(body.get("disrupt"))
        )
        db.log_event(
            "info" if report.ok else "error", "selftest",
            "no leak found" if report.ok
            else f"{len(report.failed)} critical failure(s)",
        )
        return {
            "ok": report.ok,
            "report": report.render(),
            "checks": [
                {"id": c.id, "name": c.name, "passed": c.passed,
                 "detail": c.detail, "critical": c.critical}
                for c in report.checks
            ],
        }

    return app


def serve(service) -> None:
    import uvicorn

    app = create_app(service)
    settings = service.settings
    log.info("web UI on http://%s:%d", settings.api.bind, settings.api.port)
    uvicorn.run(
        app, host=settings.api.bind, port=settings.api.port,
        log_level="warning", access_log=False,
    )
