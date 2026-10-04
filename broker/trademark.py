"""EUIPO Trademark Search route (moved from the trademark shim).

OAuth2 client-credentials, RSQL filter. Sandbox or production is this
module's constant (it was an env override in the shim that nothing set).

CAVEAT carried over: the record field names are from third-party clients
of the API (the gated OpenAPI spec was not readable at build time). The
normalizer tries several spellings and the shim falls back to a raw dump,
so the first live call reveals the real schema.
"""
from __future__ import annotations

import json
import urllib.parse

from broker import config, upstream
from broker.runs import RouteError

EUIPO_SANDBOX = True
AUTH_URL = ("https://auth-sandbox.euipo.europa.eu/oidc/accessToken" if EUIPO_SANDBOX
            else "https://auth.euipo.europa.eu/oidc/accessToken")
SEARCH_URL = ("https://api-sandbox.euipo.europa.eu/trademark-search/trademarks" if EUIPO_SANDBOX
              else "https://api.euipo.europa.eu/trademark-search/trademarks")

STATUS_ENUM = {
    "REGISTERED", "RECEIVED", "UNDER_EXAMINATION", "APPLICATION_PUBLISHED",
    "REGISTRATION_PENDING", "WITHDRAWN", "REFUSED", "OPPOSITION_PENDING",
    "APPEALED", "CANCELLATION_PENDING", "CANCELLED", "EXPIRED",
}
MAX_HITS = 50

EUIPO_TOKEN = upstream.TokenCache()


def rsql_quote(value: str) -> str:
    r"""Escape for an RSQL double-quoted string: `\` doubled, `"` escaped."""
    return value.replace("\\", "\\\\").replace('"', '\\"')


def build_filter(name: str, nice_classes: list[int] | None = None,
                 status: str | None = None, exact: bool = False) -> str:
    """The RSQL `filter=` expression. `;` = AND in RSQL."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError("name is required")
    term = rsql_quote(name.strip())
    if not exact:
        term = f"*{term}*"
    clauses = [f'wordMarkSpecification.verbalElement=="{term}"']
    if nice_classes:
        nums = []
        for c in nice_classes:
            n = int(c)
            if not (1 <= n <= 45):
                raise ValueError(f"nice class out of range: {n}")
            nums.append(str(n))
        if nums:
            clauses.append(f"niceClasses=in=({','.join(nums)})")
    if status:
        s = str(status).strip().upper()
        if s not in STATUS_ENUM:
            raise ValueError(f"unknown status '{status}'. Valid: {sorted(STATUS_ENUM)}")
        clauses.append(f"status=={s}")
    return ";".join(clauses)


def _first(d: dict, *keys: str):
    lower = {k.lower(): v for k, v in d.items()} if isinstance(d, dict) else {}
    for k in keys:
        v = lower.get(k.lower())
        if v not in (None, "", [], {}):
            return v
    return None


def _scalar(v):
    if isinstance(v, (str, int, float)) and not isinstance(v, bool):
        return v
    if isinstance(v, list):
        return ", ".join(str(x) for x in v if isinstance(x, (str, int, float)))
    return None if v is None else json.dumps(v, ensure_ascii=False)[:200]


def normalize_hit(rec) -> dict:
    """One raw EUIPO record -> a stable summary shape (values scalar)."""
    if not isinstance(rec, dict):
        return {}
    mark = _first(rec, "markName", "verbalElement", "wordMarkText")
    if mark is None:
        wms = rec.get("wordMarkSpecification") or {}
        if isinstance(wms, dict):
            mark = _first(wms, "verbalElement")
    hit = {
        "mark": mark,
        "applicationNumber": _first(rec, "applicationNumber", "stNumber", "ipRightNumber"),
        "owner": _first(rec, "applicantName", "applicant", "holderName", "ownerName"),
        "niceClasses": _first(rec, "niceClasses", "niceClass", "classDescriptionDetails"),
        "status": _first(rec, "status", "markCurrentStatusCode"),
        "filingDate": _first(rec, "filingDate", "applicationDate"),
        "url": _first(rec, "euipoUrl", "url"),
    }
    return {k: _scalar(v) for k, v in hit.items()}


def extract_records(body) -> list:
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("trademarks", "content", "results", "items", "data"):
            v = body.get(key)
            if isinstance(v, list):
                return v
    return []


def _mint(ctx: upstream.Ctx) -> tuple[str, float]:
    status, data = upstream.call(
        ctx, "EUIPO auth", "POST", AUTH_URL,
        {"Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({
            "client_id": ctx.creds["euipo-client-id"],
            "client_secret": ctx.creds["euipo-client-secret"],
            "grant_type": "client_credentials", "scope": "uid",
        }).encode("ascii"),
        impersonate=True, cap_s=config.OAUTH_MINT_TIMEOUT_S)
    if status >= 400:
        raise upstream.upstream_error("EUIPO auth", status, data)
    tok = upstream.parse_json("EUIPO auth", data)
    access = tok.get("access_token") if isinstance(tok, dict) else None
    if not access or not isinstance(access, str):
        raise RouteError(502, "EUIPO auth: no access_token in response", "upstream")
    try:
        ttl = float(tok.get("expires_in", 300))
    except (TypeError, ValueError):
        ttl = 300.0
    return access, ttl


def euipo_search(ctx: upstream.Ctx, args: dict) -> dict:
    try:
        size = args.get("size") or 25
        if isinstance(size, bool) or not isinstance(size, (int, float)):
            raise ValueError("size must be an integer")
        size = max(1, min(int(size), MAX_HITS))
        nice = args.get("nice_classes")
        if nice is not None and not isinstance(nice, list):
            raise ValueError("nice_classes must be a list of integers")
        filt = build_filter(args.get("name") or "", nice, args.get("status"),
                            bool(args.get("exact", False)))
    except (ValueError, TypeError) as e:
        raise RouteError(400, str(e), "bad_request") from None
    if not ctx.creds.get("euipo-client-id") or not ctx.creds.get("euipo-client-secret"):
        raise RouteError(503, "EUIPO not configured (no EUIPO client on the broker)",
                         "not_configured")
    ctx.run.spend("euipo")
    token = EUIPO_TOKEN.get(lambda: _mint(ctx))
    url = SEARCH_URL + "?" + urllib.parse.urlencode({"page": 0, "size": size, "filter": filt})
    status, data = upstream.call(ctx, "EUIPO search", "GET", url, {
        "Authorization": f"Bearer {token}",
        "X-IBM-Client-Id": ctx.creds["euipo-client-id"]}, impersonate=True)
    if status == 401:
        EUIPO_TOKEN.clear()
    if status >= 400:
        raise upstream.upstream_error("EUIPO search", status, data)
    body = upstream.parse_json("EUIPO search", data)
    records = extract_records(body)
    if not records:
        return {"total": 0, "hits": [], "raw": json.dumps(body, ensure_ascii=False)[:4000]}
    hits = []
    for rec in records[:MAX_HITS]:
        h = normalize_hit(rec)
        if not any(h.values()):
            h = {"raw": json.dumps(rec, ensure_ascii=False)[:1000]}
        hits.append(h)
    # Register records name no fetchable URLs we expect; any that do are
    # register-authored, so they may be opened.
    ctx.run.harvest([h["url"] for h in hits if isinstance(h.get("url"), str)])
    return {"total": len(records), "hits": hits}
