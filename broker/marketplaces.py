"""eBay Browse API and Tradera REST v4 search routes (moved from the
shopping shim). Search only: application credentials cannot bid, buy or
message, and no route here tries to.

Etiquette (per run, per marketplace): at least MARKETPLACE_MIN_INTERVAL_S
between calls, the call budget in config, and a 403/429 closes that
marketplace for the rest of the run — the remedy for a quota or policy
refusal is to stop, not to try again.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse

from broker import config, upstream
from broker.runs import RouteError

MAX_ITEMS = 50
DEFAULT_ITEMS = 20
MAX_URL_CHARS = 2000
_URL_RX = re.compile(r"^https://[^\s<>\"']+$")


def _url(value) -> str:
    """A plain https URL of sane length, or nothing (never repaired)."""
    s = value if isinstance(value, str) else ""
    if len(s) > MAX_URL_CHARS or not _URL_RX.match(s):
        return ""
    return s


def _int_arg(args: dict, key: str, default: int, lo: int, hi: int) -> int:
    v = args.get(key)
    if v is None:
        return default
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"{key} must be an integer")
    return max(lo, min(v, hi))


def _price_arg(args: dict, key: str):
    v = args.get(key)
    if v is None:
        return None
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
        raise ValueError(f"{key} must be a non-negative number")
    return v


def etiquette(ctx: upstream.Ctx, market: str, name: str) -> None:
    run = ctx.run
    with run.lock:
        reason = run.market_closed.get(market)
    if reason:
        raise RouteError(429, f"{name}: no further requests this run ({reason}). "
                              "Do not retry.", "market_closed")
    run.spend(market)
    with run.lock:
        last = run.market_last.get(market)
        wait = 0.0 if last is None else config.MARKETPLACE_MIN_INTERVAL_S - (ctx.clock() - last)
        run.market_last[market] = ctx.clock() + max(0.0, wait)
    if wait > 0:
        ctx.sleep(wait)


def close_on_refusal(ctx: upstream.Ctx, market: str, status: int) -> None:
    if status in (403, 429):
        with ctx.run.lock:
            ctx.run.market_closed[market] = f"API answered HTTP {status}"


# --- eBay ----------------------------------------------------------------------

EBAY_TOKEN_URL = "https://api.ebay.com/identity/v1/oauth2/token"
EBAY_SEARCH_URL = "https://api.ebay.com/buy/browse/v1/item_summary/search"
EBAY_SCOPE = "https://api.ebay.com/oauth/api_scope"

# eBay has no Swedish site. A buyer in Sweden searches an EU marketplace and
# asks for delivery to Sweden. Marketplace id -> web host for canonical links.
EBAY_MARKETPLACE_HOSTS = {
    "EBAY_DE": "www.ebay.de", "EBAY_GB": "www.ebay.co.uk",
    "EBAY_FR": "www.ebay.fr", "EBAY_IT": "www.ebay.it",
    "EBAY_ES": "www.ebay.es", "EBAY_NL": "www.ebay.nl",
    "EBAY_AT": "www.ebay.at", "EBAY_BE": "www.ebay.be",
    "EBAY_IE": "www.ebay.ie", "EBAY_PL": "www.ebay.pl",
    "EBAY_CH": "www.ebay.ch", "EBAY_US": "www.ebay.com",
}
EBAY_MARKETPLACES = set(EBAY_MARKETPLACE_HOSTS)
_EBAY_DOMAINS = {h.removeprefix("www.") for h in EBAY_MARKETPLACE_HOSTS.values()}
_EBAY_ID_RX = re.compile(r"^[0-9]{6,20}$")
_EBAY_ITM_PATH_RX = re.compile(r"^/itm/(?:[^/]+/)?([0-9]{6,20})/?$")
EBAY_DEFAULT_MARKETPLACE = "EBAY_DE"
EBAY_SORTS = {
    "best_match": "",
    "price_asc": "price",
    "price_desc": "-price",
    "newest": "newlyListed",
    "ending_soonest": "endingSoonest",
}
EBAY_CONDITIONS = {"NEW", "USED"}
EBAY_BUYING_OPTIONS = {"FIXED_PRICE", "AUCTION", "BEST_OFFER"}
_CURRENCY_RX = re.compile(r"^[A-Z]{3}$")
_COUNTRY_RX = re.compile(r"^[A-Z]{2}$")

EBAY_TOKEN = upstream.TokenCache()


def _enum_list(args: dict, key: str, allowed: set) -> list:
    v = args.get(key)
    if v is None:
        return []
    if isinstance(v, str):
        v = [v]
    if not isinstance(v, list):
        raise ValueError(f"{key} must be a list")
    out = []
    for item in v:
        s = str(item).strip().upper()
        if s not in allowed:
            raise ValueError(f"unknown {key} value {item!r}. Valid: {sorted(allowed)}")
        out.append(s)
    return out


def build_ebay_request(args: dict) -> tuple[str, dict]:
    """Validate tool arguments into (url, headers-without-auth).

    Every value that reaches the `filter` expression is either numeric or
    drawn from a fixed set, so an argument cannot add a filter clause.
    """
    q = args.get("query")
    if not isinstance(q, str) or not q.strip():
        raise ValueError("query is required")
    marketplace = str(args.get("marketplace") or EBAY_DEFAULT_MARKETPLACE).upper()
    if marketplace not in EBAY_MARKETPLACES:
        raise ValueError(
            f"unknown marketplace {marketplace!r}. Valid: {sorted(EBAY_MARKETPLACES)}"
        )
    deliver_to = str(args.get("deliver_to_country") or "SE").upper()
    if not _COUNTRY_RX.match(deliver_to):
        raise ValueError("deliver_to_country must be a 2-letter country code")
    sort_key = str(args.get("sort") or "best_match")
    if sort_key not in EBAY_SORTS:
        raise ValueError(f"unknown sort {sort_key!r}. Valid: {sorted(EBAY_SORTS)}")

    filters = [f"deliveryCountry:{deliver_to}"]
    pmin, pmax = _price_arg(args, "min_price"), _price_arg(args, "max_price")
    if pmin is not None or pmax is not None:
        currency = str(args.get("currency") or "").upper()
        if not _CURRENCY_RX.match(currency):
            raise ValueError(
                "currency (3-letter code, the marketplace's own currency) "
                "is required with min_price/max_price"
            )
        lo = "" if pmin is None else f"{pmin:g}"
        hi = "" if pmax is None else f"{pmax:g}"
        filters.append(f"price:[{lo}..{hi}]")
        filters.append(f"priceCurrency:{currency}")
    conditions = _enum_list(args, "conditions", EBAY_CONDITIONS)
    if conditions:
        filters.append("conditions:{" + "|".join(conditions) + "}")
    buying = _enum_list(args, "buying_options", EBAY_BUYING_OPTIONS)
    if buying:
        filters.append("buyingOptions:{" + "|".join(buying) + "}")
    item_country = args.get("item_location_country")
    if item_country is not None:
        ic = str(item_country).upper()
        if not _COUNTRY_RX.match(ic):
            raise ValueError("item_location_country must be a 2-letter country code")
        filters.append(f"itemLocationCountry:{ic}")

    params = {
        "q": q.strip()[:350],
        "limit": str(_int_arg(args, "limit", DEFAULT_ITEMS, 1, MAX_ITEMS)),
        "offset": str(_int_arg(args, "offset", 0, 0, 9_000)),
        "filter": ",".join(filters),
    }
    if EBAY_SORTS[sort_key]:
        params["sort"] = EBAY_SORTS[sort_key]
    headers = {
        "X-EBAY-C-MARKETPLACE-ID": marketplace,
        "X-EBAY-C-ENDUSERCTX": "contextualLocation="
        + urllib.parse.quote(f"country={deliver_to}", safe=""),
    }
    return EBAY_SEARCH_URL + "?" + urllib.parse.urlencode(params), headers


def _ebay_host(value) -> str:
    """The lowercased host of an https/http link on an eBay site, or ""."""
    if not isinstance(value, str):
        return ""
    try:
        parts = urllib.parse.urlsplit(value.strip())
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if (parts.scheme.lower() not in ("http", "https")
            or parts.netloc.lower() != host
            or not any(host == d or host.endswith("." + d) for d in _EBAY_DOMAINS)):
        return ""
    return host


def _ebay_item_id(it: dict) -> str:
    """The numeric listing id: legacyItemId, else from itemWebUrl, else itemId."""
    legacy = it.get("legacyItemId")
    if isinstance(legacy, int) and not isinstance(legacy, bool):
        legacy = str(legacy)
    if isinstance(legacy, str) and _EBAY_ID_RX.match(legacy.strip()):
        return legacy.strip()
    web = it.get("itemWebUrl")
    if _ebay_host(web):
        m = _EBAY_ITM_PATH_RX.match(urllib.parse.urlsplit(web.strip()).path)
        if m:
            return m.group(1)
    rest = it.get("itemId")  # RESTful id, "v1|<legacy id>|<variation id>"
    if isinstance(rest, str):
        bits = rest.split("|")
        if len(bits) == 3 and bits[0] == "v1" and _EBAY_ID_RX.match(bits[1]):
            return bits[1]
    return ""


def ebay_listing_url(it, marketplace: str = EBAY_DEFAULT_MARKETPLACE) -> str:
    """A short canonical listing link, https://<ebay host>/itm/<id>, or nothing.

    itemWebUrl carries tracking parameters that bloat the report; the listing
    id alone addresses the same item. With no usable id the returned link is
    kept as-is (subject to `_url`).
    """
    if not isinstance(it, dict):
        return ""
    item_id = _ebay_item_id(it)
    if not item_id:
        return _url(it.get("itemWebUrl"))
    host = (_ebay_host(it.get("itemWebUrl"))
            or EBAY_MARKETPLACE_HOSTS.get(str(marketplace).upper())
            or EBAY_MARKETPLACE_HOSTS[EBAY_DEFAULT_MARKETPLACE])
    return f"https://{host}/itm/{item_id}"


def _pick(d, *keys):
    return {k: d[k] for k in keys if isinstance(d, dict) and k in d}


def filter_ebay_item(it, marketplace: str) -> dict:
    """The fields the shim shows, in eBay's own shape, plus the canonical url."""
    if not isinstance(it, dict):
        return {}
    out = _pick(it, "title", "price", "currentBidPrice", "condition", "buyingOptions",
                "itemEndDate")
    opts = it.get("shippingOptions")
    if isinstance(opts, list) and opts and isinstance(opts[0], dict):
        out["shippingOptions"] = [_pick(opts[0], "shippingCost")]
    if isinstance(it.get("itemLocation"), dict):
        out["itemLocation"] = _pick(it["itemLocation"], "country")
    if isinstance(it.get("seller"), dict):
        out["seller"] = _pick(it["seller"], "feedbackPercentage", "feedbackScore")
    out["url"] = ebay_listing_url(it, marketplace)
    return out


def _ebay_mint(ctx: upstream.Ctx) -> tuple[str, float]:
    basic = base64.b64encode(
        f"{ctx.creds['ebay-client-id']}:{ctx.creds['ebay-client-secret']}".encode("utf-8")
    ).decode("ascii")
    status, data = upstream.call(
        ctx, "eBay auth", "POST", EBAY_TOKEN_URL,
        {"Authorization": f"Basic {basic}",
         "Content-Type": "application/x-www-form-urlencoded"},
        urllib.parse.urlencode({"grant_type": "client_credentials",
                                "scope": EBAY_SCOPE}).encode("ascii"),
        cap_s=config.OAUTH_MINT_TIMEOUT_S)
    if status >= 400:
        raise RouteError(502, f"eBay auth HTTP {status}", "upstream", upstream_status=status)
    tok = upstream.parse_json("eBay auth", data)
    access = tok.get("access_token") if isinstance(tok, dict) else None
    if not access or not isinstance(access, str):
        raise RouteError(502, "eBay auth: no access_token in response", "upstream")
    try:
        ttl = float(tok.get("expires_in") or 300)
    except (TypeError, ValueError):
        ttl = 300.0
    return access, ttl


def ebay_search(ctx: upstream.Ctx, args: dict) -> dict:
    try:
        url, headers = build_ebay_request(args)
    except ValueError as e:
        raise RouteError(400, str(e), "bad_request") from None
    if not ctx.creds.get("ebay-client-id") or not ctx.creds.get("ebay-client-secret"):
        raise RouteError(503, "eBay search is not configured (no eBay keyset on the "
                              "broker). Report eBay as not searched; do not substitute "
                              "a scraped eBay page.", "not_configured")
    etiquette(ctx, "ebay", "eBay")
    token = EBAY_TOKEN.get(lambda: _ebay_mint(ctx))
    status, data = upstream.call(ctx, "eBay", "GET", url,
                                 dict(headers, Authorization=f"Bearer {token}"))
    if status == 401:
        EBAY_TOKEN.clear()
    if status >= 400:
        close_on_refusal(ctx, "ebay", status)
        raise upstream.upstream_error("eBay", status, data)
    body = upstream.parse_json("eBay", data)
    marketplace = headers["X-EBAY-C-MARKETPLACE-ID"]
    items = body.get("itemSummaries") if isinstance(body, dict) else None
    out_items = [filter_ebay_item(it, marketplace) for it in items[:MAX_ITEMS]] \
        if isinstance(items, list) else []
    ctx.run.harvest([it["url"] for it in out_items if it.get("url")])
    total = body.get("total") if isinstance(body, dict) else None
    return {"marketplace": marketplace,
            "total": total if isinstance(total, (int, float, str)) else None,
            "itemSummaries": out_items}


# --- Tradera -------------------------------------------------------------------

TRADERA_SEARCH_URL = "https://api.tradera.com/v4/search"
TRADERA_WEB_ORIGIN = "https://www.tradera.com"
_TRADERA_LIST_KEY = "items"
_TRADERA_TOTAL_KEY = "totalNumberOfItems"
_TRADERA_FIELDS = ("id", "shortDescription", "buyItNowPrice", "maxBid", "nextBid",
                   "hasBids", "bidCount", "totalBids", "endDate", "isEnded", "sellerAlias")


def build_tradera_request(args: dict) -> str:
    q = args.get("query")
    if not isinstance(q, str) or not q.strip():
        raise ValueError("query is required")
    params = {
        "query": q.strip()[:200],
        "categoryId": str(_int_arg(args, "category_id", 0, 0, 10_000_000)),
        "pageNumber": str(_int_arg(args, "page", 0, 0, 1_000)),
    }
    return TRADERA_SEARCH_URL + "?" + urllib.parse.urlencode(params)


def tradera_listing_url(value) -> str:
    """The listing URL Tradera returned, as a usable https link, or nothing.

    Only links on tradera.com. An http link is upgraded to https and a
    site-relative path is joined to the www origin — the same address
    Tradera gave, not one invented from an id.
    """
    if not isinstance(value, str):
        return ""
    s = value.strip()
    if s.startswith("/") and not s.startswith("//"):
        s = TRADERA_WEB_ORIGIN + s
    try:
        parts = urllib.parse.urlsplit(s)
    except ValueError:
        return ""
    host = (parts.hostname or "").lower()
    if (parts.scheme.lower() not in ("http", "https")
            or not (host == "tradera.com" or host.endswith(".tradera.com"))
            or parts.netloc.lower() != host):
        return ""
    return _url(urllib.parse.urlunsplit(("https",) + tuple(parts)[1:]))


def filter_tradera_item(rec) -> dict:
    if not isinstance(rec, dict):
        return {}
    out = _pick(rec, *_TRADERA_FIELDS)
    if isinstance(rec.get("seller"), dict):
        out["seller"] = _pick(rec["seller"], "alias")
    link = tradera_listing_url(rec.get("itemUrl") or rec.get("itemLink"))
    if link:
        out["itemUrl"] = link
    return out


def tradera_search(ctx: upstream.Ctx, args: dict) -> dict:
    try:
        url = build_tradera_request(args)
    except ValueError as e:
        raise RouteError(400, str(e), "bad_request") from None
    if not ctx.creds.get("tradera-app-id") or not ctx.creds.get("tradera-app-key"):
        raise RouteError(503, "Tradera API search is not configured (no Tradera key on "
                              "the broker). Fall back to mcp__render__render_page on "
                              "https://www.tradera.com/search?q=<query>, which returns "
                              "listings.", "not_configured")
    etiquette(ctx, "tradera", "Tradera")
    status, data = upstream.call(ctx, "Tradera", "GET", url, {
        "X-App-Id": ctx.creds["tradera-app-id"],
        "X-App-Key": ctx.creds["tradera-app-key"]})
    if status >= 400:
        close_on_refusal(ctx, "tradera", status)
        raise upstream.upstream_error("Tradera", status, data)
    body = upstream.parse_json("Tradera", data)
    records = body.get(_TRADERA_LIST_KEY) if isinstance(body, dict) else None
    if not isinstance(records, list):
        # Unrecognised shape: shown raw (capped) so the first live call
        # reveals it, rather than hidden. Nothing in it is harvested.
        return {"raw": json.dumps(body, ensure_ascii=False)[:4000]}
    items = [filter_tradera_item(r) for r in records[:MAX_ITEMS]]
    ctx.run.harvest([it["itemUrl"] for it in items if it.get("itemUrl")])
    total = body.get(_TRADERA_TOTAL_KEY)
    return {_TRADERA_LIST_KEY: items,
            _TRADERA_TOTAL_KEY: total if isinstance(total, (int, float, str)) else None}
