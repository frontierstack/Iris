"""End-to-end demo load via TestClient."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from tests.conftest import load_sample_case


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        load_sample_case(c)
        yield c


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json()["ok"] is True


def test_demo_loads_events(client):
    case = client.get("/api/case").json()
    assert case["eventCount"] > 0
    assert len(case["sources"]) == 7
    assert any(p["label"] == "Detections fired" and p["color"] == "bad" for p in case["posture"])


def test_events_query(client):
    r = client.get("/api/events", params={"q": "user:svc_deploy", "limit": 50})
    body = r.json()
    assert body["total"] > 0
    assert all("svc_deploy" in (e["user"] + e["raw"]) for e in body["rows"])


def test_events_sev_filter(client):
    r = client.get("/api/events", params={"sev": "critical", "limit": 100}).json()
    assert r["total"] >= 3
    assert all(e["sev"] == "critical" for e in r["rows"])


def test_timeline_has_clusters(client):
    tl = client.get("/api/timeline").json()
    assert tl["stats"]["clusters"] >= 3
    tags = {c["tag"] for c in tl["clusters"]}
    assert "FREQUENCY" in tags
    assert any(c["sev"] == "critical" for c in tl["clusters"])


def test_graph_v2_has_typed_nodes_and_relations(client):
    """The graph is typed: an IP and a user are different node types joined by named relations."""
    g = client.get("/api/graph").json()
    by_id = {n["id"]: n for n in g["nodes"]}
    assert "ip:45.83.140.22" in by_id and by_id["ip:45.83.140.22"]["type"] == "ip"
    assert "user:svc_deploy" in by_id and by_id["user:svc_deploy"]["type"] == "user"
    assert g["edges"], "there must be relations"
    rels = {e["relation"] for e in g["edges"]}
    assert "auth_from" in rels, "the credential-stuffing sample must yield user<-auth_from-ip"
    assert all(e["source"] in by_id and e["target"] in by_id for e in g["edges"]), "edges only join returned nodes"
    assert all(e["why"] for e in g["edges"]), "every edge explains itself"
    assert g["stats"]["nodes"] == len(g["nodes"])


def test_graph_v2_relations_cross_events(client):
    """The same entity in two log lines is ONE node — that is what lets a chain span events."""
    g = client.get("/api/graph?focus=ip:45.83.140.22&hops=1").json()
    ip = next(n for n in g["nodes"] if n["id"] == "ip:45.83.140.22")
    assert ip["count"] > 1, "the attacker IP appears in many events but is a single node"
    srcs = {s for f in ip["facts"] if f[0] == "Sources" for s in f[1].split(" · ")}
    assert len(srcs) >= 2, "it must be reachable from more than one log source"


def test_graph_v2_filters_and_focus(client):
    all_g = client.get("/api/graph").json()
    ips = client.get("/api/graph?types=ip").json()
    assert ips["nodes"] and all(n["type"] == "ip" for n in ips["nodes"])
    auth = client.get("/api/graph?relations=auth_from").json()
    assert auth["edges"] and all(e["relation"] == "auth_from" for e in auth["edges"])
    q = client.get("/api/graph?q=svc_deploy").json()
    assert any(n["id"] == "user:svc_deploy" for n in q["nodes"])
    assert len(q["nodes"]) < len(all_g["nodes"]), "the query bar narrows the graph"
    hood = client.get("/api/graph?focus=user:svc_deploy&hops=1").json()
    assert any(n["id"] == "user:svc_deploy" for n in hood["nodes"])
    assert len(hood["nodes"]) <= len(all_g["nodes"])


def test_graph_v2_node_detail_and_path(client):
    d = client.get("/api/graph/node/user:svc_deploy").json()
    assert d["type"] == "user" and d["neighbours"] and d["timeline"]
    assert client.get("/api/graph/node/user:nope").status_code == 404
    p = client.get("/api/graph/path?from=ip:45.83.140.22&to=user:svc_deploy&maxHops=3").json()
    assert p["found"] and p["path"][0]["id"] == "ip:45.83.140.22" and p["path"][-1]["id"] == "user:svc_deploy"
    assert len(p["edges"]) == len(p["path"]) - 1


def test_graph_links_persist(client):
    body = {"source": "ip:45.83.140.22", "target": "user:svc_deploy", "relation": "co_occurred",
            "why": "analyst: same actor per threat intel", "ai": True, "confidence": 0.8}
    e = client.post("/api/graph/links", json=body).json()
    assert e["ai"] is True and e["confidence"] == 0.8
    assert client.post("/api/graph/links", json=body).status_code == 409
    g = client.get("/api/graph").json()
    assert any(x["id"] == e["id"] and x["ai"] for x in g["edges"]), "accepted links come back on every GET"
    assert client.delete(f"/api/graph/links/{e['id']}").status_code == 200
    assert not any(x["id"] == e["id"] for x in client.get("/api/graph").json()["edges"])
    # An end extraction never found is now CREATED as an authored node on the case, which is what makes
    # an investigation graph drawable at all on a raw-first workspace (it used to 404 with "both ends of
    # a link must be nodes in the current graph"). It is marked `manual`, carries no event count, and is
    # drawn dashed — a conclusion, never evidence.
    made = client.post("/api/graph/links", json={**body, "target": "user:ghost"})
    assert made.status_code == 200
    node = next(n for n in client.get("/api/graph").json()["nodes"] if n["id"] == "user:ghost")
    assert node["manual"] is True and node["count"] == 0
    # ...but a node id that is not a node id at all is still refused
    assert client.post("/api/graph/links", json={**body, "target": "ghost"}).status_code == 400
    client.delete(f"/api/graph/links/{made.json()['id']}")


def test_entity_detail(client):
    e = client.get("/api/graph/svc_deploy").json()
    assert e["name"] == "svc_deploy"
    assert e["count"] > 0
    assert len(e["links"]) > 0


def test_event_detail_has_correlations(client):
    rows = client.get("/api/events", params={"sev": "critical", "limit": 5}).json()["rows"]
    eid = rows[0]["id"]
    d = client.get(f"/api/events/{eid}").json()
    assert d["id"] == eid
    assert "correlations" in d
    assert d.get("baseline")


def test_report_severity_critical(client):
    rep = client.get("/api/report").json()
    assert rep["severity"] == "critical"
    assert len(rep["findings"]) >= 3
    assert any(i["kind"] == "aws-access-key" for i in rep["iocs"])


def test_report_exports(client):
    for fmt in ("md", "json", "stix"):
        r = client.get("/api/report/export", params={"format": fmt})
        assert r.status_code == 200
        assert len(r.content) > 0
    stix = client.get("/api/report/export", params={"format": "stix"}).json()
    assert stix["type"] == "bundle"
    assert any(o["type"] == "indicator" for o in stix["objects"])


def test_case_set_add_remove(client):
    cs = client.get("/api/case-set").json()
    assert len(cs["entries"]) > 0
    assert len(cs["events"]) == len(cs["entries"])
    eid = cs["entries"][0]["eventId"]
    # events carry their membership so lists can render it without a second request
    assert all(e["inCase"] for e in cs["events"])

    assert client.delete(f"/api/case-set/{eid}").status_code == 200
    assert eid not in {e["eventId"] for e in client.get("/api/case-set").json()["entries"]}

    # re-add with labels + a note; add is an upsert
    entry = client.post(f"/api/case-set/{eid}", json={"labels": ["exfil", " exfil ", ""], "note": "30x daily median"}).json()
    assert entry["labels"] == ["exfil"]  # trimmed, blanks dropped, de-duplicated
    assert entry["note"] == "30x daily median"
    assert client.get("/api/case-set").json()["labels"] == ["exfil"]

    patched = client.patch(f"/api/case-set/{eid}", json={"labels": ["exfil", "initial-access"]}).json()
    assert patched["labels"] == ["exfil", "initial-access"]
    assert patched["note"] == "30x daily median"  # untouched fields survive a PATCH


def test_case_set_scopes_analysis(client):
    """scope=case must re-run correlation over the subset, not filter the full-corpus result."""
    all_tl = client.get("/api/timeline").json()
    case_tl = client.get("/api/timeline?scope=case").json()
    assert len(case_tl["clusters"]) <= len(all_tl["clusters"])

    n_case = len(client.get("/api/case-set").json()["entries"])
    scoped = client.get("/api/events?scope=case&limit=500").json()
    assert scoped["total"] == n_case

    g = client.get("/api/graph?scope=case").json()
    assert len(g["nodes"]) <= len(client.get("/api/graph").json()["nodes"])

    rep = client.get("/api/report?scope=case").json()
    assert len(rep["caseSet"]) == n_case


def test_case_detail(client):
    cid = client.get("/api/case").json()["id"]
    d = client.get(f"/api/cases/{cid}").json()
    assert d["active"] is True
    assert d["caseSet"] > 0
    assert d["snapshot"]["events"] > 0
    assert d["snapshot"]["range"] is not None
    assert len(d["sourceList"]) > 0


def test_case_notes_crud(client):
    """Notes are a timestamped feed, not one blob — post / edit / delete, with refs to events."""
    cid = client.get("/api/case").json()["id"]
    eid = client.get("/api/case-set").json()["entries"][0]["eventId"]

    n1 = client.post(f"/api/cases/{cid}/notes", json={"text": "opened case"}).json()
    assert n1["createdAt"] and n1["updatedAt"] == ""  # unedited notes carry no updatedAt
    n2 = client.post(f"/api/cases/{cid}/notes", json={
        "text": "pivot confirmed", "refs": [{"kind": "event", "value": eid, "label": "bulk export"}]}).json()
    assert n2["refs"][0]["value"] == eid
    assert n1["id"] != n2["id"]

    feed = client.get(f"/api/cases/{cid}/notes").json()
    assert [n["id"] for n in feed] == [n1["id"], n2["id"]]  # oldest first, like a chat log

    edited = client.patch(f"/api/cases/{cid}/notes/{n1['id']}", json={"text": "opened case (revised)"}).json()
    assert edited["text"] == "opened case (revised)"
    assert edited["updatedAt"]                      # now flagged as edited
    assert edited["createdAt"] == n1["createdAt"]   # creation time is preserved

    assert client.delete(f"/api/cases/{cid}/notes/{n1['id']}").status_code == 200
    assert [n["id"] for n in client.get(f"/api/cases/{cid}/notes").json()] == [n2["id"]]
    assert client.delete(f"/api/cases/{cid}/notes/nope").status_code == 404
    # an empty note is rejected
    assert client.post(f"/api/cases/{cid}/notes", json={"text": "   "}).status_code == 400
    # notes reach the report
    assert len(client.get("/api/report").json()["notes"]) == 1


def test_iocs_link_back_to_logs(client):
    r = client.get("/api/iocs").json()
    assert r["total"] == len(r["iocs"])
    if not r["iocs"]:
        return
    top = r["iocs"][0]
    assert top["count"] >= 1
    assert top["files"], "an IOC must record which log file it came from"
    assert top["hits"] and len(top["hits"]) <= 5
    hit = top["hits"][0]
    # every hit resolves to a real event, so the UI can link straight to it
    assert client.get(f"/api/events/{hit['eventId']}").status_code == 200
    assert hit["file"] == top["files"][0] or hit["file"] in top["files"]
    # counts never exceed the full corpus when scoped down
    scoped = client.get("/api/iocs?scope=case").json()
    assert scoped["total"] <= r["total"]


def test_settings_masks_key(client):
    client.put("/api/settings", json={"ai": {"provider": "openai", "apiKey": "sk-secret-1234567890"}})
    s = client.get("/api/settings").json()
    assert s["ai"]["apiKey"].endswith("7890")
    assert "secret" not in s["ai"]["apiKey"]
    # masked value on PUT must not overwrite the stored key
    client.put("/api/settings", json={"ai": {"apiKey": s["ai"]["apiKey"]}})
    s2 = client.get("/api/settings").json()
    assert s2["ai"]["apiKey"].endswith("7890")


def test_compute_status(client):
    c = client.get("/api/compute").json()
    assert c["active"] in ("cuda", "cpu")
    assert c["backend"] in ("cupy", "torch", "numpy")


def test_ai_analyze_offline_stream(client):
    client.put("/api/settings", json={"ai": {"provider": "none"}})
    with client.stream("POST", "/api/ai/analyze", json={"scope": "case"}) as r:
        assert r.status_code == 200
        body = "".join(chunk for chunk in r.iter_text())
    assert '"type":"done"' in body or '"type": "done"' in body


def test_source_mapping_reparse(client):
    case = client.get("/api/case").json()
    fw = next(s for s in case["sources"] if "fw-edge" in s["file"])
    src = client.post(f"/api/sources/{fw['id']}/mapping",
                      json={"fields": ["timestamp", "host", "action", "src", "dst", "proto", "bytes"], "delimiter": "|"}).json()
    assert src["state"] == "READY"
    assert src["events"] > 0


def test_manual_iocs_are_located_in_the_logs(client):
    """Adding an indicator by hand should immediately show where it appears — that is the point."""
    # an extracted entity is guaranteed to appear in the event text
    rows = client.get("/api/events?limit=200").json()["rows"]
    needle = next(e["entities"][0] for e in rows if e["entities"])

    created = client.post("/api/iocs", json={"kind": "custom", "value": needle, "note": "from threat intel"}).json()
    assert created["manual"] is True
    assert created["note"] == "from threat intel"
    assert created["count"] >= 1, "a manual IOC must be looked up across the events"
    assert created["files"], "and must report which log files it appears in"
    assert created["hits"] and client.get(f"/api/events/{created['hits'][0]['eventId']}").status_code == 200

    listed = client.get("/api/iocs").json()
    assert any(i["id"] == created["id"] for i in listed["iocs"])

    # duplicates are rejected rather than silently doubling up
    assert client.post("/api/iocs", json={"kind": "custom", "value": needle}).status_code == 409

    assert client.patch(f"/api/iocs/{created['id']}", json={"kind": "custom", "value": needle, "note": "revised"}).json()["note"] == "revised"
    assert client.delete(f"/api/iocs/{created['id']}").status_code == 200
    assert not any(i["id"] == created["id"] and i["manual"] for i in client.get("/api/iocs").json()["iocs"])
    # an extracted indicator cannot be deleted — it is derived from events, not stored
    assert client.delete("/api/iocs/ipv4:1.2.3.4").status_code == 404


def test_manual_ioc_survives_a_value_with_no_hits(client):
    created = client.post("/api/iocs", json={"kind": "ipv4", "value": "203.0.113.250"}).json()
    assert created["count"] == 0 and created["files"] == [] and created["hits"] == []
    assert any(i["value"] == "203.0.113.250" for i in client.get("/api/iocs").json()["iocs"])
    client.delete(f"/api/iocs/{created['id']}")


def test_builtin_regex_is_visible_and_editable(client):
    """A built-in that matches with a regex must expose it AND let the analyst re-tune it."""
    rules = {r["id"]: r for r in client.get("/api/rules").json()}
    ua = rules["SIGMA-WEB-0050"]
    assert ua["patterns"], "the scanner-UA rule matches with a regex, so it must be exposed"
    shipped = ua["patterns"][0]["pattern"]
    assert "sqlmap" in shipped and ua["patterns"][0]["field"] == "user_agent"

    body = {"name": ua["name"], "description": ua["description"], "sev": ua["sev"], "enabled": True,
            "kind": "builtin", "builtin": True, "tags": ua["tags"], "createdBy": "system"}

    # an invalid regex is rejected before it can break the detection pass
    assert client.put("/api/rules/SIGMA-WEB-0050", json={**body, "pattern": "([unclosed"}).status_code == 400

    edited = client.put("/api/rules/SIGMA-WEB-0050", json={**body, "pattern": "sqlmap|myscanner"}).json()
    assert edited["patterns"][0]["pattern"] == "sqlmap|myscanner"
    assert edited["overridden"] is True

    # restore puts the shipped regex back
    restored = client.post("/api/rules/SIGMA-WEB-0050/restore").json()
    assert restored["patterns"][0]["pattern"] == shipped
    assert restored["overridden"] is False


def test_builtin_regex_override_changes_what_matches(client):
    """The edited regex must actually drive detection, not just display."""
    before = next(r for r in client.get("/api/rules").json() if r["id"] == "SIGMA-LNX-0050")
    body = {"name": before["name"], "description": before["description"], "sev": before["sev"], "enabled": True,
            "kind": "builtin", "builtin": True, "tags": before["tags"], "createdBy": "system"}
    # a pattern that cannot match anything must drive the hit count to zero
    client.put("/api/rules/SIGMA-LNX-0050", json={**body, "pattern": "zzz-never-matches-anything-zzz"})
    after = next(r for r in client.get("/api/rules").json() if r["id"] == "SIGMA-LNX-0050")
    assert after["hits"] == 0, "an overridden regex must be what the engine actually matches with"
    client.post("/api/rules/SIGMA-LNX-0050/restore")


def test_add_a_whole_log_to_the_case(client):
    """The + on a Sources row adds every event of that file, labelled with the file name."""
    src = client.get("/api/case").json()["sources"][0]
    r = client.post(f"/api/case-set/source/{src['id']}").json()
    assert r["added"] > 0 and r["file"] == src["file"]
    assert r["total"] == src["events"]

    entries = client.get("/api/case-set").json()["entries"]
    from_src = [e for e in entries if src["file"] in e["labels"]]
    assert len(from_src) == r["added"], "every added event carries the file name as its label"

    # and it can be taken back out in one go
    back = client.delete(f"/api/case-set/source/{src['id']}").json()
    assert back["removed"] == r["added"]
    assert not [e for e in client.get("/api/case-set").json()["entries"] if src["file"] in e["labels"]]
    assert client.post("/api/case-set/source/nope").status_code == 404
