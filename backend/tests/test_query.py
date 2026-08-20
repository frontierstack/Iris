"""Search query parser tests."""
from __future__ import annotations

from app.models import Detection, Event
from app.query import compile_query


def mk(**kw) -> Event:
    base = dict(id="e1", ts="2026-08-11T03:14:47Z", source="nginx.access", sourceId="s1", file="a.log",
               host="edge-lb-01", user="svc_deploy", msg="POST /api/v2/login 200", sev="critical",
               raw="45.83.140.22 svc_deploy 200", fields={"src_ip": "45.83.140.22", "http.status": "200"},
               entities=["45.83.140.22", "svc_deploy"], detections=[Detection(name="x", id="SIGMA-AUTH-0111", level="critical")])
    base.update(kw)
    return Event(**base)


E = mk()
OTHER = mk(id="e2", user="alice", sev="info", entities=["1.2.3.4"], fields={"http.status": "404"}, detections=[])


def test_free_text():
    assert compile_query("login")(E)
    assert not compile_query("logout")(E)


def test_field_value():
    assert compile_query("user:svc_deploy")(E)
    assert not compile_query("user:alice")(E)
    assert compile_query("src_ip:45.83.140.22")(E)


def test_and_or_not():
    assert compile_query("user:svc_deploy AND src_ip:45.83.140.22")(E)
    assert not compile_query("user:svc_deploy AND user:alice")(E)
    assert compile_query("user:alice OR user:svc_deploy")(E)
    assert compile_query("NOT user:alice")(E)
    assert not compile_query("NOT user:svc_deploy")(E)
    assert compile_query("-user:alice")(E)


def test_sev_filter():
    assert compile_query("sev:critical")(E)
    assert not compile_query("sev:info")(E)
    assert compile_query("sev:critical,high")(E)


def test_quoted_phrase():
    assert compile_query('"/api/v2/login"')(E)
    assert compile_query('msg:"POST /api/v2/login"')(E)


def test_implicit_and_and_grouping():
    assert compile_query("login 200")(E)
    assert compile_query("(user:alice OR user:svc_deploy) AND sev:critical")(E)
    assert not compile_query("(user:alice OR user:bob) AND sev:critical")(E)


def test_empty_matches_all():
    assert compile_query("")(E)
    assert compile_query("   ")(OTHER)


def test_detection_field():
    assert compile_query("detection:SIGMA-AUTH-0111")(E)
    assert not compile_query("detection:SIGMA-AUTH-0111")(OTHER)


# ---------------------------------------------------------------- escaping
def test_escaped_colon_is_literal_text():
    r"""`\:` searches for a colon instead of splitting field:value.

    Without it, `10.0.0.9:3001` looks for a FIELD named "10.0.0.9" and quietly returns nothing.
    """
    e = mk(msg="connect to 10.0.0.9:3001 refused", raw="connect to 10.0.0.9:3001 refused")
    assert compile_query(r"10.0.0.9\:3001")(e)
    assert compile_query('"10.0.0.9:3001"')(e)      # quoting remains an alternative
    assert not compile_query("10.0.0.9:3001")(e)    # unescaped is still a field lookup


def test_escaped_space_keeps_one_term():
    e = mk(msg="connect to host", raw="connect to host")
    assert compile_query(r"connect\ to")(e)
    assert not compile_query(r"connect\ nope")(e)


def test_escape_does_not_break_real_fields():
    e = mk()
    assert compile_query("user:svc_deploy")(e)
    assert compile_query("src_ip:45.83.140.22")(e)
    assert not compile_query("user:someone_else")(e)


def test_escaped_operator_is_a_search_term():
    r"""`\AND` looks for the word AND rather than combining two terms."""
    e = mk(msg="policy AND rule matched", raw="policy AND rule matched")
    assert compile_query(r"\AND")(e)


def test_predicate_and_vector_lowering_agree_on_escapes():
    """search.py builds masks from atom_parts and confirms with node_pred — they must split identically."""
    from app.query import atom_parts, parse_query
    for q, expected in [(r"10.0.0.9\:3001", (None, "10.0.0.9:3001")),
                        ("user:svc_deploy", ("user", "svc_deploy")),
                        (r"connect\ to", (None, "connect to"))]:
        node = parse_query(q)
        assert node.tok is not None
        assert atom_parts(node.tok) == expected
