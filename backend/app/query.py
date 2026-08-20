r"""Search query parser: free text, field:value, AND / OR / NOT, quoted phrases.

Grammar (precedence low→high):  or := and ('OR' and)* ; and := unary (('AND')? unary)* ; unary := 'NOT' unary | '-' unary | atom
atom := '(' or ')' | field ':' value | value ;  value := quoted | word
Special fields: sev, source, host, user, file, id, msg — everything else matches Event.fields[name] (case-insensitive).

Escaping: a backslash makes the next character literal, so `\:` searches for a colon rather than splitting
field:value (`10.0.0.9\:3001`), and `\ ` keeps a space inside one term. Quoting does the same for a whole
phrase ("10.0.0.9:3001"). A doubled backslash is a literal backslash.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable, Optional

from .models import Event

# A bare word may contain backslash escapes, so `\:` `\(` `\)` and `\ ` stay part of the same token
# instead of splitting the query or being read as the field:value separator.
_TOKEN = re.compile(r'\s*(?:(\()|(\))|([\w.\-]+:"(?:[^"\\]|\\.)*")|("(?:[^"\\]|\\.)*")|((?:\\.|[^\s()])+))')

Predicate = Callable[[Event], bool]

FIELD_ALIASES = {
    "severity": "sev", "level": "sev", "src": "source", "parser": "source", "hostname": "host", "username": "user",
    "message": "msg", "text": "msg", "raw": "raw", "ip": "_ip", "entity": "_entity",
}
_SEV_SET = {"critical", "high", "medium", "low", "info"}


@dataclass
class _Tok:
    kind: str  # 'lp' | 'rp' | 'term'
    text: str
    quoted: bool = False


def unescape(s: str) -> str:
    r"""Drop one level of backslash escaping: `\:` → `:`, `\\` → `\`, `\ ` → a space."""
    if "\\" not in s:
        return s
    out: list[str] = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i + 1])
            i += 2
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def split_field(text: str) -> Optional[tuple[str, str]]:
    r"""Split `field:value` on the first UNESCAPED colon, or None when the term is plain text.

    `10.0.0.9\:3001` therefore searches for the literal string instead of looking for a field named
    "10.0.0.9". A leading colon is not a field either — `:foo` is free text.
    """
    i = 0
    while i < len(text):
        c = text[i]
        if c == "\\":
            i += 2  # skip the escaped character, whatever it is
            continue
        if c == ":":
            return None if i == 0 else (text[:i], text[i + 1:])
        i += 1
    return None


def _tokenize(q: str) -> list[_Tok]:
    toks: list[_Tok] = []
    pos = 0
    while pos < len(q):
        m = _TOKEN.match(q, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        lp, rp, field_q, quoted, word = m.groups()
        if lp:
            toks.append(_Tok("lp", "("))
        elif rp:
            toks.append(_Tok("rp", ")"))
        elif field_q:
            field, _, val = field_q.partition(":")
            toks.append(_Tok("term", f"{field}:{val[1:-1]}".replace('\\"', '"')))
        elif quoted:
            toks.append(_Tok("term", quoted[1:-1].replace('\\"', '"'), True))
        elif word:
            toks.append(_Tok("term", word))
    return toks


# ----------------------------------------------------------------------------- AST
# The parser builds a small AST so the same query can be (a) compiled to a Python predicate for exact
# evaluation and (b) lowered to vectorized boolean masks over the packed search index (search.py) that
# runs on cupy (CUDA) or numpy.
@dataclass
class Node:
    kind: str                       # 'and' | 'or' | 'not' | 'atom' | 'true'
    children: list["Node"]
    tok: Optional[_Tok] = None      # for 'atom'


class _Parser:
    def __init__(self, toks: list[_Tok]) -> None:
        self.toks = toks
        self.i = 0

    def peek(self) -> Optional[_Tok]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def next(self) -> _Tok:
        t = self.toks[self.i]
        self.i += 1
        return t

    def parse(self) -> Node:
        if not self.toks:
            return Node("true", [])
        return self.parse_or()

    def parse_or(self) -> Node:
        parts = [self.parse_and()]
        while True:
            t = self.peek()
            if t and t.kind == "term" and not t.quoted and t.text.upper() == "OR":
                self.next()
                parts.append(self.parse_and())
            else:
                break
        return parts[0] if len(parts) == 1 else Node("or", parts)

    def parse_and(self) -> Node:
        parts: list[Node] = []
        while True:
            t = self.peek()
            if t is None or t.kind == "rp":
                break
            if t.kind == "term" and not t.quoted and t.text.upper() == "OR":
                break
            if t.kind == "term" and not t.quoted and t.text.upper() == "AND":
                self.next()
                continue
            parts.append(self.parse_unary())
        if not parts:
            return Node("true", [])
        return parts[0] if len(parts) == 1 else Node("and", parts)

    def parse_unary(self) -> Node:
        t = self.peek()
        assert t is not None
        if t.kind == "term" and not t.quoted and (t.text.upper() == "NOT" or (t.text.startswith("-") and len(t.text) > 1)):
            if t.text.upper() == "NOT":
                self.next()
                if self.peek() is None:
                    return Node("true", [])
                inner = self.parse_unary()
            else:
                self.next()
                inner = Node("atom", [], _Tok("term", t.text[1:]))
            return Node("not", [inner])
        return self.parse_atom()

    def parse_atom(self) -> Node:
        t = self.next()
        if t.kind == "lp":
            inner = self.parse_or()
            if self.peek() and self.peek().kind == "rp":  # type: ignore[union-attr]
                self.next()
            return inner
        if t.kind == "rp":
            return Node("true", [])
        return Node("atom", [], t)


def parse_query(q: str) -> Node:
    q = (q or "").strip()
    if not q:
        return Node("true", [])
    return _Parser(_tokenize(q)).parse()


def node_pred(n: Node) -> Predicate:
    if n.kind == "true":
        return lambda e: True
    if n.kind == "atom":
        assert n.tok is not None
        return _atom_pred(n.tok)
    if n.kind == "not":
        inner = node_pred(n.children[0])
        return lambda e: not inner(e)
    preds = [node_pred(c) for c in n.children]
    if n.kind == "and":
        return lambda e: all(p(e) for p in preds)
    return lambda e: any(p(e) for p in preds)


def _atom_pred(t: _Tok) -> Predicate:
    text = t.text
    if not t.quoted:
        parts = split_field(text)
        if parts:
            field, value = parts
            field = FIELD_ALIASES.get(unescape(field).lower(), unescape(field))
            return _field_pred(field, unescape(value).strip('"'))
    # quoted text was already unescaped by the tokenizer; only bare words still carry escapes
    needle = (text if t.quoted else unescape(text)).lower()

    def free(e: Event) -> bool:
        # NOTE: keep in sync with search._doc() — the vectorized index treats free-text as exact over these parts
        if needle in e.msg.lower() or needle in e.raw.lower():
            return True
        if needle in e.host.lower() or needle in e.user.lower() or needle in e.source.lower():
            return True
        if needle in e.file.lower() or needle in e.id.lower():
            return True
        for x in e.entities:
            if needle in x.lower():
                return True
        for d in e.detections:
            if needle in d.name.lower() or needle in d.id.lower():
                return True
        for k, v in e.fields.items():
            if needle in k.lower() or needle in v.lower():
                return True
        return False

    return free


def _field_pred(field: str, value: str) -> Predicate:
    v = value.lower()
    wildcard = "*" in v
    rx = re.compile("^" + ".*".join(re.escape(p) for p in v.split("*")) + "$", re.I) if wildcard else None

    def match(s: str) -> bool:
        s = s.lower()
        if rx:
            return bool(rx.match(s))
        return s == v or (len(v) >= 3 and v in s and field not in ("sev", "id"))

    f = field.lower()
    if f == "sev":
        wanted = {x for x in v.split(",") if x in _SEV_SET}
        return lambda e: e.sev in wanted if wanted else False
    if f == "source":
        return lambda e: match(e.source) or match(e.file) or match(e.sourceId)
    if f == "host":
        return lambda e: match(e.host) or match(e.fields.get("host", "")) or match(e.fields.get("Computer", ""))
    if f == "user":
        return lambda e: match(e.user) or any(match(e.fields.get(k, "")) for k in ("user", "user.name", "TargetUserName", "SubjectUserName", "actor", "userIdentity.userName"))
    if f == "file":
        return lambda e: match(e.file)
    if f == "id":
        return lambda e: e.id.lower() == v
    if f == "msg":
        return lambda e: v in e.msg.lower()
    if f == "raw":
        return lambda e: v in e.raw.lower()
    if f == "_ip":
        return lambda e: any(match(x) for x in e.entities) or any(match(e.fields.get(k, "")) for k in ("src_ip", "src", "dst", "sourceIPAddress", "IpAddress"))
    if f == "_entity":
        # EXACT, unlike every other field. An entity is an extracted token, and the graph's notion of
        # "this node's events" is exactly "events whose extracted entities contain this value" — with the
        # usual substring fallback, `entity:10.0.0.1` also drags in 10.0.0.100 and the set stops being
        # the node's. A wildcard still works (`entity:10.0.0.*`), and free text is still there for
        # anyone who wants a loose match.
        if rx is not None:
            return lambda e: any(bool(rx.match(x)) for x in e.entities)
        return lambda e: any(x.lower() == v for x in e.entities)
    if f in ("detection", "rule", "sigma"):
        return lambda e: any(match(d.id) or match(d.name) for d in e.detections)
    if f == "ts":
        return lambda e: e.ts.lower().startswith(v)

    def fld(e: Event) -> bool:
        val = e.fields.get(field)
        if val is None:
            for k, x in e.fields.items():
                if k.lower() == f:
                    val = x
                    break
        if val is None:
            return False
        return match(val)

    return fld


def compile_query(q: str) -> Predicate:
    """Compile a query string into a predicate over Event. Empty query matches everything."""
    return node_pred(parse_query(q))


def atom_parts(t: _Tok) -> tuple[Optional[str], str]:
    """(field or None, value) for an atom token — shared with search.py's mask lowering.

    MUST stay in step with _atom_pred: the vector path uses this to build masks and the predicate
    confirms them, so a disagreement about where `field:value` splits would drop real matches.
    """
    text = t.text
    if not t.quoted:
        parts = split_field(text)
        if parts:
            field, value = parts
            f = unescape(field).lower()
            return FIELD_ALIASES.get(f, f).lower(), unescape(value).strip('"').lower()
    return None, (text if t.quoted else unescape(text)).lower()
