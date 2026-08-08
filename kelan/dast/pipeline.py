
from __future__ import annotations

import asyncio
import random
import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import httpx
import structlog

from kelan.dast.bypass import build_probes, RATELIMIT_HEADERS
from kelan.dast.crawler import Crawler, DEFAULT_HEADERS
from kelan.dast.heuristics import (
    reflected, sql_error_hint, traversal_hit, ssti_hit, grade_idor,
    grade_ratelimit_burst,
)
from kelan.dast.llm import CATEGORY_CWE, enrich_finding
from kelan.dast.report import Finding, Report, SEV_ORDER

log = structlog.get_logger()

REQUIRED_HEADERS = [
    "content-security-policy", "x-frame-options", "x-content-type-options",
    "referrer-policy", "permissions-policy", "strict-transport-security",
]
API_RE = re.compile(r"/(api|v\d+|rest|graphql|service)/", re.I)


@dataclass
class ScanOptions:
    target: str
    model: str = "qwen2.5-coder:latest"
    endpoint: str = "http://127.0.0.1:11434"
    crawl: bool = False
    max_pages: int = 15
    max_depth: int = 3
    delay: float = 0.5
    bypass: bool = False
    vectors: tuple = ("xss", "sqli", "cmdi", "traversal", "ssti", "ratelimit")
    timeout: float = 15.0
    concurrency: int = 2
    fuzz_tokens: bool = False
    external: bool = False
    use_llm: bool = True


def _inject_query(url: str, param: str, value: str) -> str:
    u = urlparse(url)
    q = dict(parse_qsl(u.query, keep_blank_values=True))
    q[param] = value
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), ""))


def _build_targets(pages, fuzz_tokens: bool = False):
    targets, seen = [], set()
    for page in pages:
        for pname in page.params:
            key = (page.url, "GET", pname, None)
            if key not in seen:
                seen.add(key)
                targets.append(key)
        for form in page.forms:
            for f in form.fields:
                if (f.is_secret and not fuzz_tokens) or not f.name:
                    continue
                key = (form.action, form.method.upper(), f.name, form)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)
    return targets


def _evaluate(cat, resp, payload, variant, url, method, param, marker,
              strong_seen: set) -> Optional[Finding]:
    body = resp.text or ""
    st = resp.status_code
    key = (url, param, cat)
    if cat == "xss":
        if reflected(body, payload):
            strong_seen.add(key)
            return Finding(url=url, method=method, param=param, category="xss",
                title="Reflected Cross-Site Scripting (XSS)",
                evidence=f"payload reflected unencoded in response (HTTP {st}): {payload[:120]}",
                payload=payload, variant=variant, confidence="strong")
        if st in (400, 500) and key not in strong_seen:
            return Finding(url=url, method=method, param=param, category="xss",
                title="Input rejected by server-side validation (WAF / ASP.NET ValidateRequest)",
                evidence=f"HTTP {st} on probe; raw payload blocked — encoding variants may bypass (tried: {variant})",
                payload=payload, variant=variant, confidence="weak",
                remediation="Confirm whether encoding variants bypass the filter; if none do, the control is working.")
        return None
    if cat == "sqli" and sql_error_hint(body):
        return Finding(url=url, method=method, param=param, category="sqli",
            title="SQL injection (error-based evidence)",
            evidence=f"database error string in response (HTTP {st}) via {variant}",
            payload=payload, variant=variant, confidence="medium")
    if cat == "cmdi" and marker and marker in body:
        return Finding(url=url, method=method, param=param, category="cmdi",
            title="Command injection (marker echo)",
            evidence=f"marker {marker} echoed in response (HTTP {st}) via {variant}",
            payload=payload, variant=variant, confidence="strong")
    if cat == "traversal" and traversal_hit(body):
        return Finding(url=url, method=method, param=param, category="traversal",
            title="Path traversal / arbitrary file read",
            evidence=f"file-content markers in response (HTTP {st}) via {variant}",
            payload=payload, variant=variant, confidence="strong")
    if cat == "ssti":
        if ssti_hit(body, payload):
            return Finding(url=url, method=method, param=param, category="ssti",
                title="Server-Side Template Injection",
                evidence=f"oracle {payload} evaluated (49 observed, HTTP {st})",
                payload=payload, variant=variant, confidence="strong")
        if st == 500:
            return Finding(url=url, method=method, param=param, category="ssti",
                title="Template engine error on injection oracle",
                evidence=f"HTTP 500 for {payload} — template may evaluate input",
                payload=payload, variant=variant, confidence="weak")
    return None


async def _probe_targets(sem, client, targets, report, opts, headers):
    marker = "KELAN" + format(random.getrandbits(24), "x")
    strong_seen: set = set()

    async def work(t):
        url, method, param, form = t
        probes = build_probes(opts.vectors, marker=marker, bypass=opts.bypass)
        async with sem:
            for cat, variant, payload in probes:
                try:
                    if form is not None:
                        if method == "GET":
                            resp = await client.get(
                                _inject_query(form.action, param, payload),
                                headers=headers,
                            )
                        else:
                            data = {f.name: f.value for f in form.fields}
                            data[param] = payload
                            resp = await client.post(form.action, data=data, headers=headers)
                    else:
                        resp = await client.get(_inject_query(url, param, payload),
                                                headers=headers)
                except Exception as exc:
                    log.debug("probe_failed", url=url, param=param, error=str(exc))
                    continue
                f = _evaluate(cat, resp, payload, variant, url, method, param,
                              marker, strong_seen)
                if f:
                    report.add(f)
            if opts.delay:
                await asyncio.sleep(opts.delay)

    await asyncio.gather(*(work(t) for t in targets))


async def _probe_api(sem, client, pages, report, opts, headers):
    seen = set()
    for page in pages:
        u = urlparse(page.url)
        q = dict(parse_qsl(u.query, keep_blank_values=True))
        is_api = bool(API_RE.search(u.path.lower())) or "id" in q
        if not is_api:
            continue
        base = urlunparse((u.scheme, u.netloc, u.path, u.params, "", ""))
        if base in seen:
            continue
        seen.add(base)
        async with sem:
            try:
                if "id" in q:
                    ra = await client.get(_inject_query(page.url, "id", "1"), headers=headers)
                    rb = await client.get(_inject_query(page.url, "id", "2"), headers=headers)
                else:
                    ra = await client.get(base + "/1", headers=headers)
                    rb = await client.get(base + "/2", headers=headers)
            except Exception as exc:
                log.debug("api_probe_failed", url=base, error=str(exc))
                continue
            conf, note = grade_idor(ra, rb)
            if conf == "strong":
                report.add(Finding(url=base, method="GET", param="id",
                    category="idor", title="Broken Object Level Authorization (BOLA/IDOR)",
                    evidence=note, confidence="strong"))
            elif conf == "weak":
                report.add(Finding(url=base, method="GET", param="id",
                    category="idor", title="Possible IDOR — responses differ across ids",
                    evidence=note, confidence="weak", severity="MEDIUM"))
            else:
                log.info("idor_none", url=base, note=note)


def _check_headers(resp_headers: dict, report, url):
    for h in REQUIRED_HEADERS:
        if h not in resp_headers:
            report.add(Finding(url=url, method="GET", param=h, category="header",
                title=f"Missing security header: {h}",
                evidence=f"response omits {h}",
                confidence="strong"))


async def _ratelimit_probe(url: str, client) -> list[dict]:
    results = []
    for variant in RATELIMIT_HEADERS:
        codes = []
        for _ in range(20):
            try:
                r = await client.get(url, headers=variant, timeout=15)
                codes.append(r.status_code)
            except Exception as exc:
                log.debug("ratelimit_probe_request_failed", error=str(exc))
                codes.append(0)
        results.append({
            "code": (429 if 429 in codes else max(codes) if codes else 0),
            "headers": variant,
            "url": url,
            "identity": "baseline" if not variant else list(variant.values())[0]
        })
    return results


async def run_scan(opts: ScanOptions) -> Report:
    log.info("dast_start", target=opts.target, model=opts.model)
    report = Report(opts.target, opts.model)
    headers = dict(DEFAULT_HEADERS)



    crawler = Crawler(
        seed=opts.target,
        max_pages=opts.max_pages if opts.crawl else 1,
        max_depth=opts.max_depth if opts.crawl else 1,
        delay=opts.delay, timeout=opts.timeout, external=opts.external,
    )
    pages = await crawler.crawl()
    if not pages:
        raise RuntimeError(f"could not fetch seed URL: {opts.target}")
    seed = pages[0]
    log.info("dast_fetch", status=seed.status, url=seed.url)
    _check_headers(seed.resp_headers, report, seed.url)

    if opts.crawl:
        log.info("dast_crawl",
                 pages=len(pages),
                 forms=sum(len(p.forms) for p in pages),
                 params=sum(len(p.params) for p in pages),
                 links=sum(len(p.links) for p in pages))

    login_forms = [
        f for p in pages for f in p.forms if f.is_login
    ]
    report.meta = {
        "pages": len(pages),
        "forms": sum(len(p.forms) for p in pages),
        "params": sum(len(p.params) for p in pages),
        "login_forms": [
            {"action": f.action, "method": f.method,
             "fields": [x.name for x in f.fields]} for f in login_forms
        ],
    }

    targets = _build_targets(pages, fuzz_tokens=opts.fuzz_tokens)
    sem = asyncio.Semaphore(opts.concurrency)
    async with httpx.AsyncClient(timeout=opts.timeout, follow_redirects=True) as client:
        await _probe_targets(sem, client, targets, report, opts, headers)
        await _probe_api(sem, client, pages, report, opts, headers)
        if "ratelimit" in opts.vectors:
            rl_results = await _ratelimit_probe(opts.target, client)
            rl_finding = grade_ratelimit_burst(rl_results)
            if rl_finding:
                report.add(rl_finding)

    if opts.use_llm and report.findings:
        for f in report.findings:
            if f.category in CATEGORY_CWE:
                f_dict = {
                    "category": f.category,
                    "title": f.title,
                    "remediation": f.remediation,
                    "cwe": f.cwe,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "evidence": [{"kind": "advisory", "detail": f.evidence, "ref": f.url, "snippet": f.payload or f.variant}]
                }
                enriched = await enrich_finding(f_dict, endpoint=opts.endpoint, model=opts.model)
                f.title = enriched.get("title", f.title)
                f.remediation = enriched.get("remediation", f.remediation)
                f.cwe = enriched.get("cwe", f.cwe)
        report.risk_summary = _builtin_summary(report)
    else:
        report.risk_summary = _builtin_summary(report)

    report.finalize()
    log.info("dast_done", findings=len(report.findings), target=opts.target)
    return report


def _builtin_summary(report: Report) -> str:
    if not report.findings:
        return "No confirmed weaknesses detected in scope."
    top = sorted(report.findings,
                 key=lambda f: SEV_ORDER.get(f.severity, 9))[:3]
    return "Top risks: " + "; ".join(f"{f.severity} {f.cwe} {f.title} @ {f.url}" for f in top)


def render_report(report: Report):
    width = 72
    flagged = report.findings
    print("=" * width)
    print("🛡️  KELAN DAST AGENT REPORT")
    print("=" * width)
    print(f"Target: {report.target}")
    flawed = any(f.severity in ("CRITICAL", "HIGH", "MEDIUM") for f in flagged)
    print(f"Flaw detected: {'YES ⚠️' if flawed else 'NO ✅'}")
    stats = report.stats()
    sev = stats["severities"]
    print(f"Findings: " + ", ".join(f"{sev.get(s, 0)} {s}" for s in
                                     ("CRITICAL", "HIGH", "MEDIUM", "LOW")) or "0")
    missing = [f for f in flagged if f.category == "header"]
    if missing:
        print("\nMissing Security Headers:")
        for f in missing:
            print(f"  • {f.title.removeprefix('Missing security header: ')}")
    surface = report.meta.get("login_forms") or []
    if surface:
        print("\nDiscovered login forms (attack surface):")
        for lf in surface:
            print(f"  • {lf['action']} [{lf['method'].upper()}] fields={lf['fields']}")
    print("-" * width)
    for f in flagged:
        if f.category == "header":
            continue
        print(f"\n[{f.severity}] {f.cwe} — {f.title}")
        print(f"  URL:       {f.url}")
        print(f"  Param:     {f.param} ({f.method})  variant: {f.variant}")
        print(f"  Evidence:  {f.evidence}")
        print(f"  Remediation: {f.remediation}")
        print(f"  Confidence: {f.confidence}")
    print("-" * width)
    if report.risk_summary:
        print(f"Risk Summary: {report.risk_summary}")
    print("=" * width)
