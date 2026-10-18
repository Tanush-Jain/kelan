





from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import urljoin, urldefrag, urlparse, parse_qsl

import httpx
import structlog

log = structlog.get_logger()

DEFAULT_HEADERS = {
    "User-Agent": "kelan-dast/0.4 (authorized security assessment)",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}


SKIP_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".avif",
    ".css", ".woff", ".woff2", ".ttf", ".eot",
    ".mp4", ".mp3", ".webm", ".zip", ".gz", ".bz2", ".7z", ".rar",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".exe", ".msi", ".dmg", ".apk", ".deb", ".rpm", ".map",
}


TOKEN_HINT = re.compile(r"(^|[_\-])(csrf|xsrf|nonce|token|captcha|honeypot)([_\-]|$)", re.I)
ASP_NET_HIDDEN = re.compile(r"^__", re.I)


@dataclass
class FormField:
    name: str
    type: str
    value: str = ""
    is_secret: bool = False


@dataclass
class Form:
    action: str
    method: str
    fields: list[FormField] = field(default_factory=list)
    is_login: bool = False


@dataclass
class Page:
    url: str
    status: int
    final_url: str
    content_type: str
    resp_headers: dict = field(default_factory=dict)
    title: str = ""
    links: list[str] = field(default_factory=list)
    forms: list[Form] = field(default_factory=list)
    params: list[str] = field(default_factory=list)


class _HtmlParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.title = ""
        self.links: list[str] = []
        self.forms: list[Form] = []
        self._in_title = False
        self._current: Optional[Form] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "base" and a.get("href"):
            self.base_url = urljoin(self.base_url, a["href"])
        elif tag == "title":
            self._in_title = True
        elif tag == "a":
            href = a.get("href")
            if href:
                self.links.append(urljoin(self.base_url, href))
        elif tag in ("iframe", "frame"):
            src = a.get("src")
            if src:
                self.links.append(urljoin(self.base_url, src))
        elif tag == "form":
            self._current = Form(
                action=urljoin(self.base_url, a.get("action") or self.base_url),
                method=(a.get("method") or "get").lower(),
            )
        elif tag == "input" and self._current is not None:
            ftype = (a.get("type") or "text").lower()
            f = FormField(name=a.get("name", ""), type=ftype, value=a.get("value", ""))
            if ftype == "password":
                self._current.is_login = True
            if ftype == "hidden":
                f.is_secret = bool(TOKEN_HINT.search(f.name) or ASP_NET_HIDDEN.match(f.name))
            if ftype not in ("submit", "button", "image"):
                self._current.fields.append(f)
        elif tag in ("textarea", "select") and self._current is not None:
            self._current.fields.append(
                FormField(name=a.get("name", ""), type=tag, value=a.get("value", ""))
            )

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None

    def handle_data(self, data):
        if self._in_title:
            self.title = (self.title + " " + data).strip()


class Crawler:
    def __init__(self, seed: str, max_pages: int = 15, max_depth: int = 3,
                 delay: float = 0.5, timeout: float = 15.0,
                 external: bool = False, headers: Optional[dict] = None):
        self.seed = seed
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.delay = delay
        self.timeout = timeout
        self.external = external
        self.headers = {**DEFAULT_HEADERS, **(headers or {})}
        self._base_host = urlparse(seed).netloc.lower()
        self._seen: set[str] = set()
        self._client: Optional[httpx.AsyncClient] = None

    def _canon(self, url: str) -> str:
        return urldefrag(url)[0].rstrip("/") or urldefrag(url)[0]

    def _in_scope(self, url: str) -> bool:
        if not self.external:
            host = urlparse(url).netloc.lower()
            if host and host != self._base_host:
                return False
        return True

    async def crawl(self) -> list[Page]:
        self._client = httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True,
            limits=httpx.Limits(max_connections=4),
        )
        pages: list[Page] = []
        queue: list[tuple[str, int]] = [(self.seed, 0)]
        try:
            while queue and len(pages) < self.max_pages:
                url, depth = queue.pop(0)
                canon = self._canon(url)
                if canon in self._seen:
                    continue
                self._seen.add(canon)
                try:
                    r = await self._client.get(url, headers=self.headers)
                except Exception as exc:
                    log.warning("crawl_fetch_failed", url=url, error=str(exc))
                    continue
                if self.delay:
                    await asyncio.sleep(self.delay)
                ctype = (r.headers.get("content-type") or "").lower()
                if "html" not in ctype and "xhtml" not in ctype:
                    continue
                if len(r.content) > 2_000_000:
                    continue
                pages.append(self._parse_page(url, r))
                if depth >= self.max_depth:
                    continue
                for link in pages[-1].links:
                    if len(pages) >= self.max_pages:
                        break
                    if not self._in_scope(link):
                        continue
                    if any(urlparse(link).path.lower().endswith(e) for e in SKIP_EXT):
                        continue
                    queue.append((link, depth + 1))
        finally:
            await self._client.aclose()
            self._client = None
        return pages

    def _parse_page(self, url: str, r: httpx.Response) -> Page:
        parser = _HtmlParser(url)
        parser.feed(r.text)
        params = [name for name, _ in parse_qsl(urlparse(url).query)]
        return Page(
            url=url, status=r.status_code, final_url=str(r.url),
            content_type=r.headers.get("content-type", ""),
            resp_headers={k.lower(): v for k, v in r.headers.items()},
            title=parser.title, links=parser.links, forms=parser.forms,
            params=params,
        )
