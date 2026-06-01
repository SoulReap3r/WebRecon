from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests

from .models import PageResult, EndpointSignal

# Patterns for API/path references inside JS
_JS_PATH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post|put|delete|patch)|url\s*[:=]|href\s*=|src\s*=|\.open\s*\(\s*["'](?:GET|POST)["']\s*,)\s*["'`]([^"'`\s]{3,120})["'`]""",
    re.IGNORECASE,
)
_RELATIVE_PATH_RE = re.compile(r"""["'`](/[a-zA-Z0-9_/\-\.]{2,80})["'`]""")


def _extract_js_urls(base_url: str, pages: list[PageResult]) -> list[str]:
    from bs4 import BeautifulSoup
    js_urls = []
    for page in pages:
        if "html" not in page.content_type:
            continue
        # We don't have the raw HTML here — re-fetch would be needed.
        # Instead collect src= from already-crawled link lists that end in .js
        for link in page.links:
            if link.endswith(".js") and link not in js_urls:
                js_urls.append(link)
    return js_urls


def _fetch_text(session: requests.Session, url: str, timeout: float) -> str:
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        return resp.text[:500_000]
    except requests.RequestException:
        return ""


def scan_js(
    pages: list[PageResult],
    session: requests.Session,
    base_url: str,
    timeout: float,
    verbose: bool,
) -> list[EndpointSignal]:
    signals: list[EndpointSignal] = []
    js_urls = _extract_js_urls(base_url, pages)

    for js_url in js_urls:
        if verbose:
            print(f"  [js] {js_url}")
        text = _fetch_text(session, js_url, timeout)
        if not text:
            continue

        found_paths: set[str] = set()

        for m in _JS_PATH_RE.finditer(text):
            path = m.group(1)
            if path.startswith("/") or path.startswith("http"):
                found_paths.add(path)

        for m in _RELATIVE_PATH_RE.finditer(text):
            path = m.group(1)
            if "/api/" in path or "/admin" in path or "/user" in path or "/file" in path:
                found_paths.add(path)

        for path in found_paths:
            abs_url = urljoin(base_url, path) if path.startswith("/") else path

            # Score based on path content
            pl = path.lower()
            if re.search(r"/\d+", path):
                signals.append(EndpointSignal(
                    url=abs_url, method="GET", source="js",
                    vector="IDOR", weight=3,
                    detail=f"JS references numeric-ID path: {path}",
                ))
            if any(x in pl for x in ("/api/", "/v1/", "/v2/", "/rest/")):
                signals.append(EndpointSignal(
                    url=abs_url, method="GET", source="js",
                    vector="IDOR", weight=2,
                    detail=f"JS references API endpoint: {path}",
                ))
            if any(x in pl for x in ("/upload", "/file", "/import")):
                signals.append(EndpointSignal(
                    url=abs_url, method="POST", source="js",
                    vector="UPLOAD", weight=2,
                    detail=f"JS references upload endpoint: {path}",
                ))
            if any(x in pl for x in ("/admin", "/dashboard", "/manage")):
                signals.append(EndpointSignal(
                    url=abs_url, method="GET", source="js",
                    vector="BRAUTH", weight=2,
                    detail=f"JS references admin path: {path}",
                ))

    return signals
