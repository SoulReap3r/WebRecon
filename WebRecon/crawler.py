from __future__ import annotations

import re
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

try:
    from bs4 import BeautifulSoup
    _BS4 = True
except ImportError:
    _BS4 = False

from .models import PageResult


def _same_origin(base: str, url: str) -> bool:
    b = urlparse(base)
    u = urlparse(url)
    return b.scheme == u.scheme and b.netloc == u.netloc


def _normalise(url: str) -> str:
    p = urlparse(url)
    # drop fragment, sort query params for deduplication
    qs = parse_qs(p.query, keep_blank_values=True)
    sorted_query = urlencode(sorted(qs.items()), doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, sorted_query, ""))


def _extract_forms(soup) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        fields = []
        for inp in form.find_all(["input", "textarea", "select"]):
            fields.append({
                "name": inp.get("name", ""),
                "type": inp.get("type", "text"),
            })
        forms.append({
            "action": form.get("action", ""),
            "method": (form.get("method", "GET")).upper(),
            "fields": fields,
        })
    return forms


def _extract_links(soup, base_url: str) -> list[str]:
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if href.startswith(("mailto:", "javascript:", "#")):
            continue
        abs_url = urljoin(base_url, href)
        if _same_origin(base_url, abs_url):
            links.append(abs_url)
    return links


def _extract_params(url: str) -> list[str]:
    return list(parse_qs(urlparse(url).query).keys())


def fetch_page(
    session: requests.Session,
    url: str,
    timeout: float,
    max_bytes: int,
) -> PageResult | None:
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True)
        raw = resp.content[:max_bytes]
        encoding = resp.encoding or resp.apparent_encoding or "utf-8"
        text = raw.decode(encoding, errors="replace")
        content_type = resp.headers.get("content-type", "")
        headers = {k.lower(): v for k, v in resp.headers.items()}
        params = _extract_params(resp.url)
        forms: list[dict] = []
        links: list[str] = []
        if _BS4 and "html" in content_type:
            soup = BeautifulSoup(text, "html.parser")
            forms = _extract_forms(soup)
            links = _extract_links(soup, resp.url)
        return PageResult(
            url=resp.url,
            status=resp.status_code,
            content_type=content_type,
            headers=headers,
            forms=forms,
            params=params,
            links=links,
        )
    except requests.RequestException:
        return None


def crawl(
    start_url: str,
    session: requests.Session,
    timeout: float,
    max_bytes: int,
    max_pages: int,
    delay: float,
    verbose: bool,
) -> list[PageResult]:
    visited: set[str] = set()
    queue: list[str] = [start_url]
    results: list[PageResult] = []

    while queue and len(results) < max_pages:
        url = queue.pop(0)
        norm = _normalise(url)
        if norm in visited:
            continue
        visited.add(norm)

        if verbose:
            print(f"  [crawl] {url}")

        page = fetch_page(session, url, timeout, max_bytes)
        if delay:
            time.sleep(delay)
        if not page:
            continue

        results.append(page)

        for link in page.links:
            if _normalise(link) not in visited:
                queue.append(link)

    return results
