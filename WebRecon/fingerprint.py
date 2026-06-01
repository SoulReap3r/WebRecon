from __future__ import annotations

import re

from .constants import (
    PARAM_SIGNALS, PATH_SIGNALS, HEADER_SIGNALS,
    FORM_SIGNALS, NUMERIC_ID_RE,
)
from .models import PageResult, EndpointSignal


def _param_signals(page: PageResult) -> list[EndpointSignal]:
    signals = []
    for param in page.params:
        pl = param.lower()
        for names, vector, weight in PARAM_SIGNALS:
            if pl in names or any(n in pl for n in names):
                signals.append(EndpointSignal(
                    url=page.url, method="GET", source="param",
                    vector=vector, weight=weight,
                    detail=f"param '{param}' matches {vector} pattern",
                ))
                break
    return signals


def _path_signals(page: PageResult) -> list[EndpointSignal]:
    from urllib.parse import urlparse
    path = urlparse(page.url).path.lower()
    signals = []
    for pattern, vector, weight in PATH_SIGNALS:
        if pattern in path:
            signals.append(EndpointSignal(
                url=page.url, method="GET", source="path",
                vector=vector, weight=weight,
                detail=f"path contains '{pattern}'",
            ))
    # numeric ID in path — IDOR signal
    if re.search(NUMERIC_ID_RE, path):
        signals.append(EndpointSignal(
            url=page.url, method="GET", source="path",
            vector="IDOR", weight=3,
            detail=f"numeric ID in path",
        ))
    return signals


def _header_signals(page: PageResult) -> list[EndpointSignal]:
    signals = []
    for hname, hval, vector, weight in HEADER_SIGNALS:
        v = page.headers.get(hname, "")
        if hval == "" and hname in page.headers:
            signals.append(EndpointSignal(
                url=page.url, method="GET", source="header",
                vector=vector, weight=weight,
                detail=f"header '{hname}' present",
            ))
        elif hval and hval.lower() in v.lower():
            signals.append(EndpointSignal(
                url=page.url, method="GET", source="header",
                vector=vector, weight=weight,
                detail=f"header '{hname}: {v}' contains '{hval}'",
            ))
    return signals


def _form_signals(page: PageResult) -> list[EndpointSignal]:
    signals = []
    for form in page.forms:
        for field in form.get("fields", []):
            for attr, pattern, vector, weight in FORM_SIGNALS:
                val = field.get(attr, "").lower()
                if pattern in val:
                    signals.append(EndpointSignal(
                        url=page.url,
                        method=form.get("method", "GET"),
                        source="form",
                        vector=vector,
                        weight=weight,
                        detail=f"form field {attr}='{field.get(attr,'')}' matches {vector}",
                    ))
                    break
    return signals


def _ssti_signals(page: PageResult) -> list[EndpointSignal]:
    signals = []
    # params that accept user-controlled text displayed back → SSTI candidate
    ssti_names = ["name", "title", "greeting", "template", "render", "text", "msg", "message"]
    for param in page.params:
        if param.lower() in ssti_names:
            signals.append(EndpointSignal(
                url=page.url, method="GET", source="param",
                vector="SSTI", weight=2,
                detail=f"param '{param}' commonly reflects user input (potential SSTI)",
            ))
    return signals


def fingerprint_page(page: PageResult) -> PageResult:
    page.signals = (
        _param_signals(page)
        + _path_signals(page)
        + _header_signals(page)
        + _form_signals(page)
        + _ssti_signals(page)
    )
    return page
