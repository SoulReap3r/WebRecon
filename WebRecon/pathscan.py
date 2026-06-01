from __future__ import annotations

import time
from urllib.parse import urljoin

import requests

from .models import PageResult, EndpointSignal

COMMON_PATHS = [
    # Auth / admin
    "/admin", "/admin/", "/admin.php", "/administrator", "/administrator/",
    "/login", "/login.php", "/signin", "/auth", "/auth/login",
    "/register", "/signup", "/user/login", "/account/login",
    "/panel", "/cpanel", "/dashboard", "/manage", "/management",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",
    "/administrator/index.php",   # Joomla
    "/user/login",                # Drupal
    # Upload / files
    "/upload", "/uploads", "/upload.php", "/file", "/files",
    "/images/upload", "/media", "/attachments", "/static/uploads",
    "/import", "/export",
    # API
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/graphql", "/query",
    "/api/users", "/api/user", "/api/items",
    # Config / info leaks
    "/config", "/config.php", "/configuration.php",
    "/backup", "/backup.zip", "/backup.tar.gz", "/db.sql",
    "/.env", "/env", "/settings", "/settings.php",
    "/phpinfo.php", "/info.php", "/test.php", "/debug",
    "/.git/HEAD", "/.svn/entries",
    "/web.config", "/appsettings.json",
    # Common includes / LFI targets
    "/index.php?page=", "/index.php?file=", "/index.php?lang=",
    # XML / SOAP
    "/soap", "/wsdl", "/service.wsdl", "/api.xml",
    # Shell / cmd
    "/cmd", "/exec", "/shell", "/command",
    "/ping", "/lookup", "/check",
]

# Map path keywords to vectors
_PATH_VECTOR_MAP: list[tuple[str, str, int]] = [
    ("admin",    "BRAUTH", 3),
    ("login",    "BRAUTH", 2),
    ("upload",   "UPLOAD", 3),
    ("file",     "UPLOAD", 2),
    ("api",      "IDOR",   2),
    ("graphql",  "IDOR",   3),
    ("config",   "BRAUTH", 2),
    ("backup",   "BRAUTH", 3),
    (".env",     "BRAUTH", 3),
    (".git",     "BRAUTH", 3),
    ("phpinfo",  "SQLI",   2),
    ("soap",     "XXE",    3),
    ("wsdl",     "XXE",    3),
    ("xml",      "XXE",    2),
    ("cmd",      "CMDI",   3),
    ("exec",     "CMDI",   3),
    ("shell",    "CMDI",   3),
    ("ping",     "CMDI",   3),
    ("page=",    "LFI",    3),
    ("file=",    "LFI",    3),
    ("lang=",    "LFI",    2),
]


def scan_paths(
    base_url: str,
    session: requests.Session,
    timeout: float,
    delay: float,
    verbose: bool,
) -> list[EndpointSignal]:
    signals: list[EndpointSignal] = []
    base = base_url.rstrip("/")

    for path in COMMON_PATHS:
        url = base + path if path.startswith("/") else urljoin(base + "/", path)
        try:
            resp = session.get(url, timeout=timeout, verify=False, allow_redirects=False)
            if delay:
                time.sleep(delay)
            if resp.status_code in (200, 301, 302, 403, 401):
                pl = path.lower()
                for keyword, vector, weight in _PATH_VECTOR_MAP:
                    if keyword in pl:
                        note = f"HTTP {resp.status_code}"
                        if resp.status_code == 403:
                            note += " (forbidden — exists but protected)"
                        if verbose:
                            print(f"  [path] {resp.status_code} {url}")
                        signals.append(EndpointSignal(
                            url=url, method="GET", source="pathscan",
                            vector=vector, weight=weight,
                            detail=f"{note}: {path}",
                        ))
                        break
        except requests.RequestException:
            pass

    return signals
