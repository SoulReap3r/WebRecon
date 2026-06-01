from __future__ import annotations

from .models import PageResult


TECH_FINGERPRINTS: list[tuple[str, str, str]] = [
    # header           value-contains   tech-label
    ("server",         "apache",        "Apache"),
    ("server",         "nginx",         "Nginx"),
    ("server",         "iis",           "IIS"),
    ("server",         "litespeed",     "LiteSpeed"),
    ("x-powered-by",   "php",           "PHP"),
    ("x-powered-by",   "asp.net",       "ASP.NET"),
    ("x-powered-by",   "express",       "Node/Express"),
    ("x-powered-by",   "python",        "Python"),
    ("x-powered-by",   "ruby",          "Ruby"),
    ("x-generator",    "wordpress",     "WordPress"),
    ("x-generator",    "drupal",        "Drupal"),
    ("x-generator",    "joomla",        "Joomla"),
]

COOKIE_FINGERPRINTS: dict[str, str] = {
    "phpsessid":         "PHP",
    "jsessionid":        "Java/Tomcat",
    "asp.net_sessionid": "ASP.NET",
    "cfid":              "ColdFusion",
    "cftoken":           "ColdFusion",
    "rack.session":      "Ruby/Rack",
}

EXT_MAP: dict[str, str] = {
    ".php":   "PHP",
    ".asp":   "ASP",
    ".aspx":  "ASP.NET",
    ".jsp":   "Java/JSP",
    ".do":    "Java/Struts",
    ".py":    "Python",
    ".rb":    "Ruby",
    ".cfm":   "ColdFusion",
}

# Vector weights boosted when a given tech is detected
TECH_BOOSTS: dict[str, dict[str, int]] = {
    "PHP":       {"LFI": 3, "SQLI": 2, "UPLOAD": 1, "SSTI": 1},
    "ASP.NET":   {"SQLI": 2, "VERB": 2, "BRAUTH": 1},
    "Java/JSP":  {"SQLI": 2, "SSTI": 2, "XXE": 2},
    "Java/Tomcat": {"SQLI": 2, "SSTI": 2, "XXE": 2},
    "Node/Express": {"IDOR": 2, "SSTI": 2, "BRAUTH": 2},
    "Ruby":      {"SSTI": 3, "IDOR": 2},
    "Python":    {"SSTI": 3, "CMDI": 2},
    "WordPress": {"UPLOAD": 3, "SQLI": 2, "BRAUTH": 2, "IDOR": 2},
    "Apache":    {"LFI": 1},
    "Nginx":     {"LFI": 1},
    "IIS":       {"VERB": 2, "UPLOAD": 2},
}


def detect_stack(pages: list[PageResult]) -> dict[str, str]:
    """Return detected tech components: {'server': 'Apache', 'lang': 'PHP', ...}"""
    from urllib.parse import urlparse

    stack: dict[str, str] = {}

    for page in pages:
        # Headers
        for hname, hval, label in TECH_FINGERPRINTS:
            v = page.headers.get(hname, "")
            if hval.lower() in v.lower():
                category = "lang" if any(x in label for x in ("PHP","ASP","Java","Node","Python","Ruby","Cold")) else "server"
                if label in ("WordPress", "Drupal", "Joomla"):
                    category = "cms"
                stack.setdefault(category, label)

        # Session cookies
        cookie_hdr = page.headers.get("set-cookie", "")
        for cname, clabel in COOKIE_FINGERPRINTS.items():
            if cname in cookie_hdr.lower():
                stack.setdefault("lang", clabel)

        # URL extensions
        path = urlparse(page.url).path.lower()
        for ext, label in EXT_MAP.items():
            if path.endswith(ext):
                stack.setdefault("lang", label)

    return stack


def stack_boosts(stack: dict[str, str]) -> dict[str, int]:
    """Return extra score boosts per vector based on detected tech."""
    boosts: dict[str, int] = {}
    for tech in stack.values():
        for vector, boost in TECH_BOOSTS.get(tech, {}).items():
            boosts[vector] = boosts.get(vector, 0) + boost
    return boosts
