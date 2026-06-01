from __future__ import annotations

VERSION = "1.0"

# Param name signals — mapped to (vector, weight)
PARAM_SIGNALS: list[tuple[list[str], str, int]] = [
    (["page", "file", "lang", "language", "include", "view", "template",
      "path", "doc", "read", "load", "resource", "src", "import", "require"], "LFI", 3),
    (["cmd", "command", "exec", "execute", "run", "ping", "host",
      "lookup", "query", "shell", "system", "process"], "CMDI", 3),
    (["id", "user_id", "uid", "account", "profile", "record",
      "order", "invoice", "document", "item", "object"], "IDOR", 2),
    (["q", "search", "keyword", "term", "filter", "name",
      "username", "user", "email", "login"], "SQLI", 2),
    (["redirect", "url", "return", "next", "target", "callback",
      "dest", "destination", "goto", "link", "ref", "referrer"], "XSS", 1),
    (["comment", "message", "content", "body", "text",
      "description", "note", "feedback", "input"], "XSS", 2),
]

# URL path pattern signals
PATH_SIGNALS: list[tuple[str, str, int]] = [
    # pattern (substring in path)  vector  weight
    ("upload",     "UPLOAD",  3),
    ("file",       "UPLOAD",  2),
    ("import",     "UPLOAD",  2),
    ("api/",       "IDOR",    2),
    ("api/v",      "IDOR",    3),
    ("graphql",    "IDOR",    2),
    ("admin",      "BRAUTH",  2),
    ("login",      "BRAUTH",  3),
    ("register",   "BRAUTH",  2),
    ("reset",      "BRAUTH",  2),
    ("password",   "BRAUTH",  2),
    ("auth",       "BRAUTH",  2),
    ("token",      "BRAUTH",  2),
    ("xml",        "XXE",     3),
    ("soap",       "XXE",     3),
    ("wsdl",       "XXE",     3),
    ("search",     "SQLI",    2),
    ("filter",     "SQLI",    2),
    ("cmd",        "CMDI",    3),
    ("exec",       "CMDI",    3),
    ("ping",       "CMDI",    3),
]

# Response header signals
HEADER_SIGNALS: list[tuple[str, str, str, int]] = [
    # header-name   value-contains   vector   weight
    ("dav",               "",            "VERB",   3),
    ("allow",             "PUT",         "VERB",   3),
    ("allow",             "DELETE",      "VERB",   2),
    ("content-type",      "xml",         "XXE",    2),
    ("content-type",      "soap",        "XXE",    3),
    ("set-cookie",        "jwt",         "BRAUTH", 2),
    ("set-cookie",        "token",       "BRAUTH", 2),
    ("www-authenticate",  "",            "BRAUTH", 2),
    ("x-powered-by",      "php",         "SQLI",   1),
]

# Form field signals
FORM_SIGNALS: list[tuple[str, str, str, int]] = [
    # input type / name contains   vector   weight
    ("type", "file",         "UPLOAD", 3),
    ("name", "file",         "UPLOAD", 2),
    ("name", "upload",       "UPLOAD", 3),
    ("name", "username",     "SQLI",   2),
    ("name", "password",     "SQLI",   2),
    ("name", "search",       "SQLI",   2),
    ("name", "email",        "SQLI",   1),
    ("name", "comment",      "XSS",    2),
    ("name", "message",      "XSS",    2),
    ("name", "feedback",     "XSS",    2),
    ("name", "xml",          "XXE",    3),
    ("name", "data",         "XXE",    1),
    ("name", "host",         "CMDI",   3),
    ("name", "cmd",          "CMDI",   3),
    ("name", "ping",         "CMDI",   3),
    ("name", "ip",           "CMDI",   2),
    ("name", "url",          "SSRF",   3),
    ("name", "webhook",      "SSRF",   3),
    ("name", "callback",     "SSRF",   2),
    ("name", "fetch",        "SSRF",   2),
]

# Content-type request signals (for API endpoint detection)
ACCEPT_XML_TYPES = {"application/xml", "text/xml", "application/soap+xml", "application/xhtml+xml"}

# Numeric ID pattern in URL paths — strong IDOR signal
NUMERIC_ID_RE = r"/\d+(?:/|$)"

# Vector metadata — display name, description, OSCP relevance note
VECTORS: dict[str, dict] = {
    "LFI":    {"name": "Local File Inclusion",       "note": "file param → /etc/passwd → log poison chain"},
    "UPLOAD": {"name": "File Upload Bypass",         "note": "extension filter bypass → webshell"},
    "SQLI":   {"name": "SQL Injection",              "note": "union/blind → creds or direct RCE via INTO OUTFILE"},
    "CMDI":   {"name": "Command Injection",          "note": "OS command injection → direct shell"},
    "XXE":    {"name": "XML External Entity (XXE)",  "note": "file read or SSRF pivot via XML parser"},
    "IDOR":   {"name": "Insecure Direct Object Ref", "note": "change ID → access other users' data"},
    "XSS":    {"name": "Cross-Site Scripting",       "note": "stored → session hijack; reflected → phish"},
    "VERB":   {"name": "HTTP Verb Tampering",        "note": "PUT/DELETE bypass auth; WebDAV file write"},
    "BRAUTH": {"name": "Broken Authentication",      "note": "default creds, weak JWT, password reset flaw"},
    "SSRF":   {"name": "Server-Side Request Forgery","note": "internal pivot, cloud metadata, port scan"},
    "SSTI":   {"name": "Server-Side Template Inj",  "note": "{{7*7}} in name/search → RCE via template engine"},
}
