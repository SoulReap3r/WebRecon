from __future__ import annotations

import argparse
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .constants import VERSION
from .display import print_banner, print_crawl_summary, print_vector_scores
from .reports import build_report, save_json
from .wizard import run_scan, run_wizard


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Crawl a web app and classify likely OSCP attack vectors.",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL, e.g. http://TARGET/")
    parser.add_argument("--wizard", action="store_true",
                        help="Launch interactive guided wizard (recommended).")
    parser.add_argument("--mode", choices=("quick", "active", "full"), default="quick",
                        help="Scan mode: quick (passive), active (+probes), full (+JS+paths). Default: quick.")
    parser.add_argument("--exam", action="store_true",
                        help="Print exam-mode output: top vectors + direct attack commands.")
    parser.add_argument("--max-pages", type=int, default=30,
                        help="Max pages to crawl. Default: 30.")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="Request timeout seconds. Default: 8.")
    parser.add_argument("--max-bytes", type=int, default=200_000,
                        help="Max response bytes per page. Default: 200000.")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="Delay between requests in seconds. Default: 0.")
    parser.add_argument("--cookie", metavar="VALUE",
                        help="Cookie header, e.g. 'PHPSESSID=abc123'.")
    parser.add_argument("-H", "--header", action="append", default=[],
                        metavar="NAME:VALUE",
                        help="Extra request header (repeatable).")
    parser.add_argument("--proxy",
                        help="Proxy URL, e.g. http://127.0.0.1:8080.")
    parser.add_argument("--user-agent", default=f"WebRecon/{VERSION}",
                        help=f"User-Agent. Default: WebRecon/{VERSION}.")
    parser.add_argument("-s", "--signals", action="store_true",
                        help="Show individual signals under each vector.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print each URL/path as it is processed.")
    parser.add_argument("--json-output", metavar="FILE",
                        help="Save JSON report to file.")
    parser.add_argument("--no-color", action="store_true",
                        help="Disable ANSI color output.")
    parser.add_argument("--no-banner", action="store_true",
                        help="Suppress banner.")
    return parser.parse_args()


def build_session(args: argparse.Namespace) -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = args.user_agent
    if args.cookie:
        session.headers["Cookie"] = args.cookie
    for h in (args.header or []):
        if ":" in h:
            name, value = h.split(":", 1)
            session.headers[name.strip()] = value.strip()
    if args.proxy:
        session.proxies.update({"http": args.proxy, "https": args.proxy})
    return session


def main() -> int:
    args = parse_args()
    colors = (not args.no_color) and sys.stdout.isatty()

    if not args.no_banner:
        print_banner(VERSION, colors)

    if args.wizard:
        run_wizard(args, colors)
        return 0

    print(f"  target : {args.target}")
    print(f"  mode   : {args.mode}")
    print(f"  pages  : up to {args.max_pages}")
    print()

    session = build_session(args)
    pages, scores, stack = run_scan(args, session, args.mode, colors)

    print_crawl_summary(pages, colors)

    if args.exam:
        from .wizard import _print_exam_mode
        _print_exam_mode(scores, args.target, stack, colors)
    else:
        if stack:
            from .display import _c
            stack_str = "  ".join(f"{k}:{_c(v,'1;93',colors)}" for k, v in stack.items())
            print(f"  stack detected: {stack_str}\n")
        print_vector_scores(scores, colors, show_signals=args.signals)

    if args.json_output:
        report = build_report(args.target, pages, scores, stack)
        save_json(report, args.json_output)
        print(f"  [+] report saved: {args.json_output}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
