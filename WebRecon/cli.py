from __future__ import annotations

import argparse
import sys

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

from .constants import VERSION
from .crawler import crawl
from .fingerprint import fingerprint_page
from .scorer import score_vectors
from .display import print_banner, print_crawl_summary, print_vector_scores


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="webrecon",
        description="Crawl a web app and classify likely OSCP attack vectors.",
    )
    parser.add_argument("-t", "--target", required=True,
                        help="Target URL, e.g. http://TARGET/")
    parser.add_argument("--max-pages", type=int, default=30,
                        help="Max pages to crawl. Default: 30.")
    parser.add_argument("--timeout", type=float, default=8.0,
                        help="Request timeout seconds. Default: 8.")
    parser.add_argument("--max-bytes", type=int, default=200_000,
                        help="Max response bytes to read per page. Default: 200000.")
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
                        help=f"User-Agent string. Default: WebRecon/{VERSION}.")
    parser.add_argument("-s", "--signals", action="store_true",
                        help="Show individual signals under each vector.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print each URL as it is crawled.")
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
    for h in args.header:
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

    print(f"  target : {args.target}")
    print(f"  pages  : up to {args.max_pages}")
    print()

    session = build_session(args)
    pages = crawl(
        start_url=args.target,
        session=session,
        timeout=args.timeout,
        max_bytes=args.max_bytes,
        max_pages=args.max_pages,
        delay=args.delay,
        verbose=args.verbose,
    )

    for page in pages:
        fingerprint_page(page)

    scores = score_vectors(pages)

    print_crawl_summary(pages, colors)
    print_vector_scores(scores, colors, show_signals=args.signals)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
