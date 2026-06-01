from __future__ import annotations

from .constants import VECTORS
from .models import VectorScore, PageResult


def _c(text: str, code: str, colors: bool) -> str:
    return f"\033[{code}m{text}\033[0m" if colors else text


def print_banner(version: str, colors: bool) -> None:
    banner = f"""
  ██╗    ██╗███████╗██████╗ ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██║    ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║ █╗ ██║█████╗  ██████╔╝██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║███╗██║██╔══╝  ██╔══██╗██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚███╔███╔╝███████╗██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  v{version}  —  OSCP web vector classifier
"""
    print(_c(banner, "96", colors))


def print_crawl_summary(pages: list[PageResult], colors: bool) -> None:
    print(_c(f"\n  [*] crawled {len(pages)} page(s)", "96", colors))
    total_signals = sum(len(p.signals) for p in pages)
    total_forms = sum(len(p.forms) for p in pages)
    total_params = sum(len(p.params) for p in pages)
    print(f"      {total_params} params   {total_forms} forms   {total_signals} signals detected\n")


def print_vector_scores(scores: list[VectorScore], colors: bool, show_signals: bool) -> None:
    conf_color = {"HIGH": "1;92", "MEDIUM": "1;93", "LOW": "90"}

    print(_c("  ╔══════════════════════════════════════════════════════════════╗", "96", colors))
    print(_c("  ║  OSCP VECTOR ASSESSMENT                                      ║", "96", colors))
    print(_c("  ╚══════════════════════════════════════════════════════════════╝", "96", colors))
    print()

    shown = [s for s in scores if s.score > 0]
    if not shown:
        print("  no signals detected — try crawling more pages or check the target URL\n")
        return

    for rank, vs in enumerate(shown, 1):
        meta = VECTORS.get(vs.vector, {"name": vs.vector, "note": ""})
        conf = vs.confidence
        cc = conf_color.get(conf, "0")
        bar = "█" * min(vs.score, 20)
        print(
            f"  [{rank}] {_c(conf, cc, colors):<6}  "
            f"{_c(meta['name'], '1', colors):<35}  "
            f"score:{vs.score:>3}  {_c(bar, cc, colors)}"
        )
        print(f"        {_c(meta['note'], '2', colors)}")
        if show_signals:
            seen: set[str] = set()
            for sig in vs.signals[:6]:
                key = sig.detail
                if key not in seen:
                    seen.add(key)
                    print(f"         {_c('·', '90', colors)} [{sig.source}] {sig.detail}  ({sig.url})")
        print()
