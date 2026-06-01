from __future__ import annotations

import json
from datetime import datetime

from .models import VectorScore, PageResult
from .constants import VECTORS


def build_report(
    target: str,
    pages: list[PageResult],
    scores: list[VectorScore],
    stack: dict[str, str],
) -> dict:
    return {
        "tool": "WebRecon",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "stack": stack,
        "pages_crawled": len(pages),
        "vectors": [
            {
                "vector": vs.vector,
                "name": VECTORS.get(vs.vector, {}).get("name", vs.vector),
                "confidence": vs.confidence,
                "score": vs.score,
                "note": VECTORS.get(vs.vector, {}).get("note", ""),
                "signals": [
                    {"url": s.url, "source": s.source, "detail": s.detail, "weight": s.weight}
                    for s in vs.signals
                ],
            }
            for vs in scores
        ],
    }


def save_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
