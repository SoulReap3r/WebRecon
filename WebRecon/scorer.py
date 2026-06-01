from __future__ import annotations

from .models import PageResult, VectorScore, EndpointSignal


def score_vectors(pages: list[PageResult]) -> list[VectorScore]:
    totals: dict[str, int] = {}
    all_signals: dict[str, list[EndpointSignal]] = {}

    for page in pages:
        for sig in page.signals:
            totals[sig.vector] = totals.get(sig.vector, 0) + sig.weight
            all_signals.setdefault(sig.vector, []).append(sig)

    scores = [
        VectorScore(vector=v, score=s, signals=all_signals.get(v, []))
        for v, s in totals.items()
    ]
    return sorted(scores, key=lambda x: x.score, reverse=True)
