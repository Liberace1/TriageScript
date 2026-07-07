from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from triagescript.detectors import DetectorHit


@dataclass
class ScoreResult:
    verdict: str
    score: int
    max_score: int
    contributions: list[DetectorHit]
    hard_escalator: bool


def score_hits(hits: Iterable[DetectorHit]) -> ScoreResult:
    contributions = sorted(hits, key=lambda hit: hit.score, reverse=True)
    total = sum(hit.score for hit in contributions)
    hard_escalator = any(hit.technique_id == "T1105" for hit in contributions)

    if hard_escalator and total < 45:
        total = 45

    total = min(total, 100)

    if total >= 70:
        verdict = "CRITICAL"
    elif total >= 45:
        verdict = "HIGH"
    elif total >= 25:
        verdict = "MEDIUM"
    else:
        verdict = "LOW"

    return ScoreResult(
        verdict=verdict,
        score=total,
        max_score=100,
        contributions=contributions,
        hard_escalator=hard_escalator,
    )
