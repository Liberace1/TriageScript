from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List as _list

from triagescript.analyzers.vba import MacroInfo, extract_vba_macros
from triagescript.decode import (
    extract_decoded_strings,
    extract_recovered_strings,
    normalize_vba_code,
)
from triagescript.detectors import (
    DetectorHit,
    collect_techniques,
    detect_autoexec,
    detect_obfuscation,
    find_iocs,
    run_behavior_detectors,
)
from triagescript.scorer import score_hits

DECODED_SUFFIX = " (found in decoded content)"


@dataclass
class AnalysisResult:
    success: bool
    message: str
    filename: str
    verdict: str | None = None
    score: int | None = None
    max_score: int | None = None
    contributions: _list[DetectorHit] = None
    iocs: dict[str, list[str]] = None
    techniques: _list[str] = None
    macros: _list[MacroInfo] = None
    recovered: _list[str] = None


def analyze_vba_code(code: str, filename: str = "input") -> AnalysisResult:
    normalized = normalize_vba_code(code)
    recovered = extract_recovered_strings(normalized)

    hits: list[DetectorHit] = []
    hits.extend(detect_autoexec(normalized))
    hits.extend(run_behavior_detectors(normalized))
    hits.extend(detect_obfuscation(normalized, extract_decoded_strings(normalized)))

    # Second pass over the decoded/recovered strings, so behavior hidden inside
    # Chr() arrays, Base64 blobs, or split literals still scores. A behavior
    # already seen in the raw source is not double-counted.
    decoded_blob = "\n".join(recovered)
    if decoded_blob:
        seen = {hit.description for hit in hits}
        for hit in run_behavior_detectors(decoded_blob):
            if hit.description in seen:
                continue
            hit.description += DECODED_SUFFIX
            hits.append(hit)

    iocs = find_iocs(normalized, recovered)
    score = score_hits(hits)
    techniques = collect_techniques(hits)

    return AnalysisResult(
        success=True,
        message="Analysis completed.",
        filename=str(filename),
        verdict=score.verdict,
        score=score.score,
        max_score=score.max_score,
        contributions=score.contributions,
        iocs=iocs,
        techniques=techniques,
        macros=[],
        recovered=recovered,
    )


def analyze_vba_file(path: str | Path) -> AnalysisResult:
    extraction = extract_vba_macros(path)
    if not extraction.success:
        return AnalysisResult(
            success=False,
            message=extraction.message,
            filename=str(path),
            contributions=[],
            iocs={"urls": [], "ips": []},
            techniques=[],
            macros=[],
            recovered=[],
        )

    source_code = "\n\n".join(module.code for module in extraction.macros)
    result = analyze_vba_code(source_code, filename=path)
    result.macros = extraction.macros
    return result
