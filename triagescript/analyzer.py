from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import List as _list

from triagescript.analyzers.vba import MacroInfo, extract_vba_macros
from triagescript.decode import extract_recovered_strings, normalize_vba_code
from triagescript.detectors import (
    DetectorHit,
    collect_techniques,
    detect_autoexec,
    detect_download_chain,
    detect_obfuscation,
    detect_suspicious_shell,
    find_iocs,
)
from triagescript.scorer import score_hits


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


def analyze_vba_code(code: str, filename: str = "input") -> AnalysisResult:
    normalized = normalize_vba_code(code)
    recovered = extract_recovered_strings(normalized)

    hits: list[DetectorHit] = []
    hits.extend(detect_autoexec(normalized))
    hits.extend(detect_suspicious_shell(normalized))
    hits.extend(detect_download_chain(normalized))
    hits.extend(detect_obfuscation(normalized, recovered))

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
        )

    source_code = "\n\n".join(module.code for module in extraction.macros)
    result = analyze_vba_code(source_code, filename=path)
    result.macros = extraction.macros
    return result
