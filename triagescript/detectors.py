from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from triagescript.attack_map import TECHNIQUE_NAMES


def _compile(pattern: str, flags: int = re.IGNORECASE) -> re.Pattern[str]:
    return re.compile(pattern, flags)


@dataclass
class DetectorHit:
    technique_id: str
    technique_name: str
    description: str
    score: int
    indicator: str | None = None


AUTOEXEC_PATTERN = _compile(r'\bSub\s+(AutoOpen|Auto_Open|Document_Open|Workbook_Open|DocumentOpen|WorkbookOpen)\b')
SHELL_PATTERNS = [
    _compile(r'CreateObject\s*\(\s*"WScript\.Shell"\s*\)'),
    _compile(r'CreateObject\s*\(\s*"Shell\.Application"\s*\)'),
    _compile(r'\bShell\s*\('),
    _compile(r'\.Run\s*\('),
    _compile(r'\.Exec\s*\('),
]
DOWNLOAD_PATTERNS = [
    _compile(r'URLDownloadToFile', re.I),
    _compile(r'MSXML2?\.XMLHTTP', re.I),
    _compile(r'ServerXMLHTTP', re.I),
    _compile(r'WinHttpRequest', re.I),
    _compile(r'ADODB\.Stream', re.I),
    _compile(r'bitsadmin', re.I),
    _compile(r'curl\s', re.I),
    _compile(r'power(?:shell|sh)\b', re.I),
]
EVAL_PATTERNS = [
    _compile(r'\bEval(?:uate)?\s*\('),
    _compile(r'\bExecute(?:Global)?\s*\('),
    _compile(r'\bCallByName\s*\('),
    _compile(r'Application\.Run\b'),
    _compile(r'ExecuteExcel4Macro'),
    _compile(r'ScriptControl'),
]
FILE_WRITE_PATTERNS = [
    _compile(r'Scripting\.FileSystemObject'),
    _compile(r'\.SaveToFile\b'),
    _compile(r'\.CreateTextFile\b'),
    _compile(r'\bOpen\s+.+\s+For\s+Binary'),
]
REGISTRY_PATTERNS = [
    _compile(r'\.RegWrite\b'),
    _compile(r'CurrentVersion\\+Run'),
    _compile(r'\bStartup\s+Folder', re.I),
]
RECON_PATTERNS = [
    _compile(r'\bEnviron\$?\s*\('),
    _compile(r'Application\.UserName'),
    _compile(r'\bComputerName\b'),
]
EVASION_PATTERNS = [
    _compile(r'Application\.Wait'),
    _compile(r'\bSleep\b'),
]
OBFUSCATION_PATTERNS = [
    _compile(r'Chr\b'),
    _compile(r'StrReverse\b'),
    _compile(r'Asc\b'),
    _compile(r'Xor\b'),
]
URL_PATTERN = re.compile(r'\b(?:hxxp|https?)://[\w\-\.\[\]]+(?:[:\d]*)?(?:/[\w\-\./?%&=~]*)?', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')


def _make_hit(technique_id: str, description: str, score: int, indicator: str | None = None) -> DetectorHit:
    return DetectorHit(
        technique_id=technique_id,
        technique_name=TECHNIQUE_NAMES.get(technique_id, "Unknown technique"),
        description=description,
        score=score,
        indicator=indicator,
    )


def _first_match(patterns: list[re.Pattern[str]], code: str) -> re.Pattern[str] | None:
    for pattern in patterns:
        if pattern.search(code):
            return pattern
    return None


def detect_autoexec(code: str) -> list[DetectorHit]:
    if AUTOEXEC_PATTERN.search(code):
        return [
            _make_hit(
                "T1204.002",
                "Autoexec VBA macro trigger detected.",
                20,
                "AutoOpen/Workbook_Open/Document_Open",
            )
        ]
    return []


def detect_suspicious_shell(code: str) -> list[DetectorHit]:
    pattern = _first_match(SHELL_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1059.005",
                "Suspicious shell or scripting host activity detected.",
                25,
                pattern.pattern,
            )
        ]
    return []


def detect_download_chain(code: str) -> list[DetectorHit]:
    matches = [pattern for pattern in DOWNLOAD_PATTERNS if pattern.search(code)]
    if matches:
        indicator = ", ".join(pattern.pattern for pattern in matches[:3])
        return [
            _make_hit(
                "T1105",
                "Download or external content retrieval behavior detected.",
                35,
                indicator,
            )
        ]
    return []


def detect_dynamic_execution(code: str) -> list[DetectorHit]:
    pattern = _first_match(EVAL_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1059.005",
                "Dynamic code evaluation detected (Eval/Execute/CallByName style).",
                20,
                pattern.pattern,
            )
        ]
    return []


def detect_file_write(code: str) -> list[DetectorHit]:
    pattern = _first_match(FILE_WRITE_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1105",
                "File write or payload staging capability detected.",
                10,
                pattern.pattern,
            )
        ]
    return []


def detect_registry_persistence(code: str) -> list[DetectorHit]:
    pattern = _first_match(REGISTRY_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1547.001",
                "Registry or startup persistence behavior detected.",
                20,
                pattern.pattern,
            )
        ]
    return []


def detect_environment_recon(code: str) -> list[DetectorHit]:
    pattern = _first_match(RECON_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1082",
                "Host or user environment reconnaissance detected.",
                5,
                pattern.pattern,
            )
        ]
    return []


def detect_sandbox_evasion(code: str) -> list[DetectorHit]:
    pattern = _first_match(EVASION_PATTERNS, code)
    if pattern:
        return [
            _make_hit(
                "T1497.003",
                "Time-based delay that may be sandbox evasion detected.",
                10,
                pattern.pattern,
            )
        ]
    return []


def run_behavior_detectors(code: str) -> list[DetectorHit]:
    """All content-based detectors (everything except autoexec and obfuscation).

    Safe to run over both the raw macro source and the decoded/recovered
    strings, so behavior hidden inside obfuscated payloads still scores.
    """
    hits: list[DetectorHit] = []
    hits.extend(detect_suspicious_shell(code))
    hits.extend(detect_download_chain(code))
    hits.extend(detect_dynamic_execution(code))
    hits.extend(detect_file_write(code))
    hits.extend(detect_registry_persistence(code))
    hits.extend(detect_environment_recon(code))
    hits.extend(detect_sandbox_evasion(code))
    return hits


def detect_obfuscation(code: str, recovered: list[str]) -> list[DetectorHit]:
    for pattern in OBFUSCATION_PATTERNS:
        if pattern.search(code):
            return [
                _make_hit(
                    "T1027",
                    "VBA obfuscation constructs detected.",
                    15,
                    pattern.pattern,
                )
            ]

    if recovered:
        return [
            _make_hit(
                "T1027",
                "Decoded obfuscated strings were recovered from the macro.",
                15,
                "; ".join(recovered[:3]),
            )
        ]

    return []


def find_iocs(code: str, recovered: list[str]) -> dict[str, list[str]]:
    urls = set(URL_PATTERN.findall(code))
    ips = set(match.group(0) for match in IP_PATTERN.finditer(code) if all(0 <= int(part) <= 255 for part in match.group(0).split('.')))

    for recovered_text in recovered:
        urls.update(URL_PATTERN.findall(recovered_text))
        ips.update(match.group(0) for match in IP_PATTERN.finditer(recovered_text) if all(0 <= int(part) <= 255 for part in match.group(0).split('.')))

    return {
        "urls": sorted(urls),
        "ips": sorted(ips),
    }


def collect_techniques(hits: Iterable[DetectorHit]) -> list[str]:
    unique = []
    for hit in hits:
        if hit.technique_id not in unique:
            unique.append(hit.technique_id)
    return unique
