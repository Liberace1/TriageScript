from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from triagescript.attack_map import TECHNIQUE_NAMES
from triagescript.decode import extract_recovered_strings


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


def detect_autoexec(code: str) -> list[DetectorHit]:
    if AUTOEXEC_PATTERN.search(code):
        return [
            _make_hit(
                "T1546.001",
                "Autoexec VBA macro trigger detected.",
                20,
                "AutoOpen/Workbook_Open/Document_Open",
            )
        ]
    return []


def detect_suspicious_shell(code: str) -> list[DetectorHit]:
    for pattern in SHELL_PATTERNS:
        if pattern.search(code):
            return [
                _make_hit(
                    "T1059.007",
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
