from __future__ import annotations

import base64
import re
from typing import Iterable

_CHR_SEQUENCE_PATTERN = re.compile(r'(?:Chr(?:W)?\(\s*\d+\s*\)\s*(?:&\s*)?)+', re.I)
_CHR_LITERAL_PATTERN = re.compile(r'Chr(?:W)?\(\s*(\d+)\s*\)', re.I)
_STR_REVERSE_PATTERN = re.compile(r'StrReverse\(\s*"([^"]*)"\s*\)', re.I)
_BASE64_LITERAL_PATTERN = re.compile(r'"([A-Za-z0-9+/=]{16,})"')
_STRING_CONCAT_PATTERN = re.compile(r'"([^"]*)"\s*&\s*"([^"]*)"', re.I)
_STRING_LITERAL_PATTERN = re.compile(r'"([^"]*)"')


def normalize_vba_code(code: str) -> str:
    lines = [line.rstrip() for line in code.splitlines()]
    normalized_lines: list[str] = []
    pending = ""

    for line in lines:
        if line.strip().endswith("_"):
            pending += line.rstrip()[:-1].rstrip()
        else:
            normalized_lines.append(pending + line)
            pending = ""

    if pending:
        normalized_lines.append(pending)

    return "\n".join(normalized_lines)


def decode_chr_sequences(code: str) -> list[str]:
    decoded: set[str] = set()

    for block in _CHR_SEQUENCE_PATTERN.findall(code):
        digits = _CHR_LITERAL_PATTERN.findall(block)
        if len(digits) < 2:
            continue

        try:
            text = "".join(chr(int(value)) for value in digits if 0 <= int(value) <= 0x10FFFF)
        except ValueError:
            continue

        if text:
            decoded.add(text)

    return sorted(decoded)


def decode_reversed_strings(code: str) -> list[str]:
    return [data[::-1] for data in _STR_REVERSE_PATTERN.findall(code)]


def decode_concatenated_literals(code: str) -> list[str]:
    normalized = code
    decoded: set[str] = set()

    while True:
        normalized, count = _STRING_CONCAT_PATTERN.subn(lambda m: f'"{m.group(1)+m.group(2)}"', normalized)
        if count == 0:
            break

    for literal in _STRING_LITERAL_PATTERN.findall(normalized):
        if len(literal) > 1:
            decoded.add(literal)

    return sorted(decoded)


def decode_base64_literals(code: str) -> list[str]:
    decoded: set[str] = set()

    for literal in _BASE64_LITERAL_PATTERN.findall(code):
        if len(literal) % 4 != 0:
            continue

        try:
            payload = base64.b64decode(literal, validate=True)
            if not payload:
                continue
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            continue

        if text.strip():
            decoded.add(text)

    return sorted(decoded)


def extract_recovered_strings(code: str) -> list[str]:
    results: set[str] = set()
    results.update(decode_chr_sequences(code))
    results.update(decode_reversed_strings(code))
    results.update(decode_concatenated_literals(code))
    results.update(decode_base64_literals(code))
    return sorted(value for value in results if value.strip())
