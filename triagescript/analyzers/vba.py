from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from oletools.olevba import VBA_Parser

SUPPORTED_EXTENSIONS = {
    ".doc",
    ".docm",
    ".dotm",
    ".xls",
    ".xlsm",
    ".xltm",
    ".xlam",
    ".ppt",
    ".pptm",
    ".potm",
    ".ppam",
}


@dataclass
class MacroInfo:
    filename: str
    stream_path: str
    vba_filename: str
    code: str


@dataclass
class VbaExtractionResult:
    success: bool
    macros: list[MacroInfo]
    message: str


def extract_vba_macros(path: str | Path) -> VbaExtractionResult:
    file_path = Path(path)

    if not file_path.exists():
        return VbaExtractionResult(
            success=False,
            macros=[],
            message=f"Input file not found: {file_path}",
        )

    if not file_path.is_file():
        return VbaExtractionResult(
            success=False,
            macros=[],
            message=f"Input path is not a file: {file_path}",
        )

    extension = file_path.suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        return VbaExtractionResult(
            success=False,
            macros=[],
            message=(
                f"Unsupported file type '{extension}'. "
                "Expected an Office macro-enabled file such as .docm or .xlsm."
            ),
        )

    try:
        parser = VBA_Parser(str(file_path), relaxed=True, encoding="utf-8")
    except Exception as exc:
        return VbaExtractionResult(
            success=False,
            macros=[],
            message=f"Failed to initialize VBA parser: {exc}",
        )

    try:
        if parser.detect_is_encrypted():
            parser.close()
            return VbaExtractionResult(
                success=False,
                macros=[],
                message="The document contains encrypted or password-protected VBA content.",
            )

        if not parser.detect_macros():
            parser.close()
            return VbaExtractionResult(
                success=False,
                macros=[],
                message="No VBA macros were found in the document.",
            )

        parser.extract_all_macros()
        macros = [
            MacroInfo(filename=filename, stream_path=stream_path, vba_filename=vba_filename, code=vba_code)
            for filename, stream_path, vba_filename, vba_code in parser.modules
        ]
    except Exception as exc:
        parser.close()
        return VbaExtractionResult(
            success=False,
            macros=[],
            message=f"Failed to extract VBA macros: {exc}",
        )
    finally:
        parser.close()

    if not macros:
        return VbaExtractionResult(
            success=False,
            macros=[],
            message="No VBA macros were found in the document.",
        )

    return VbaExtractionResult(
        success=True,
        macros=macros,
        message="VBA extraction completed.",
    )
