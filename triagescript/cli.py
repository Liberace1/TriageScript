from __future__ import annotations

import argparse
import sys

from triagescript.analyzer import analyze_vba_file


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze Office VBA macros and report a transparent verdict.")
    parser.add_argument("file", help="Path to a .docm, .xlsm, or similar Office document")
    args = parser.parse_args()

    result = analyze_vba_file(args.file)
    if not result.success:
        print(f"TriageScript error: {result.message}", file=sys.stderr)
        return 2

    print(f"TriageScript verdict: {result.verdict} ({result.score}/{result.max_score})")
    print(f"File: {result.filename} (VBA)")
    print()
    print("Why:")
    if result.contributions:
        for hit in result.contributions[:3]:
            indicator = f" [{hit.indicator}]" if hit.indicator else ""
            print(f"  [+] {hit.description}{indicator}")
    else:
        print("  [ ] No suspicious indicators detected.")

    if result.iocs and (result.iocs.get("urls") or result.iocs.get("ips")):
        print()
        print("Recovered IOCs:")
        for url in result.iocs.get("urls", []):
            print(f"  url   {url}")
        for ip in result.iocs.get("ips", []):
            print(f"  ip    {ip}")

    if result.techniques:
        print()
        print("ATT&CK: " + ", ".join(result.techniques))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
