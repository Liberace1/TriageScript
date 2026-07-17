# TriageScript - Design Spec

**Course:** CSC-842 Security Tool Development
**Theme:** Reverse Engineering & Adversary Tradecraft
**Portfolio:** Triage family (TriageIQ, TriageSBOM, TriageScript)
**Language:** Python
**End user:** SOC analyst triaging a suspicious Office document from a phishing report or EDR alert

## Pitch

TriageScript takes a macro-enabled Office document, extracts the VBA without
ever running it, unrolls the common obfuscation tricks, and returns a
transparent "how dangerous is this and why" verdict with recovered IOCs and
MITRE ATT&CK techniques. Usable in under a minute, fully offline.

## Problem

Macro-laden Office documents are a dominant phishing payload. An analyst who
receives one has three bad options: upload it to an online sandbox (slow, and
the sample may be sensitive), read the obfuscated VBA by hand (slow,
error-prone), or open it (dangerous). TriageScript is the fourth option: a
local, zero-execution first look that says what the macro is hiding and what
to escalate.

Scope note: the original plan covered PowerShell, JavaScript, and VBA
analyzers. It was cut to Office VBA only, because one deep analyzer beats
three shallow ones in a single course cycle.

## Design principles

1. **Offline-first.** No network calls, no API keys, nothing leaves the box.
2. **Zero execution.** Deobfuscation is pure data transformation. No `eval`,
   `exec`, `subprocess`, or script-host call anywhere in the codebase.
3. **Transparent scoring.** Every point traces to a named, plain-English
   reason. No black-box verdict.
4. **Analyst-shaped output.** Verdict, reasons, IOCs, recovered strings, and
   techniques. Not an AST dump.

## Pipeline

```
document -> extract VBA (olevba, read-only)
         -> normalize (line continuations)
         -> decode (Chr() arrays, StrReverse, split literals, Base64)
         -> detect (raw source AND decoded strings)
         -> score -> report (CLI or local web UI)
```

Running the detectors over the decoded strings as well as the raw source is
the point: behavior hidden inside an obfuscated payload still scores, and the
report labels it as found in decoded content.

## Detections and scoring

| Behavior | Weight | ATT&CK |
|----------|-------:|--------|
| Download / external content retrieval | 35 | T1105 |
| Shell or scripting-host activity | 25 | T1059.005 |
| Autoexec trigger (AutoOpen, Document_Open, ...) | 20 | T1204.002 |
| Dynamic code evaluation (Eval, Execute, CallByName) | 20 | T1059.005 |
| Registry / startup persistence | 20 | T1547.001 |
| Obfuscation constructs or decoded payloads | 15 | T1027 |
| File write / payload staging | 10 | T1105 |
| Time-based sandbox evasion | 10 | T1497.003 |
| Host or user recon | 5 | T1082 |

Scores are additive, capped at 100. A download chain is a hard escalator that
floors the total at 45 (HIGH), so a quiet-looking downloader can't score LOW.
Verdict bands: LOW under 25, MEDIUM 25-44, HIGH 45-69, CRITICAL 70+.

Detection is pattern-based, so a LOW verdict is not proof of safety. To
compensate, the report shows every recovered and decoded string, scoring or
not, so the analyst can catch what the rules missed.

## Output

- **CLI:** `python -m triagescript.cli file.docm` prints the verdict, every
  scoring reason, IOCs, recovered strings, and technique IDs.
- **Web UI:** `python -m triagescript.web` serves a drag-and-drop page on
  127.0.0.1 only, Python stdlib server, no added dependencies. Includes a
  bundled synthetic sample for a one-click demo.

## Safety

Defensive tool only. It analyzes and explains; it never executes the macro.
The bundled `sample.docm` is synthetic and defanged. The repo carries no live
malware.

## Dependencies

`oletools` (read-only macro extraction). Everything else is Python stdlib.
