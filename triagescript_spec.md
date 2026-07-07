# TriageScript — Tool 3 Specification

**Course:** CSC-842 Security Tool Development
**Theme:** Reverse Engineering & Adversary Tradecraft
**Portfolio:** Triage family (TriageIQ, TriageSBOM, TriageScript)
**Primary language:** Python
**End user:** SOC analyst triaging a suspicious script pulled from an email, EDR alert, or phishing sample

---

## 1. One-line pitch

TriageScript takes a suspicious script (PowerShell, JavaScript/WSH, or Office VBA macro), peels back its obfuscation layers using only safe static decoding, maps the revealed behavior to MITRE ATT&CK techniques, and outputs a transparent weighted "how dangerous is this and why" verdict an analyst can act on in under a minute.

## 2. The problem it solves

Script-based malware is the dominant initial-access vector. A SOC analyst who gets a suspicious `.ps1`, `.js`, or macro-laden `.docm` faces a wall of base64 blobs, char-code arrays, and string concatenation built specifically to hide what the script does. The analyst's choices today are bad: paste it into an online sandbox (data exposure, slow, sometimes the sample is sensitive), read it by hand (slow, error-prone), or run it (dangerous). TriageScript gives a fourth option — a local, zero-execution triage that unrolls the obfuscation and explains the verdict.

## 3. What makes it distinct (vs. the rest of the portfolio and the cohort)

- **vs. TriageIQ:** TriageIQ finds indicators that are already visible in an alert. TriageScript *reveals* hidden indicators by unrolling obfuscation first. The deobfuscation engine is the novel core, not the indicator extraction.
- **vs. TriageSBOM:** Different input (live script vs. SBOM), different enrichment (technique mapping vs. CVE/EPSS/KEV), but the same transparent-weighted-scoring DNA.
- **vs. cohort:** Joel Austin (BOF injection detector) and David Garner (Mem-Triage) work at the binary/memory layer. TriageScript works at the source-script layer — a different artifact entirely. No overlap.

## 4. Design principles (carried from the Triage family)

1. **Offline-first, no API keys.** Runs on any analyst box. No network calls in the default path.
2. **Zero execution.** Deobfuscation is pure data transformation (base64, gzip/zlib/deflate, hex, XOR with recovered/brute-forced single-byte keys, char-code and format-string reassembly). The tool NEVER calls `eval`, `Invoke-Expression`, `subprocess`, a JS engine, or a VBA host. This is a hard safety guarantee and a selling point.
3. **Transparent scoring.** Every point in the risk score traces to a named, plain-English reason. No black-box verdict.
4. **Analyst-shaped output.** The default output is a short verdict with the top reasons, the recovered IOCs, and the ATT&CK techniques — not a developer-style AST dump.

## 5. Architecture

A language-agnostic **core** with pluggable **per-language analyzers**. This is what keeps three languages buildable in one cycle: each analyzer only handles its own obfuscation grammar and feeds normalized findings into one shared engine.

```
                ┌─────────────────────────────────────────┐
   input file ──►   Language router (detect PS / JS / VBA) │
                └───────────────┬─────────────────────────┘
                                │
            ┌───────────────────┼───────────────────┐
            ▼                   ▼                   ▼
     PowerShell analyzer   JS/WSH analyzer     VBA analyzer
     (deep / polished)     (functional)        (functional)
            │                   │                   │
            └───────────────────┼───────────────────┘
                                ▼
                   ┌────────────────────────────┐
                   │ Decode engine (shared)     │  base64, gzip/zlib,
                   │ iterative, depth-capped    │  hex, XOR, char-codes,
                   └─────────────┬──────────────┘  string reassembly
                                 ▼
                   ┌────────────────────────────┐
                   │ Behavior detectors (rules) │  pattern → technique
                   └─────────────┬──────────────┘
                                 ▼
                   ┌────────────────────────────┐
                   │ ATT&CK mapper              │  technique IDs + names
                   └─────────────┬──────────────┘
                                 ▼
                   ┌────────────────────────────┐
                   │ Transparent scorer         │  weighted, explainable
                   └─────────────┬──────────────┘
                                 ▼
                   ┌────────────────────────────┐
                   │ Reporter (CLI / JSON / MD) │
                   └────────────────────────────┘
```

### Module breakdown

| Module | Responsibility |
|--------|----------------|
| `router.py` | Detect language from extension + content sniff; dispatch to analyzer. |
| `analyzers/powershell.py` | Strip PS-specific obfuscation: backtick escapes, `-join`/`-f` format strings, `[char]` arrays, `[Convert]::FromBase64String`, `IEX` chains, env-var splicing, case randomization. **Deep path.** |
| `analyzers/javascript.py` | Strip JS/WSH obfuscation: `String.fromCharCode`, hex/unicode escapes, `unescape`, concatenation chains, `eval`/`Function` wrappers (detected, never run), `ActiveXObject` usage. **Functional path.** |
| `analyzers/vba.py` | Extract macros from Office files (use `oletools`/`olevba` — read-only parsing), strip `Chr()` arrays, `StrReverse`, concatenation, `Shell`/`WScript` calls, autoexec triggers (`AutoOpen`, `Document_Open`). **Functional path.** |
| `decode.py` | Shared iterative decoder. Tries each transform, recurses on decoded output up to a depth cap, records every layer for the report. |
| `detectors.py` | Rule set mapping recovered patterns to behaviors (download-and-execute, credential access, persistence, AMSI bypass, defense evasion, C2 beacon). |
| `attack_map.py` | Map each detector hit to ATT&CK technique ID + name. Bundled offline copy of the technique subset used (no live API). |
| `scorer.py` | Transparent weighted score; each contribution carries a human-readable reason. |
| `report.py` | CLI table (default), `--json`, and `--md` outputs. |
| `cli.py` | Entry point. |

## 6. Scoring model (transparent, weighted)

Score is a sum of weighted, named contributions. Each appears in the report with its reason.

| Signal | Example weight | Rationale |
|--------|---------------|-----------|
| AMSI / ETW bypass present | High (hard escalator) | Almost never benign; defense evasion. |
| Download-and-execute chain | High | `IWR`/`DownloadString` + `IEX`, or `XMLHTTP` + `Run`. |
| Heavy multi-layer obfuscation | Medium (scales with layer depth) | Benign scripts rarely nest base64-in-gzip-in-XOR. |
| Credential-access API calls | Medium | LSASS, DPAPI, keyword scraping. |
| Persistence mechanism | Medium | Run keys, scheduled task, startup folder, WMI sub. |
| Suspicious network IOC recovered | Medium | IP/domain/URL surfaced only after deobfuscation. |
| Autoexec macro trigger (VBA) | Medium | `AutoOpen`/`Document_Open` = runs on file open. |
| Known-bad string / signature hit | Low–Medium | Optional local signature list. |

**Hard-escalator rule (mirrors KEV in TriageSBOM):** an AMSI bypass or a confirmed download-and-execute chain floors the verdict at HIGH regardless of other signals. Keeps the analyst from under-reacting to a quiet-looking but lethal script.

Verdict bands: `LOW` / `MEDIUM` / `HIGH` / `CRITICAL`, each with the top 3 contributing reasons shown.

## 7. Output (analyst-shaped)

Default CLI verdict block:

```
TriageScript verdict: HIGH (score 78/100)
File: invoice_macro.docm  (VBA)

Why:
  [+] AMSI bypass detected                    (T1562.001 Impair Defenses)
  [+] Download-and-execute chain recovered     (T1059.001 / T1105)
  [+] 3 obfuscation layers unrolled (b64→gzip→char-array)

Recovered IOCs:
  url   hxxp://185.x.x.x/payload.dll
  ip    185.x.x.x

ATT&CK: T1059.001, T1562.001, T1105, T1547.001
Run with --md for full layer-by-layer deobfuscation trace.
```

`--json` for piping into TriageIQ or a SIEM. `--md` for an attach-to-ticket report with the full decode trace.

## 8. Vertical-slice build plan (one cycle)

Ship a working end-to-end path first, then widen. Do NOT build three analyzers to 100% in parallel.

**Slice 1 — end-to-end on one PowerShell sample.** Router → PS analyzer (base64 + IEX only) → decode → one detector (download-and-execute) → scorer → CLI verdict. Prove the whole pipe works on one real-world-style sample.

**Slice 2 — deepen PowerShell.** Add char-array, `-join`/`-f`, AMSI-bypass detection, multi-layer recursive decode, the full PS detector set, ATT&CK mapping, `--json`/`--md`.

**Slice 3 — add JavaScript analyzer.** Reuse the shared decode engine; add JS-specific de-obfuscation and detectors.

**Slice 4 — add VBA analyzer.** `olevba` extraction (read-only), VBA de-obfuscation, autoexec-trigger detector.

**Slice 5 — polish for demo/peer-review.** Fixtures, README, sample corpus, edge-case handling, `setup.sh`/`setup.ps1` (carry the startup-script lesson from TriageSBOM peer review).

If time runs short, JS and VBA can ship as "functional, PS is the deep path" — the demo leads on PowerShell.

## 9. Test corpus (bundled, offline)

Hand-built **defanged** samples — synthetic, never live malware — covering: clean benign scripts (must score LOW, guards against false positives), single-layer base64, multi-layer nested encoding, AMSI bypass, download-cradle, a benign-but-heavily-obfuscated script (the hard false-positive case), and one VBA autoexec macro. URLs/IPs use `hxxp`/placeholder octets so the corpus is safe to commit.

## 10. Safety & ethics notes (for docs and video)

- TriageScript is **defensive**: it analyzes and explains, it does not generate, pack, or execute malicious code.
- Zero-execution guarantee stated explicitly in the README — auditors can confirm there is no `eval`/`exec`/`subprocess`/script-host call in the codebase.
- Bundled samples are synthetic and defanged; the repo carries no live malware.

## 11. Dependencies

- `oletools` (olevba) — read-only Office macro extraction.
- Python stdlib for the rest (base64, zlib, gzip, re, binascii). Keep the dependency surface tiny for reproducibility and to honor offline-first.
- **Do not** introduce Trivy or any tool flagged in prior course work.

## 12. Repo structure

```
TriageScript/
├── README.md
├── requirements.txt
├── setup.sh / setup.ps1
├── triagescript/
│   ├── cli.py
│   ├── router.py
│   ├── decode.py
│   ├── detectors.py
│   ├── attack_map.py
│   ├── scorer.py
│   ├── report.py
│   └── analyzers/
│       ├── powershell.py
│       ├── javascript.py
│       └── vba.py
├── data/
│   └── attack_subset.json
├── samples/          # synthetic, defanged
└── tests/
```

## 13. Peer-review differentiation talking points

- Only tool in the cohort that **unrolls obfuscation** rather than pattern-matching raw text.
- **Zero-execution** static analysis — safe to run on any sensitive sample, no sandbox, no data leaving the box.
- Transparent scoring with ATT&CK mapping — the analyst sees *why*, not just *what*.
- Coherent with TriageIQ/TriageSBOM as a portfolio (`--json` output feeds TriageIQ).

lets just focus on excle macros then

Smart narrowing — going VBA-only makes this far stronger than three half-built analyzers, and Office macros are exactly what lands in SOC queues from phishing. But let me pressure-test the scope before re-speccing, because narrowing changes the risk picture:

The good: Single-language depth means you can actually go deep — full olevba extraction, autoexec trigger analysis, the real obfuscation tricks (Chr arrays, StrReverse, string-splitting, form-property hiding). That's a more impressive demo than a shallow three-language tool.

The theme-fit check: VBA-only is still solidly "Reverse Engineering & Adversary Tradecraft" — macro analysis is classic malware RE, and the deobfuscation core carries the weight. No problem there.

One real risk: "Excel macros" specifically vs. "Office macros" broadly. VBA is shared across Excel/Word/PowerPoint — the same engine parses all of them via olevba. If you scope to only .xlsm/.xls, you're artificially narrowing for no technical gain, since covering Word .docm too is nearly free and Word macros are more common in phishing. I'd suggest Office VBA macros, demoed on Excel rather than Excel-only..