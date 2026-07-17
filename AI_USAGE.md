# AI Usage — TriageScript

Peer review on Tool 3 fairly pointed out that the repo didn't say where AI was
used — `triagescript_spec.md` sits right there looking like a prompt, with no
explanation. So here it is, same spirit as the TriageSBOM write-up: what I
directed and decided, where an AI assistant helped, and how I verified the
result.

The short version: this was a mixed build. I designed the tool, wrote the spec,
and made every call that shaped it; I wrote parts of the code by hand and used
an AI coding assistant to scaffold others from the spec. Nothing shipped that I
didn't run and check myself.

## The spec came first

`triagescript_spec.md` is my design document, and I left it in the repo on
purpose — it's the honest record of what I asked for, from both myself and the
assistant. It's also where the most important decision of the project is
visible: the original plan covered PowerShell, JavaScript, *and* VBA analyzers.
Partway through I cut that to Office VBA macros only, because three half-deep
analyzers in one course cycle would have made a worse tool than one deep one —
and macro-laden Office documents are what actually lands in a phishing queue.
The tail end of the spec still shows that scoping conversation.

## What was mine

- The problem choice, the spec, and the decision to narrow scope to VBA.
- The **zero-execution rule** — deobfuscation is pure data transformation, and
  there is deliberately no `eval`, `exec`, `subprocess`, or script-host call
  anywhere in the codebase. That guarantee shaped every module.
- The **transparent scoring model**: weighted, named contributions where every
  point traces to a plain-English reason, with download-and-execute as a hard
  escalator — the same DNA as the KEV escalator in TriageSBOM.
- Keeping the whole thing **offline and local**: no network calls, the web UI
  binds to 127.0.0.1 only, and the server is Python stdlib so the dependency
  surface stays at exactly one package (`oletools`).
- The synthetic, defanged `sample.docm` — the repo carries no live malware.
- All of the testing and verification described below.

## Where AI helped

- Scaffolding the pipeline modules (extraction, decoding, detectors, scoring,
  reporting) from the spec, which I then reviewed, adjusted, and tested.
- The boilerplate-heavy corners: the web UI's HTML/CSS and the minimal
  multipart upload parser.
- Implementing the peer-feedback round below, working from the list of fixes I
  chose.

## The peer-feedback round (v1.1)

Three classmates reviewed the tool, and their feedback drove a real update —
credit where due:

- **Jabree Ellis** ran a genuine MalwareBazaar maldoc through it and caught an
  `eval` string the results never showed. Two fixes came out of that: a new
  dynamic-code-evaluation detector (`Eval` / `Execute` / `CallByName` /
  `ExecuteExcel4Macro` / `ScriptControl`), and the behavior detectors now run a
  second pass over everything the decoder recovers, so a command hidden inside
  an obfuscated payload still scores (labeled "found in decoded content").
- **Andrew Salazar** asked for a way to see *all* recovered strings, not just
  the scoring ones, and warned that a low score shouldn't read as "safe." Both
  landed: the report now has a searchable **Recovered strings** panel, and the
  LOW verdict, the page footer, the CLI, and the README all now say plainly
  that pattern-based detection means LOW is not proof of safety.
- **Thomas Williams** asked where AI was used — this document is the answer.

While making those changes I also caught and corrected two MITRE mappings that
were simply wrong (`T1059.007` is JavaScript, not Visual Basic — the right ID
is `T1059.005`; and auto-run macros map to `T1204.002` User Execution, not
`T1546.001`), added detector families for file drops, registry-run-key
persistence, host recon, and sandbox-evasion delays, and fixed a false-positive
source where any macro containing an ordinary string literal was scored as
"obfuscated." A plain benign macro now scores 0.

## How I verified it

- Ran the CLI and the web UI against `sample.docm` before and after the update
  and compared: same CRITICAL 95/100 verdict, now with corrected ATT&CK IDs,
  all reasons listed (the old CLI silently truncated to three), and the
  recovered-strings panel populated.
- Built synthetic VBA cases for each new detector — an eval call, a
  registry-persistence/recon/delay macro, a payload visible only after Chr()
  decoding, and a clean benign macro — and checked each verdict and reason. The
  benign macro scores LOW 0/100; the hidden payload scores HIGH via the
  decoded-content pass.
- Fetched the rendered web report and confirmed the new panel, the filter box,
  and the safety caveats actually appear on the page.
