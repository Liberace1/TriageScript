# AI Usage - TriageScript

This records where AI assistance was used in building TriageScript, what I
directed and decided myself, and how I verified the result.

The short version: this was a mixed build. I wrote the design spec
(`triagescript_spec.md`, kept in the repo) and made every call that shaped
the tool. I wrote parts of the code by hand and used an AI coding assistant
to scaffold others from the spec. Nothing shipped that I didn't run and
check myself.

## What was mine

- The problem choice, the spec, and the decision to narrow scope to VBA.
- The **zero-execution rule**: deobfuscation is pure data transformation, and
  there is deliberately no `eval`, `exec`, `subprocess`, or script-host call
  anywhere in the codebase. That guarantee shaped every module.
- The **transparent scoring model**: weighted, named contributions where every
  point traces to a plain-English reason, with download-and-execute as a hard
  escalator. Same DNA as the KEV escalator in TriageSBOM.
- Keeping the whole thing **offline and local**: no network calls, the web UI
  binds to 127.0.0.1 only, and the server is Python stdlib so the dependency
  surface stays at exactly one package (`oletools`).
- The synthetic, defanged `sample.docm`; the repo carries no live malware.
- All of the testing and verification described below.

## Where AI helped

- Scaffolding the pipeline modules (extraction, decoding, detectors, scoring,
  reporting) from the spec, which I then reviewed, adjusted, and tested.
- The boilerplate-heavy corners: the web UI's HTML/CSS and the minimal
  multipart upload parser.
- Implementing the v1.1 improvements (new detector families, the
  recovered-strings panel, scanning decoded content, corrected MITRE
  mappings), working from the list of changes I chose.

## How I verified it

- Ran the CLI and the web UI against `sample.docm` before and after the v1.1
  update and compared: same CRITICAL 95/100 verdict, now with corrected
  ATT&CK IDs, all reasons listed (the old CLI silently truncated to three),
  and the recovered-strings panel populated.
- Built synthetic VBA cases for each new detector: an eval call, a
  registry-persistence/recon/delay macro, a payload visible only after Chr()
  decoding, and a clean benign macro. Checked each verdict and reason. The
  benign macro scores LOW 0/100; the hidden payload scores HIGH via the
  decoded-content pass.
- Fetched the rendered web report and confirmed the new panel, the filter
  box, and the safety caveats actually appear on the page.
