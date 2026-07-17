# AI Usage - TriageScript

This records where AI assistance was used in building TriageScript, what I
directed and decided myself, and how I verified the result. The repo includes
`triagescript_spec.md`, which can read like an unexplained AI prompt, so this
file also explains what that is.

The short version: this was a mixed build. I designed the tool, wrote the
spec, and made every call that shaped it. I wrote parts of the code by hand
and used an AI coding assistant to scaffold others from the spec. Nothing
shipped that I didn't run and check myself.

## The spec came first

`triagescript_spec.md` is my design document, and I left it in the repo on
purpose. It is the honest record of what I asked for, from both myself and
the assistant. It is also where the most important decision of the project is
visible: the original plan covered PowerShell, JavaScript, and VBA analyzers.
Partway through I cut that down to Office VBA macros only, because three
half-deep analyzers in one course cycle would have made a worse tool than one
deep one, and macro-laden Office documents are what actually lands in a
phishing queue. The tail end of the spec still shows that scoping
conversation.

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

## What the prompting actually looked like

The spec was the master prompt: I wrote it, handed it to the assistant, and
asked for one working slice at a time. The steering in between happened in
short, plain messages. Two real ones, typos and all:

> "lets just focus on excle macros then"

That single line is the scope cut that turned a three-language plan into one
deep VBA tool. The exchange it kicked off is still preserved at the tail of
`triagescript_spec.md`.

> "lets fix all then, for the ai prmpt documentaiton, check the way we did it
> in tool2 and tool 1, humanize the wordings, dont sound robotic"

That one produced the v1.1 update and this very document. The pattern was the
same throughout: the assistant proposes and drafts, I decide what ships and
how it sounds.

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
