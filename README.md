# TriageScript

A local VBA-macro triage tool for Office documents. Drop in a suspicious
`.docm` / `.xlsm` / `.doc` and get a plain-English "how dangerous is this and
why" verdict, the recovered IOCs, every string the macro was hiding, and the
MITRE ATT&CK techniques. It runs fully offline and **never executes the macro**.

The behavior detectors run twice: once over the raw macro source, and again
over the strings recovered from Chr() arrays, Base64 blobs, and split
literals, so a download command hidden inside an obfuscated payload still
scores, and the report tells you it was found in decoded content. Everything
the decoder recovers is shown in a searchable **Recovered strings** panel,
even when it didn't affect the score, so you can judge the leftovers
yourself.

## Run it (easiest: one command)

Open a terminal **in the `TriageScript` folder**, then:

**PowerShell:**

```powershell
.\start.ps1
```

If PowerShell blocks the script, run it this way instead:
`powershell -ExecutionPolicy Bypass -File .\start.ps1`

**Git Bash / Linux / macOS:**

```bash
./start.sh
```

Either launcher finds Python, installs dependencies on the first run, starts the
server, and opens your browser at **http://127.0.0.1:8742**. Click
**Try sample.docm** to see it work, or drag your own file onto the page. Press
**Ctrl+C** to stop. (Add `--port 9000` if 8742 is busy.)

## Run it manually

From the `TriageScript` folder. First time only, create a virtual environment
and install dependencies:

```bash
python -m venv .venv
# activate it:
#   PowerShell:   .venv\Scripts\Activate.ps1
#   Git Bash:     source .venv/Scripts/activate
#   Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

Then run:

```bash
python -m triagescript.web            # web UI (opens the browser)
python -m triagescript.cli sample.docm   # command line
```

## What it looks for

Auto-run triggers (`AutoOpen`, `Document_Open`, …), shell and scripting-host
calls, download-and-execute chains, dynamic code evaluation
(`Eval`/`Execute`/`CallByName`), file drops, registry-run-key persistence,
host/user reconnaissance, sandbox-evasion delays, and obfuscation constructs.
Each hit adds a weighted, named reason to the score and maps to a MITRE ATT&CK
technique; nothing contributes to the verdict without showing up in the "Why"
list.

## Limitations: read this before trusting a LOW

Detection is **pattern-based**. The rules cover the common tradecraft in
macro malware, but a novel VBA trick or an obfuscation scheme the decoder
doesn't unroll can slip through unflagged. That cuts one way: a HIGH or
CRITICAL verdict is evidence, but a **LOW verdict is not proof the document is
safe**. It only means nothing known matched. That's exactly why the report
shows *all* recovered strings rather than only the ones that scored: if the
rules missed something, it's still on the screen for you to catch.

TriageScript is a first-look triage tool, not a sandbox or a classifier. Use it
to decide what to escalate, not to clear files.

## AI usage

Parts of this tool were built with an AI coding assistant working from my
design spec (`triagescript_spec.md`, kept in the repo deliberately). What was
mine, what was AI-assisted, and how everything was verified is written up in
[AI_USAGE.md](AI_USAGE.md).
