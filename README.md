# TriageScript

A local VBA-macro triage tool for Office documents. Drop in a suspicious
`.docm` / `.xlsm` / `.doc` and get a plain-English "how dangerous is this and
why" verdict, the recovered IOCs, and the MITRE ATT&CK techniques. It runs fully
offline and **never executes the macro**.

## Run it (easiest — one command)

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

From the `TriageScript` folder. First time only — create a virtual environment
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
