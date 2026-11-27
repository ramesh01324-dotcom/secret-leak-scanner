# Automated Cloud & GitHub Secret Leak Scanner

An AppSec / DevSecOps tool built in Python to detect leaked secrets across local codebases, Git history, GitHub webhooks, and IaC files with risk scoring, redacted alerts, SQLite storage, and a FastAPI web dashboard.

## Setup
1. Create and activate virtual environment (`python3 -m venv venv && source venv/bin/activate`)
2. Install dependencies (`pip install -r requirements.txt`)

## Usage
- Scan repo: `python scan.py /path/to/repo --history --cloud`
- List saved findings: `python scan.py --list`
- Run dashboard & webhook API: `uvicorn dashboard:app --reload --host 127.0.0.1 --port 8000`
