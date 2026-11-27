# Automated Cloud & GitHub Secret Leak Scanner

An AppSec / DevSecOps tool built in Python to detect leaked secrets across local codebases, Git history, GitHub webhooks, and IaC files with risk scoring, redacted alerts, SQLite storage, and a FastAPI web dashboard.

## Setup & Installation

### 1. Clone the Repository (Linux / macOS / Windows)
```bash
git clone https://github.com/ramesh01324-dotcom/secret-leak-scanner.git
cd secret-leak-scanner
```

### 2. Virtual Environment & Dependencies

**Linux / macOS:**
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell):**
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

**Windows (CMD):**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
```

## Usage

### Run Scanner (Linux / macOS / Windows)
```bash
python scan.py .
python scan.py . --history --cloud
python scan.py --list
```

### Run Dashboard & Webhook Server (Linux / macOS / Windows)
```bash
uvicorn dashboard:app --reload --host 127.0.0.1 --port 8000
```
- Dashboard: http://127.0.0.1:8000
- API Docs: http://127.0.0.1:8000/docs
