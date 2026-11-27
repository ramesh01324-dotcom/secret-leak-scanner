import hashlib
import hmac
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from fastapi import FastAPI, Form, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from scanner.detector import SecretDetector
from scan import scan_git_history, scan_working_directory
from storage.db import FindingsDB

app = FastAPI(title="Secret Leak Scanner Dashboard")
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = str(BASE_DIR / "scanner.db")
RULES_PATH = str(BASE_DIR / "config" / "rules.yaml")
WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET", "dev-secret")


def verify_github_signature(raw_body: bytes, signature_header: str | None) -> bool:
    if not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(
        WEBHOOK_SECRET.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, signature_header)


@app.get("/", response_class=HTMLResponse)
def index(request: Request, status: str | None = None):
    db = FindingsDB(DB_PATH)
    all_items = db.list_findings()
    items = db.list_findings(status=status if status in {"open", "resolved", "false_positive"} else None)

    total = len(all_items)
    open_count = sum(1 for x in all_items if x["status"] == "open")
    critical_count = sum(1 for x in all_items if x["severity"] == "critical" and x["status"] == "open")
    resolved_count = sum(1 for x in all_items if x["status"] == "resolved")

    rows_html = ""
    for item in items:
        badge_color = "#dc2626" if item["severity"] == "critical" else "#d97706"
        rows_html += f"""
        <tr>
          <td>#{item["id"]}</td>
          <td><span style="background:{badge_color};color:#fff;padding:2px 8px;border-radius:6px;font-size:12px;">{item["severity"].upper()}</span></td>
          <td><strong>{item["rule_id"]}</strong><br><small>{item["description"]}</small></td>
          <td><code>{item["file_path"]}:{item["line_number"]}</code><br><small>commit: {item["commit_sha"]}</small></td>
          <td><code>{item["masked_secret"]}</code><br><small>entropy: {item["entropy"]}</small></td>
          <td><strong>{item["status"]}</strong></td>
          <td>
            <form method="post" action="/findings/{item["id"]}/status" style="display:flex;gap:6px;">
              <select name="status" style="padding:4px;border-radius:4px;">
                <option value="open" {"selected" if item["status"]=="open" else ""}>open</option>
                <option value="resolved" {"selected" if item["status"]=="resolved" else ""}>resolved</option>
                <option value="false_positive" {"selected" if item["status"]=="false_positive" else ""}>false_positive</option>
              </select>
              <button type="submit" style="padding:4px 10px;cursor:pointer;">Save</button>
            </form>
          </td>
        </tr>
        """

    if not rows_html:
        rows_html = "<tr><td colspan=7 style=text-align:center;padding:20px;>No findings match this filter.</td></tr>"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <title>Secret Leak Scanner - AppSec Dashboard</title>
      <style>
        body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e2e8f0; margin: 0; padding: 24px; }}
        .cards {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
        .card {{ background: #1e293b; padding: 16px 20px; border-radius: 10px; min-width: 170px; }}
        .card h3 {{ margin: 0 0 8px 0; font-size: 13px; color: #94a3b8; }}
        .card p {{ margin: 0; font-size: 28px; font-weight: bold; }}
        .filters {{ margin-bottom: 16px; display: flex; gap: 10px; }}
        .filters a {{ color: #93c5fd; text-decoration: none; background: #1e293b; padding: 6px 12px; border-radius: 6px; }}
        table {{ width: 100%; border-collapse: collapse; background: #1e293b; border-radius: 10px; overflow: hidden; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #334155; }}
        th {{ background: #0f172a; color: #94a3b8; font-size: 13px; }}
      </style>
    </head>
    <body>
      <h1>Secret Leak Scanner — AppSec Dashboard</h1>
      <div class="cards">
        <div class="card"><h3>Total Findings</h3><p>{total}</p></div>
        <div class="card"><h3>Open Leaks</h3><p style="color:#f87171;">{open_count}</p></div>
        <div class="card"><h3>Open Critical</h3><p style="color:#ef4444;">{critical_count}</p></div>
        <div class="card"><h3>Resolved</h3><p style="color:#4ade80;">{resolved_count}</p></div>
      </div>
      <div class="filters">
        <a href="/">All</a>
        <a href="/?status=open">Open</a>
        <a href="/?status=resolved">Resolved</a>
        <a href="/?status=false_positive">False Positive</a>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Severity</th><th>Rule</th><th>Location</th><th>Secret & Entropy</th><th>Status</th><th>Action</th>
          </tr>
        </thead>
        <tbody>{rows_html}</tbody>
      </table>
    </body>
    </html>
    """
    return HTMLResponse(content=html)


@app.post("/findings/{{finding_id}}/status")
def update_status(finding_id: int, status: str = Form(...)):
    if status in {"open", "resolved", "false_positive"}:
        db = FindingsDB(DB_PATH)
        with db._connect() as conn:
            conn.execute("UPDATE findings SET status = ? WHERE id = ?", (status, finding_id))
            conn.commit()
    return RedirectResponse(url="/", status_code=303)


@app.post("/webhooks/github")
async def github_webhook(
    request: Request,
    x_hub_signature_256: str | None = Header(default=None),
    x_github_event: str | None = Header(default="push"),
):
    raw_body = await request.body()
    if not verify_github_signature(raw_body, x_hub_signature_256):
        raise HTTPException(status_code=401, detail="Invalid webhook signature")

    payload = await request.json()
    repo_info = payload.get("repository", {})
    clone_url = repo_info.get("clone_url") or repo_info.get("html_url")
    repo_full_name = repo_info.get("full_name", "unknown-repo")

    if not clone_url:
        return {"status": "ignored", "reason": "no repository clone_url in payload"}

    detector = SecretDetector(RULES_PATH)
    db = FindingsDB(DB_PATH)
    temp_dir = tempfile.mkdtemp(prefix="gh_scan_")

    try:
        if Path(clone_url).exists():
            shutil.copytree(clone_url, temp_dir, dirs_exist_ok=True)
        else:
            subprocess.run(
                ["git", "clone", "--depth", "15", clone_url, temp_dir],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=60,
            )
        target_path = Path(temp_dir)
        results = scan_working_directory(target_path, detector)
        results.extend(scan_git_history(target_path, detector))
        unique_results = list({item["fingerprint"]: item for item in results}.values())
        new_count = db.save_findings(unique_results, f"github:{repo_full_name}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

    return {
        "status": "scanned",
        "event": x_github_event,
        "repository": repo_full_name,
        "total_unique_findings": len(unique_results),
        "newly_saved_to_db": new_count,
    }
