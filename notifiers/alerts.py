import json
import os
import requests


def calculate_risk_score(finding: dict) -> int:
    severity_base = {
        "critical": 80,
        "high": 60,
        "medium": 40,
        "low": 20,
    }.get(str(finding.get("severity", "medium")).lower(), 30)

    entropy = float(finding.get("entropy", 0.0))
    entropy_bonus = 10 if entropy >= 4.5 else (5 if entropy >= 3.5 else 0)

    file_path = str(finding.get("file", "")).lower()
    context_bonus = 10 if any(k in file_path for k in ("prod", ".env", "main.tf", "secret", "auth")) else 0

    return min(100, severity_base + entropy_bonus + context_bonus)


def send_redacted_alert(finding: dict, target_path: str) -> None:
    score = calculate_risk_score(finding)
    summary = {
        "severity": finding.get("severity"),
        "risk_score": score,
        "rule_id": finding.get("rule_id"),
        "target": target_path,
        "location": f"{finding.get('file')}:{finding.get('line')}",
        "commit": finding.get("commit"),
        "masked_secret": finding.get("masked_secret"),
    }

    webhook_url = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    if webhook_url:
        text = (
            f"*[Secret Leak Alert | Risk {score}/100]*\n"
            f"• *Severity:* `{summary['severity']}` | *Rule:* `{summary['rule_id']}`\n"
            f"• *Target:* `{summary['target']}`\n"
            f"• *File:* `{summary['location']}` (`{summary['commit']}`)\n"
            f"• *Masked Key:* `{summary['masked_secret']}`"
        )
        try:
            requests.post(webhook_url, json={"text": text}, timeout=10)
        except Exception as exc:
            print(f"[ALERT ERROR] Slack send failed: {exc}")
    else:
        print(f"[REDACTED ALERT] {json.dumps(summary)}")
