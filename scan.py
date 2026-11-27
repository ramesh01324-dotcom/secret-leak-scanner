import argparse
import csv
import json
from pathlib import Path
from git import InvalidGitRepositoryError, Repo
from scanner.cloud_scanner import scan_aws_readonly, scan_iac_directory
from notifiers.alerts import calculate_risk_score, send_redacted_alert
from scanner.detector import SecretDetector
from storage.db import FindingsDB


def scan_working_directory(target_dir: Path, detector: SecretDetector) -> list[dict]:
    findings = []
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        rel_path = str(path.relative_to(target_dir))
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        findings.extend(detector.scan_text(content, rel_path))
    return findings


def scan_git_history(target_dir: Path, detector: SecretDetector, max_commits: int = 50) -> list[dict]:
    findings = []
    try:
        repo = Repo(target_dir)
    except InvalidGitRepositoryError:
        return findings

    for commit in list(repo.iter_commits())[:max_commits]:
        for parent in commit.parents:
            diffs = parent.diff(commit, create_patch=True)
            for diff in diffs:
                file_path = diff.b_path or diff.a_path or "unknown"
                patch = diff.diff.decode("utf-8", errors="ignore")
                added_lines = "\n".join(
                    line[1:] for line in patch.splitlines()
                    if line.startswith("+") and not line.startswith("+++")
                )
                findings.extend(detector.scan_text(added_lines, file_path, commit.hexsha[:8]))
    return findings


def main():
    parser = argparse.ArgumentParser(description="Automated Secret Leak Scanner")
    parser.add_argument("path", nargs="?", help="Path to repo or folder to scan")
    parser.add_argument("--history", action="store_true", help="Also scan Git commit history")
    parser.add_argument("--cloud", action="store_true", help="Also scan IaC files and AWS read-only configs")
    parser.add_argument("--list", action="store_true", help="List saved findings from SQLite DB")
    parser.add_argument("--export-json", action="store_true", help="Export saved DB findings to reports/findings.json")
    parser.add_argument("--export-csv", action="store_true", help="Export saved DB findings to reports/findings.csv")
    args = parser.parse_args()

    db = FindingsDB(str(Path(__file__).resolve().parent / "scanner.db"))

    if args.export_json or args.export_csv:
        records = db.list_findings()
        out_dir = Path(__file__).resolve().parent / "reports"
        out_dir.mkdir(exist_ok=True)
        exported = []
        if args.export_json:
            json_file = out_dir / "findings.json"
            json_file.write_text(json.dumps(records, indent=2), encoding="utf-8")
            exported.append(str(json_file))
        if args.export_csv:
            csv_file = out_dir / "findings.csv"
            fields = [
                "id", "fingerprint", "rule_id", "description", "severity",
                "target_path", "file_path", "line_number", "commit_sha",
                "masked_secret", "entropy", "status", "first_seen", "last_seen"
            ]
            with csv_file.open("w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(records)
            exported.append(str(csv_file))
        print(json.dumps({"exported_files": exported, "count": len(records)}, indent=2))
        return

    if args.list:
        print(json.dumps(db.list_findings(), indent=2))
        return

    if not args.path:
        parser.error("Please provide a path to scan, or pass --list.")

    target = Path(args.path).resolve()
    detector = SecretDetector(str(Path(__file__).resolve().parent / "config" / "rules.yaml"))

    results = scan_working_directory(target, detector)
    if args.history:
        results.extend(scan_git_history(target, detector))
    if args.cloud:
        results.extend(scan_iac_directory(target, detector))
        results.extend(scan_aws_readonly(detector))

    unique_results = list({item["fingerprint"]: item for item in results}.values())
    for item in unique_results:
        item["risk_score"] = calculate_risk_score(item)
    new_count = db.save_findings(unique_results, str(target))
    for item in unique_results:
        send_redacted_alert(item, str(target))

    print(json.dumps({
        "scanned_target": str(target),
        "total_unique_findings": len(unique_results),
        "newly_saved_to_db": new_count,
        "findings": unique_results,
    }, indent=2))


if __name__ == "__main__":
    main()
