from pathlib import Path
from scanner.detector import SecretDetector


IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json", ".env", ".ini", ".toml"}


def scan_iac_directory(target_dir: Path, detector: SecretDetector) -> list[dict]:
    findings = []
    for path in target_dir.rglob("*"):
        if not path.is_file():
            continue
        if path.suffix.lower() not in IAC_EXTENSIONS:
            continue
        rel_path = str(path.relative_to(target_dir))
        try:
            content = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, PermissionError):
            continue
        findings.extend(detector.scan_text(content, rel_path, commit_sha="iac-scan"))
    return findings


def scan_aws_readonly(detector: SecretDetector, region: str = "us-east-1") -> list[dict]:
    """Safe read-only scan of AWS Lambda environment variables if boto3 & creds are present."""
    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError
    except ImportError:
        return []

    findings = []
    try:
        client = boto3.client("lambda", region_name=region)
        paginator = client.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                fn_name = fn.get("FunctionName", "unknown-lambda")
                env_vars = (fn.get("Environment") or {}).get("Variables") or {}
                for k, v in env_vars.items():
                    line_repr = f"{k}=\"{v}\""
                    hits = detector.scan_text(line_repr, f"aws:lambda:{fn_name}", commit_sha="aws-live")
                    findings.extend(hits)
    except (BotoCoreError, ClientError, Exception):
        return []

    return findings
