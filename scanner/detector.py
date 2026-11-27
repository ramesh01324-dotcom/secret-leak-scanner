import hashlib
import math
import re
from pathlib import Path
import yaml


def shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {ch: data.count(ch) for ch in set(data)}
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def mask_secret(secret: str) -> str:
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:4]}...{secret[-4:]}"


def fingerprint_secret(rule_id: str, file_path: str, secret: str) -> str:
    raw = f"{rule_id}:{file_path}:{secret}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()[:16]


class SecretDetector:
    def __init__(self, rules_path: str = "config/rules.yaml"):
        config = yaml.safe_load(Path(rules_path).read_text(encoding="utf-8"))
        self.rules = config.get("rules", [])
        allowlist = config.get("allowlist", {})
        self.ignored_paths = allowlist.get("paths", [])
        self.dummy_patterns = [p.lower() for p in allowlist.get("dummy_patterns", [])]

    def is_ignored_path(self, file_path: str) -> bool:
        return any(ignored in file_path for ignored in self.ignored_paths)

    def is_dummy(self, matched_value: str) -> bool:
        val_lower = matched_value.lower()
        return any(dummy in val_lower for dummy in self.dummy_patterns)

    def scan_text(self, text: str, file_path: str, commit_sha: str = "working-tree") -> list[dict]:
        if self.is_ignored_path(file_path):
            return []

        findings = []
        for line_num, line in enumerate(text.splitlines(), start=1):
            for rule in self.rules:
                for match in re.finditer(rule["regex"], line):
                    secret_val = match.group(1) if match.groups() else match.group(0)

                    if self.is_dummy(secret_val):
                        continue

                    entropy = shannon_entropy(secret_val)
                    if entropy < rule.get("entropy_threshold", 0.0):
                        continue

                    findings.append({
                        "rule_id": rule["id"],
                        "description": rule["description"],
                        "severity": rule["severity"],
                        "file": file_path,
                        "line": line_num,
                        "commit": commit_sha,
                        "masked_secret": mask_secret(secret_val),
                        "entropy": round(entropy, 2),
                        "fingerprint": fingerprint_secret(rule["id"], file_path, secret_val),
                    })
        return findings
