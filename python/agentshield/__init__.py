"""AgentShield: Sub-50ms security firewall for MCP and tool-enabled AI agents."""

from __future__ import annotations

import functools
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

__version__ = "1.0.1"


class AgentShieldError(Exception):
    """Base exception for AgentShield errors."""


class AgentShieldExecutionError(AgentShieldError):
    """Raised when the AgentShield binary fails to execute."""


class SecurityBlockError(AgentShieldError):
    """Raised at runtime when an agent action is blocked by security policy."""


@dataclass
class Location:
    file: str
    line: int
    column: int = 1
    end_line: Optional[int] = None
    end_column: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Optional[Dict[str, Any]]) -> Optional[Location]:
        if not data:
            return None
        return cls(
            file=data.get("file", ""),
            line=data.get("line", 1),
            column=data.get("column", 1),
            end_line=data.get("end_line"),
            end_column=data.get("end_column"),
        )


@dataclass
class Evidence:
    description: str
    location: Optional[Location] = None
    snippet: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Evidence:
        return cls(
            description=data.get("description", ""),
            location=Location.from_dict(data.get("location")),
            snippet=data.get("snippet"),
        )


@dataclass
class Finding:
    rule_id: str
    rule_name: str
    severity: str
    confidence: str
    attack_category: str
    message: str
    location: Optional[Location] = None
    evidence: List[Evidence] = field(default_factory=list)
    remediation: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        return cls(
            rule_id=data.get("rule_id", ""),
            rule_name=data.get("rule_name", ""),
            severity=data.get("severity", ""),
            confidence=data.get("confidence", ""),
            attack_category=data.get("attack_category", ""),
            message=data.get("message", ""),
            location=Location.from_dict(data.get("location")),
            evidence=[Evidence.from_dict(e) for e in data.get("evidence", [])],
            remediation=data.get("remediation"),
        )


@dataclass
class ScanSummary:
    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanSummary:
        return cls(
            total=data.get("total", 0),
            critical=data.get("critical", 0),
            high=data.get("high", 0),
            medium=data.get("medium", 0),
            low=data.get("low", 0),
            info=data.get("info", 0),
        )


@dataclass
class PolicyVerdict:
    passed: bool
    total_findings: int
    effective_findings: int
    highest_severity: Optional[str] = None
    fail_threshold: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PolicyVerdict:
        return cls(
            passed=data.get("pass", True),
            total_findings=data.get("total_findings", 0),
            effective_findings=data.get("effective_findings", 0),
            highest_severity=data.get("highest_severity"),
            fail_threshold=data.get("fail_threshold"),
        )


@dataclass
class ScanReport:
    schema_version: str
    tool_version: str
    target: str
    scan_root: str
    summary: ScanSummary
    verdict: PolicyVerdict
    findings: List[Finding] = field(default_factory=list)
    raw_json: Dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return self.verdict.passed

    def has_critical(self) -> bool:
        return self.summary.critical > 0

    def has_high(self) -> bool:
        return self.summary.high > 0

    def summary_str(self) -> str:
        return (
            f"Findings: {self.summary.total} (Critical: {self.summary.critical}, "
            f"High: {self.summary.high}, Medium: {self.summary.medium}, Low: {self.summary.low}) "
            f"- Verdict: {'PASSED' if self.passed else 'FAILED'}"
        )

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanReport:
        return cls(
            schema_version=data.get("schema_version", "1.0.0"),
            tool_version=data.get("tool_version", __version__),
            target=data.get("target", ""),
            scan_root=data.get("scan_root", ""),
            summary=ScanSummary.from_dict(data.get("summary", {})),
            verdict=PolicyVerdict.from_dict(data.get("verdict", {})),
            findings=[Finding.from_dict(f) for f in data.get("findings", [])],
            raw_json=data,
        )


def find_agentshield_bin() -> str:
    """Find the path to the agentshield executable binary."""
    # 1. Check explicit environment override
    env_bin = os.environ.get("AGENTSHIELD_BIN")
    if env_bin and os.path.isfile(env_bin) and os.access(env_bin, os.X_OK):
        return env_bin

    # 2. Check virtual environment script directory
    venv_bin_name = "agentshield.exe" if sys.platform == "win32" else "agentshield"
    prefix_bin = Path(sys.prefix) / ("Scripts" if sys.platform == "win32" else "bin") / venv_bin_name
    if prefix_bin.is_file() and os.access(str(prefix_bin), os.X_OK):
        return str(prefix_bin)

    # 3. Check PATH
    which_bin = shutil.which("agentshield")
    if which_bin:
        return which_bin

    # 4. Check local development target directories
    current_dir = Path(__file__).resolve().parent
    repo_root = current_dir.parent.parent
    for candidate in [
        repo_root / "target" / "release" / venv_bin_name,
        repo_root / "target" / "debug" / venv_bin_name,
    ]:
        if candidate.is_file() and os.access(str(candidate), os.X_OK):
            return str(candidate)

    raise FileNotFoundError(
        "AgentShield binary not found on PATH or in virtual environment. "
        "Please install via: pip install agentshield, or cargo install agent-shield --features full"
    )


def scan(
    path: str | Path = ".",
    fail_on: Optional[str] = None,
    ignore_tests: bool = True,
    rules_dir: Optional[str | Path] = None,
    extra_args: Optional[List[str]] = None,
) -> ScanReport:
    """Run an offline AgentShield security scan on the specified target path.

    Args:
        path: Path to directory or file to scan (default: current directory).
        fail_on: Severity threshold to fail the scan ('critical', 'high', 'medium', 'low').
        ignore_tests: Skip test directories and test files.
        rules_dir: Optional directory with declarative custom rules (*.yaml).
        extra_args: Additional command line arguments to pass to agentshield.

    Returns:
        ScanReport: Parsed scan report with findings and policy verdict.
    """
    bin_path = find_agentshield_bin()
    cmd = [bin_path, "scan", str(path), "--format", "json"]

    if fail_on:
        cmd.extend(["--fail-on", fail_on.lower()])
    if ignore_tests:
        cmd.append("--ignore-tests")
    if rules_dir:
        cmd.extend(["--rules-dir", str(rules_dir)])
    if extra_args:
        cmd.extend(extra_args)

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )

    if proc.returncode not in (0, 1):
        stderr = proc.stderr.strip() or "Unknown execution error"
        raise AgentShieldExecutionError(f"AgentShield scan failed (exit code {proc.returncode}): {stderr}")

    try:
        data = json.loads(proc.stdout)
        return ScanReport.from_dict(data)
    except json.JSONDecodeError as err:
        raise AgentShieldExecutionError(
            f"Failed to parse AgentShield JSON output: {err}. Output was: {proc.stdout[:200]}"
        ) from err


# Cloud metadata IP (AWS/GCP/Azure link-local endpoint)
CLOUD_METADATA_IP = "169.254.169.254"
# Common high-entropy API key patterns
SECRET_PATTERNS = [
    re.compile(r"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"]?([A-Za-z0-9_\-\.]{16,})['\"]?"),
    re.compile(r"sk-[A-Za-z0-9]{32,}"),  # OpenAI / provider tokens
    re.compile(r"AKIA[0-9A-Z]{16}"),      # AWS Access Key ID
]


def shield(
    block_ssrf: bool = True,
    redact_secrets: bool = True,
    on_block: str = "raise",
) -> Callable:
    """Runtime decorator protecting tool functions against SSRF and credential leaks.

    Args:
        block_ssrf: Blocks invocations when arguments target cloud metadata (169.254.169.254).
        redact_secrets: Redacts detected API keys and secrets from return values.
        on_block: Action when a call is blocked: 'raise' (raises SecurityBlockError)
                  or 'return_error' (returns error message string to the agent).
    """

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            # Check inputs for SSRF to cloud metadata
            if block_ssrf:
                str_repr = f"{args} {kwargs}"
                if CLOUD_METADATA_IP in str_repr:
                    msg = (
                        f"Blocked by AgentShield: Tool call '{func.__name__}' targets "
                        f"prohibited cloud metadata endpoint ({CLOUD_METADATA_IP})."
                    )
                    if on_block == "raise":
                        raise SecurityBlockError(msg)
                    return f"Error: {msg}"

            result = func(*args, **kwargs)

            # Redact secrets from string outputs
            if redact_secrets and isinstance(result, str):
                for pattern in SECRET_PATTERNS:
                    result = pattern.sub("[REDACTED_BY_AGENTSHIELD]", result)

            return result

        return wrapper

    return decorator
