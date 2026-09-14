import pytest
from pathlib import Path
import agentshield
from agentshield import shield, SecurityBlockError


def test_version():
    assert agentshield.__version__ == "1.0.1"


def test_find_binary():
    bin_path = agentshield.find_agentshield_bin()
    assert Path(bin_path).exists()


def test_scan_vulnerable_fixture():
    fixture_path = Path(__file__).resolve().parent.parent.parent / "tests/fixtures/mcp_servers/vuln_cmd_inject"
    report = agentshield.scan(fixture_path, fail_on="high", ignore_tests=False)

    assert not report.passed
    assert report.has_critical()
    assert report.summary.total >= 1
    assert any(f.rule_id == "SHIELD-001" for f in report.findings)


def test_shield_decorator_blocks_cloud_metadata():
    @shield(block_ssrf=True, on_block="raise")
    def fetch_url(url: str) -> str:
        return f"Fetched {url}"

    # Benign call passes
    assert fetch_url("https://api.github.com") == "Fetched https://api.github.com"

    # Cloud metadata SSRF is blocked
    with pytest.raises(SecurityBlockError) as exc_info:
        fetch_url("http://169.254.169.254/latest/meta-data/")
    assert "169.254.169.254" in str(exc_info.value)


def test_shield_decorator_return_error_mode():
    @shield(block_ssrf=True, on_block="return_error")
    def fetch_url(url: str) -> str:
        return f"Fetched {url}"

    res = fetch_url("http://169.254.169.254/latest/meta-data/")
    assert res.startswith("Error: Blocked by AgentShield")


def test_shield_decorator_redacts_secrets():
    @shield(redact_secrets=True)
    def get_api_response() -> str:
        return "User authenticated. token = 'sk-abcdef1234567890abcdef123456789012345678'"

    res = get_api_response()
    assert "sk-abcdef1234567890" not in res
    assert "[REDACTED_BY_AGENTSHIELD]" in res
