#[derive(Debug, Clone)]
pub struct CiInstallOptions<'a> {
    pub fail_on: &'a str,
    pub ignore_tests: bool,
    pub scan_path: &'a str,
    pub baseline_path: Option<&'a str>,
    pub upload_sarif: bool,
}

pub fn github_actions_workflow(options: &CiInstallOptions<'_>) -> String {
    let baseline_input = options
        .baseline_path
        .map(|path| format!("          baseline: \"{path}\"\n"))
        .unwrap_or_default();

    format!(
        r#"name: AgentShield

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  agentshield:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aiconnai/agentshield@main
        with:
          path: "{scan_path}"
          fail-on: "{fail_on}"
          ignore-tests: {ignore_tests}
{baseline_input}          upload-sarif: {upload_sarif}
          strict: true
"#,
        scan_path = options.scan_path,
        fail_on = options.fail_on,
        ignore_tests = options.ignore_tests,
        baseline_input = baseline_input,
        upload_sarif = options.upload_sarif,
    )
}

pub fn github_actions_security_suite_workflow(options: &CiInstallOptions<'_>) -> String {
    let baseline_input = options
        .baseline_path
        .map(|path| format!("          baseline: \"{path}\"\n"))
        .unwrap_or_default();

    format!(
        r#"name: Security Suite

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  codeql:
    name: CodeQL
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: github/codeql-action/init@v4
        with:
          queries: security-extended
      - uses: github/codeql-action/analyze@v4

  gitleaks:
    name: Gitleaks
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: gitleaks/gitleaks-action@v3
        env:
          GITHUB_TOKEN: ${{{{ secrets.GITHUB_TOKEN }}}}
          # Required by Gitleaks for organization-owned repositories.
          GITLEAKS_LICENSE: ${{{{ secrets.GITLEAKS_LICENSE }}}}

  semgrep:
    name: Semgrep CE
    runs-on: ubuntu-latest
    container:
      image: semgrep/semgrep
    if: github.actor != 'dependabot[bot]'
    steps:
      - uses: actions/checkout@v6
      - run: semgrep scan --config auto

  agentshield:
    name: AgentShield
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: aiconnai/agentshield@main
        with:
          path: "{scan_path}"
          fail-on: "{fail_on}"
          ignore-tests: {ignore_tests}
{baseline_input}          upload-sarif: {upload_sarif}
          strict: true
"#,
        scan_path = options.scan_path,
        fail_on = options.fail_on,
        ignore_tests = options.ignore_tests,
        baseline_input = baseline_input,
        upload_sarif = options.upload_sarif,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ci_workflow_uses_expected_action_inputs() {
        let workflow = github_actions_workflow(&CiInstallOptions {
            fail_on: "high",
            ignore_tests: true,
            scan_path: ".",
            baseline_path: None,
            upload_sarif: true,
        });

        assert!(workflow.contains("uses: aiconnai/agentshield@main"));
        assert!(workflow.contains("fail-on: \"high\""));
        assert!(workflow.contains("ignore-tests: true"));
        assert!(workflow.contains("upload-sarif: true"));
        assert!(workflow.contains("strict: true"));
        assert!(!workflow.contains("baseline:"));
    }

    #[test]
    fn ci_workflow_can_use_baseline_file() {
        let workflow = github_actions_workflow(&CiInstallOptions {
            fail_on: "high",
            ignore_tests: true,
            scan_path: ".",
            baseline_path: Some(".agentshield-baseline.json"),
            upload_sarif: true,
        });

        assert!(workflow.contains("baseline: \".agentshield-baseline.json\""));
        assert!(workflow.contains("upload-sarif: true"));
        assert!(workflow.contains("strict: true"));
    }

    #[test]
    fn ci_workflow_security_suite_includes_complementary_scanners() {
        let workflow = github_actions_security_suite_workflow(&CiInstallOptions {
            fail_on: "high",
            ignore_tests: true,
            scan_path: ".",
            baseline_path: Some(".agentshield-baseline.json"),
            upload_sarif: true,
        });

        assert!(workflow.contains("name: Security Suite"));
        assert!(workflow.contains("uses: github/codeql-action/init@v4"));
        assert!(workflow.contains("uses: gitleaks/gitleaks-action@v3"));
        assert!(workflow.contains("semgrep scan --config auto"));
        assert!(workflow.contains("uses: aiconnai/agentshield@main"));
        assert!(workflow.contains("baseline: \".agentshield-baseline.json\""));
        assert!(workflow.contains("strict: true"));
    }
}
