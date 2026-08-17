use serde::Serialize;

use crate::error::{Result as ShieldResult, ShieldError};
use crate::output::OutputFormat;

use super::types::{MAX_OUTPUT_CONTRIBUTIONS, RiskAssessment, RiskContribution, RiskSummary};

#[derive(Serialize)]
pub(crate) struct ExperimentalRiskOutput<'a> {
    pub(crate) status: &'static str,
    pub(crate) score: u8,
    pub(crate) model_version: &'a str,
    pub(crate) coverage_id: &'a str,
    pub(crate) raw_points: u64,
    pub(crate) contributions: &'a [RiskContribution],
    pub(crate) contributions_truncated: usize,
    pub(crate) summary: &'a RiskSummary,
    pub(crate) interpretation: &'static str,
}

pub(crate) fn render_experimental(
    base_report: &str,
    assessment: &RiskAssessment,
    format: OutputFormat,
) -> ShieldResult<String> {
    let displayed = assessment.contributions.len().min(MAX_OUTPUT_CONTRIBUTIONS);
    let output = ExperimentalRiskOutput {
        status: "informational",
        score: assessment.score,
        model_version: &assessment.model_version,
        coverage_id: &assessment.coverage_id,
        raw_points: assessment.raw_points,
        contributions: &assessment.contributions[..displayed],
        contributions_truncated: assessment.contributions.len() - displayed,
        summary: &assessment.summary,
        interpretation: "Prioritization index only; not a probability, percentage, grade, or policy verdict.",
    };

    match format {
        OutputFormat::Console => Ok(render_experimental_console(base_report, &output)),
        OutputFormat::Json => render_experimental_json(base_report, &output),
        OutputFormat::Sarif | OutputFormat::Html => Err(ShieldError::Config(
            "`--experimental-risk` supports only console and JSON output".to_owned(),
        )),
    }
}

fn render_experimental_console(base_report: &str, output: &ExperimentalRiskOutput<'_>) -> String {
    use std::fmt::Write;

    let mut rendered = base_report.to_owned();
    if !rendered.ends_with('\n') {
        rendered.push('\n');
    }
    rendered.push('\n');
    rendered.push_str("Experimental risk assessment (informational)\n");
    let _ = writeln!(rendered, "Score: {}", output.score);
    let _ = writeln!(rendered, "Model: {}", output.model_version);
    let _ = writeln!(rendered, "Coverage: {}", output.coverage_id);
    let _ = writeln!(rendered, "Raw points: {}", output.raw_points);
    let _ = writeln!(
        rendered,
        "Contributions: {} shown, {} omitted",
        output.contributions.len(),
        output.contributions_truncated
    );
    for contribution in output.contributions {
        let _ = writeln!(
            rendered,
            "- {} {} {} {}: {} point(s)",
            contribution.fingerprint,
            contribution.rule_id,
            contribution.effective_severity,
            contribution.confidence,
            contribution.points
        );
    }
    let _ = writeln!(rendered, "Interpretation: {}", output.interpretation);
    rendered
}

fn render_experimental_json(
    base_report: &str,
    output: &ExperimentalRiskOutput<'_>,
) -> ShieldResult<String> {
    let mut report: serde_json::Value = serde_json::from_str(base_report)?;
    let object = report
        .as_object_mut()
        .ok_or_else(|| ShieldError::Output("default JSON report was not an object".to_owned()))?;
    object.insert("risk_assessment".to_owned(), serde_json::to_value(output)?);
    Ok(serde_json::to_string_pretty(&report)?)
}
