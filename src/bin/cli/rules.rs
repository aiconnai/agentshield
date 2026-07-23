use agentshield::rules::RuleEngine;

pub(super) fn cmd_list_rules(format_str: String) -> Result<i32, agentshield::error::ShieldError> {
    let engine = RuleEngine::new();
    let rules = engine.list_rules();

    match format_str.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&rules)?;
            println!("{}", json);
        }
        _ => {
            println!(
                "{:<12} {:<28} {:<10} {:<8} {:<7} CATEGORY",
                "ID", "NAME", "SEVERITY", "CWE", "OWASP"
            );
            println!("{}", "-".repeat(88));
            for rule in &rules {
                println!(
                    "{:<12} {:<28} {:<10} {:<8} {:<7} {}",
                    rule.id,
                    rule.name,
                    rule.default_severity.to_string(),
                    rule.cwe_id.as_deref().unwrap_or("-"),
                    rule.owasp_mcp.map(|c| c.code()).unwrap_or("-"),
                    rule.attack_category,
                );
            }
        }
    }

    Ok(0)
}
