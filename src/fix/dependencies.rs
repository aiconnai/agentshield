use std::path::Path;

use regex::Regex;

use super::{AppliedFix, FixOutput};

/// Fix unpinned dependency specifications in requirements.txt or package.json (SHIELD-009).
pub fn fix_unpinned_dependencies(content: &str, path: &Path) -> Option<FixOutput> {
    let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");

    if file_name == "requirements.txt" || file_name.ends_with(".requirements.txt") {
        fix_requirements_txt(content)
    } else if file_name == "package.json" {
        fix_package_json(content)
    } else {
        None
    }
}

fn fix_requirements_txt(content: &str) -> Option<FixOutput> {
    let unpinned_re =
        Regex::new(r"^([a-zA-Z0-9_.\-]+)\s*(?:>=|~=|>|\^)\s*([0-9a-zA-Z_.\-]+)(.*)$").ok()?;

    let mut modified_lines = Vec::new();
    let mut fixes = Vec::new();
    let mut made_changes = false;

    for (line_idx, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') || trimmed.is_empty() {
            modified_lines.push(line.to_string());
            continue;
        }

        if let Some(caps) = unpinned_re.captures(trimmed) {
            let pkg = &caps[1];
            let ver = &caps[2];
            let rest = &caps[3];

            let new_line = format!("{pkg}=={ver}{rest}");
            fixes.push(AppliedFix {
                rule_id: "SHIELD-009".into(),
                description: format!("Pinned '{pkg}' to exact version '=={ver}'"),
                line_number: line_idx + 1,
            });
            modified_lines.push(new_line);
            made_changes = true;
        } else {
            modified_lines.push(line.to_string());
        }
    }

    if !made_changes {
        return None;
    }

    let mut output = modified_lines.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }

    Some(FixOutput {
        content: output,
        fixes,
    })
}

fn fix_package_json(content: &str) -> Option<FixOutput> {
    let npm_unpinned_re =
        Regex::new(r#"^(\s*"[^"]+"\s*:\s*)"[\^~>=]+([0-9a-zA-Z_.\-]+)"(.*)$"#).ok()?;

    let mut modified_lines = Vec::new();
    let mut fixes = Vec::new();
    let mut made_changes = false;

    for (line_idx, line) in content.lines().enumerate() {
        if let Some(caps) = npm_unpinned_re.captures(line) {
            let prefix = &caps[1];
            let ver = &caps[2];
            let suffix = &caps[3];

            let new_line = format!("{prefix}\"{ver}\"{suffix}");
            fixes.push(AppliedFix {
                rule_id: "SHIELD-009".into(),
                description: format!("Pinned npm dependency to exact version '{ver}'"),
                line_number: line_idx + 1,
            });
            modified_lines.push(new_line);
            made_changes = true;
        } else {
            modified_lines.push(line.to_string());
        }
    }

    if !made_changes {
        return None;
    }

    let mut output = modified_lines.join("\n");
    if content.ends_with('\n') {
        output.push('\n');
    }

    Some(FixOutput {
        content: output,
        fixes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fix_requirements_txt_unpinned() {
        let reqs = "requests>=2.31.0\nfastapi~=0.100.0\npytest==8.0.0\n";
        let res = fix_unpinned_dependencies(reqs, Path::new("requirements.txt")).unwrap();
        assert_eq!(
            res.content,
            "requests==2.31.0\nfastapi==0.100.0\npytest==8.0.0\n"
        );
        assert_eq!(res.fixes.len(), 2);
    }

    #[test]
    fn test_fix_package_json_unpinned() {
        let pkg = r#"{
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.0.0",
    "express": "~4.18.2"
  }
}"#;
        let res = fix_unpinned_dependencies(pkg, Path::new("package.json")).unwrap();
        assert!(
            res.content
                .contains("\"@modelcontextprotocol/sdk\": \"1.0.0\"")
        );
        assert!(res.content.contains("\"express\": \"4.18.2\""));
        assert_eq!(res.fixes.len(), 2);
    }
}
