use once_cell::sync::Lazy;
use regex::Regex;
use std::path::Path;

use super::{AppliedFix, FixOutput};

static LOADER_ARG_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"Loader=[A-Za-z0-9_.]+").expect("valid regex"));

/// Fix unsafe deserializer patterns in Python source code (SHIELD-016).
pub fn fix_unsafe_deserializers(content: &str, path: &Path) -> Option<FixOutput> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    if ext != "py" {
        return None;
    }

    let mut modified_lines = Vec::new();
    let mut fixes = Vec::new();
    let mut made_changes = false;

    let lines: Vec<&str> = content.lines().collect();

    for (line_idx, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        // 1. Rewrite yaml.load to yaml.safe_load or add SafeLoader
        if trimmed.contains("yaml.load(")
            && !trimmed.contains("yaml.safe_load(")
            && !trimmed.contains("SafeLoader")
            && !trimmed.contains("CSafeLoader")
            && !trimmed.starts_with('#')
        {
            let new_line = if line.contains("Loader=") {
                LOADER_ARG_RE
                    .replace(line, "Loader=yaml.SafeLoader")
                    .to_string()
            } else if line.contains("yaml.load(") {
                // If it's a simple yaml.load(data), replace with yaml.safe_load(data)
                line.replace("yaml.load(", "yaml.safe_load(")
            } else {
                line.to_string()
            };

            if new_line != *line {
                fixes.push(AppliedFix {
                    rule_id: "SHIELD-016".into(),
                    description: "Replaced unsafe 'yaml.load' with 'yaml.safe_load'".into(),
                    line_number: line_idx + 1,
                });
                modified_lines.push(new_line);
                made_changes = true;
                continue;
            }
        }

        // 2. Rewrite pickle.loads to json.loads
        if trimmed.contains("pickle.loads(") && !trimmed.starts_with('#') {
            let new_line = line.replace("pickle.loads(", "json.loads(");
            fixes.push(AppliedFix {
                rule_id: "SHIELD-016".into(),
                description: "Replaced insecure 'pickle.loads' with 'json.loads'".into(),
                line_number: line_idx + 1,
            });
            modified_lines.push(new_line);
            made_changes = true;
            continue;
        }

        modified_lines.push(line.to_string());
    }

    // Check if we need to update `import pickle` to `import json`
    if made_changes
        && content.contains("import pickle")
        && !modified_lines.join("\n").contains("pickle.")
    {
        for line in &mut modified_lines {
            if line.trim() == "import pickle" {
                *line = line.replace("import pickle", "import json");
            }
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
    fn test_fix_yaml_load_to_safe_load() {
        let code = "import yaml\ndata = yaml.load(user_input)\n";
        let res = fix_unsafe_deserializers(code, Path::new("server.py")).unwrap();
        assert_eq!(
            res.content,
            "import yaml\ndata = yaml.safe_load(user_input)\n"
        );
        assert_eq!(res.fixes.len(), 1);
        assert_eq!(res.fixes[0].rule_id, "SHIELD-016");
    }

    #[test]
    fn test_fix_pickle_loads_to_json_loads() {
        let code = "import pickle\ndata = pickle.loads(payload)\n";
        let res = fix_unsafe_deserializers(code, Path::new("loader.py")).unwrap();
        assert_eq!(res.content, "import json\ndata = json.loads(payload)\n");
        assert_eq!(res.fixes.len(), 1);
    }
}
