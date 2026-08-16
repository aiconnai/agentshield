use once_cell::sync::Lazy;
use regex::Regex;

use crate::ir::{Language, ScanTarget, SourceLocation};
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-021: SQL Injection
///
/// Detects unparameterized or interpolated SQL queries executed by AI agent tools,
/// MCP database servers, or database adapters (CWE-89).
pub struct SqlInjectionDetector;

// Regex matching Python SQL execution methods with string interpolation or concatenation
static PY_SQL_EXECUTE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:cursor|conn|connection|db|session|engine|sqlite3|raw_query|client)
        \s*\.\s*
        (?:execute|executemany|raw|query)\s*\(
        \s*
        (?:
            f["']|                                    # f-string: f"SELECT ... {var}"
            (?:\"[^\"]*\"|'[^']*')\s*%\s*[a-zA-Z_(]|  # % formatting: "SELECT ..." % var
            (?:\"[^\"]*\"|'[^']*')\.format\s*\(|      # format method: "SELECT ...".format(var)
            [a-zA-Z_]\w*\s*\+|                        # var + "string"
            (?:\"[^\"]*\"|'[^']*')\s*\+\s*[a-zA-Z_]   # "string" + var
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Regex matching TypeScript / JavaScript raw SQL queries with template literals or string concatenation
static TS_SQL_EXECUTE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?x)
        (?:db|client|pool|connection|sqlite|prisma|knex|sequelize)
        \s*\.\s*
        (?:\$queryRawUnsafe|\$executeRawUnsafe|query|execute|raw|all|run|get)\s*\(
        \s*
        (?:
            `[^`]*\$\{.+?\}[^`]*`|           # Template literal: `SELECT ... ${var}`
            [a-zA-Z_$]\w*\s*\+|              # var + "string"
            (?:\"[^\"]*\"|'[^']*'|`[^`]*`)\s*\+\s*[a-zA-Z_$] # "string" + var
        )
    "#,
    )
    .expect("static regex pattern is valid")
});

// Detect direct Prisma raw unsafe execution
static PRISMA_UNSAFE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?:\$queryRawUnsafe|\$executeRawUnsafe)\s*\("#)
        .expect("static regex pattern is valid")
});

impl Detector for SqlInjectionDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-021".into(),
            name: "SQL Injection".into(),
            description: "Unsanitized user or tool parameter interpolated into SQL query execution"
                .into(),
            default_severity: Severity::Critical,
            attack_category: AttackCategory::SqlInjection,
            cwe_id: Some("CWE-89".into()),
            owasp_mcp: Some(OwaspMcp::CommandExecution),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        for source in &target.source_files {
            match source.language {
                Language::Python => {
                    for (line_idx, line) in source.content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with('#') {
                            continue;
                        }

                        if PY_SQL_EXECUTE_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-021".into(),
                                rule_name: "SQL Injection".into(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::SqlInjection,
                                message: format!(
                                    "Dynamic SQL query construction detected in '{}' via string interpolation or concatenation",
                                    source.path.display()
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Unparameterized SQL execution with dynamic formatting".into(),
                                    location: Some(loc),
                                    snippet: Some(line.trim().to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use parameterized queries or prepared statements (e.g., `cursor.execute('SELECT * FROM t WHERE id = ?', (id,))` or `pool.query('SELECT * FROM t WHERE id = $1', [id])`) instead of string interpolation or concatenation."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-89".into()),
                            });
                        }
                    }
                }
                Language::TypeScript | Language::JavaScript => {
                    for (line_idx, line) in source.content.lines().enumerate() {
                        let trimmed = line.trim();
                        if trimmed.starts_with("//") || trimmed.starts_with('*') {
                            continue;
                        }

                        if TS_SQL_EXECUTE_RE.is_match(line) || PRISMA_UNSAFE_RE.is_match(line) {
                            let loc = SourceLocation {
                                file: source.path.clone(),
                                line: line_idx + 1,
                                column: 1,
                                end_line: Some(line_idx + 1),
                                end_column: Some(line.len() + 1),
                            };

                            findings.push(Finding {
                                rule_id: "SHIELD-021".into(),
                                rule_name: "SQL Injection".into(),
                                severity: Severity::Critical,
                                confidence: Confidence::High,
                                attack_category: AttackCategory::SqlInjection,
                                message: format!(
                                    "Dynamic SQL query construction detected in '{}' via template interpolation or concatenation",
                                    source.path.display()
                                ),
                                location: Some(loc.clone()),
                                evidence: vec![Evidence {
                                    description: "Unparameterized SQL query execution with dynamic variables".into(),
                                    location: Some(loc),
                                    snippet: Some(line.trim().to_string()),
                                }],
                                taint_path: None,
                                remediation: Some(
                                    "Use parameterized queries or tagged template literals (e.g. `prisma.$queryRaw` or parameterized client queries) instead of `$queryRawUnsafe` or manual string concatenation."
                                        .into(),
                                ),
                                cwe_id: Some("CWE-89".into()),
                            });
                        }
                    }
                }
                _ => {}
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{
        DataSurface, DependencySurface, ExecutionSurface, Framework, ProvenanceSurface, SourceFile,
    };
    use std::path::PathBuf;

    fn make_target(files: Vec<(&str, Language, &str)>) -> ScanTarget {
        ScanTarget {
            name: "test_sql_target".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("/test"),
            tools: Vec::new(),
            execution: ExecutionSurface::default(),
            data: DataSurface::default(),
            dependencies: DependencySurface::default(),
            provenance: ProvenanceSurface::default(),
            source_files: files
                .into_iter()
                .map(|(path, lang, content)| SourceFile {
                    path: PathBuf::from(path),
                    language: lang,
                    content: content.into(),
                    size_bytes: content.len() as u64,
                    content_hash: "hash".into(),
                })
                .collect(),
        }
    }

    #[test]
    fn detects_python_sql_injection_fstring() {
        let code = r#"
def query_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
"#;
        let target = make_target(vec![("server.py", Language::Python, code)]);
        let detector = SqlInjectionDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-021");
        assert_eq!(findings[0].severity, Severity::Critical);
        assert_eq!(findings[0].cwe_id.as_deref(), Some("CWE-89"));
    }

    #[test]
    fn detects_python_sql_injection_concat() {
        let code = r#"
def search_products(query):
    db.execute("SELECT * FROM items WHERE name LIKE '%" + query + "%'")
"#;
        let target = make_target(vec![("db.py", Language::Python, code)]);
        let detector = SqlInjectionDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-021");
    }

    #[test]
    fn allows_safe_parameterized_python_query() {
        let code = r#"
def query_user(user_id):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
"#;
        let target = make_target(vec![("safe_server.py", Language::Python, code)]);
        let detector = SqlInjectionDetector;
        let findings = detector.run(&target);

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_typescript_sql_injection_template() {
        let code = r#"
async function getAccount(accountId: string) {
    return await pool.query(`SELECT * FROM accounts WHERE id = ${accountId}`);
}
"#;
        let target = make_target(vec![("index.ts", Language::TypeScript, code)]);
        let detector = SqlInjectionDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-021");
    }

    #[test]
    fn detects_prisma_unsafe_query() {
        let code = r#"
async function rawQuery(sql: string) {
    return await prisma.$queryRawUnsafe(sql);
}
"#;
        let target = make_target(vec![("prisma.ts", Language::TypeScript, code)]);
        let detector = SqlInjectionDetector;
        let findings = detector.run(&target);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "SHIELD-021");
    }
}
