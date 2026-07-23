use crate::ir::ScanTarget;
use crate::rules::{
    AttackCategory, Confidence, Detector, Evidence, Finding, OwaspMcp, RuleMetadata, Severity,
};

/// SHIELD-010: Typosquat Detection
///
/// Flags dependencies whose names are suspiciously similar (Levenshtein
/// distance 1-2) to well-known popular packages, without being exact matches.
pub struct TyposquatDetector;

/// Popular Python packages to compare against.
const POPULAR_PYTHON: &[&str] = &[
    "requests",
    "flask",
    "django",
    "numpy",
    "pandas",
    "scipy",
    "boto3",
    "fastapi",
    "uvicorn",
    "httpx",
    "aiohttp",
    "pillow",
    "pydantic",
    "sqlalchemy",
    "celery",
    "redis",
    "psycopg2",
    "pytest",
    "setuptools",
    "cryptography",
    "paramiko",
    "pyyaml",
    "jinja2",
    "beautifulsoup4",
    "selenium",
    "scrapy",
    "tensorflow",
    "pytorch",
    "transformers",
    "langchain",
    "openai",
    "anthropic",
];

/// Known-safe packages that are within Levenshtein distance 1-2 of a popular
/// package but are themselves legitimate. Prevents false positives like
/// "vitest" being flagged as a typosquat of "pytest".
const KNOWN_SAFE: &[&str] = &[
    "vitest",  // JS test runner, distance 2 from "pytest"
    "esbuild", // JS bundler
    "bun",     // JS runtime
    "deno",    // JS runtime
    "pnpm",    // JS package manager
    "yarn",    // JS package manager
    "tsx",     // TS exec
    "tsup",    // TS bundler
    "vite",    // JS build tool
    "nuxt",    // Vue framework, distance 1 from "next"
];

/// Popular npm packages to compare against.
const POPULAR_NPM: &[&str] = &[
    "express",
    "react",
    "lodash",
    "axios",
    "chalk",
    "commander",
    "next",
    "typescript",
    "webpack",
    "eslint",
    "prettier",
    "jest",
    "mongoose",
    "sequelize",
    "prisma",
    "fastify",
    "dotenv",
    "cors",
    "jsonwebtoken",
    "bcrypt",
    "nodemailer",
    "openai",
    "langchain",
    "zod",
];

impl Detector for TyposquatDetector {
    fn metadata(&self) -> RuleMetadata {
        RuleMetadata {
            id: "SHIELD-010".into(),
            name: "Typosquat Detection".into(),
            description: "Dependency name suspiciously similar to a popular package".into(),
            default_severity: Severity::Medium,
            attack_category: AttackCategory::SupplyChain,
            cwe_id: Some("CWE-506".into()),
            owasp_mcp: Some(OwaspMcp::SupplyChain),
        }
    }

    fn run(&self, target: &ScanTarget) -> Vec<Finding> {
        let mut findings = Vec::new();

        let corpus: Vec<&str> = POPULAR_PYTHON
            .iter()
            .chain(POPULAR_NPM.iter())
            .copied()
            .collect();

        for dep in &target.dependencies.dependencies {
            let name = dep.name.to_lowercase();

            // Skip known-safe packages that look similar to popular ones
            if KNOWN_SAFE.iter().any(|&safe| name == safe) {
                continue;
            }

            for &popular in &corpus {
                if name == popular {
                    continue; // Exact match — not a typosquat
                }

                let distance = levenshtein::levenshtein(&name, popular);
                if distance > 0 && distance <= 2 {
                    let confidence = if distance == 1 {
                        Confidence::High
                    } else {
                        Confidence::Medium
                    };

                    findings.push(Finding {
                        rule_id: "SHIELD-010".into(),
                        rule_name: "Typosquat Detection".into(),
                        severity: Severity::Medium,
                        confidence,
                        attack_category: AttackCategory::SupplyChain,
                        message: format!(
                            "Dependency '{}' is suspiciously similar to popular package '{}' \
                             (edit distance {})",
                            dep.name, popular, distance
                        ),
                        location: dep.location.clone(),
                        evidence: vec![Evidence {
                            description: format!(
                                "'{}' vs '{}' — Levenshtein distance {}",
                                dep.name, popular, distance
                            ),
                            location: dep.location.clone(),
                            snippet: None,
                        }],
                        taint_path: None,
                        remediation: Some(format!(
                            "Verify that '{}' is the intended package and not a typosquat \
                             of '{}'. Check the package on {} for legitimacy.",
                            dep.name, popular, dep.registry
                        )),
                        cwe_id: Some("CWE-506".into()),
                    });
                }
            }
        }

        findings
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::dependency_surface::*;
    use crate::ir::*;
    use std::path::PathBuf;

    fn make_target(deps: Vec<Dependency>) -> ScanTarget {
        ScanTarget {
            name: "test".into(),
            framework: Framework::Mcp,
            root_path: PathBuf::from("."),
            tools: vec![],
            execution: Default::default(),
            data: Default::default(),
            dependencies: DependencySurface {
                dependencies: deps,
                ..Default::default()
            },
            provenance: Default::default(),
            source_files: vec![],
        }
    }

    #[test]
    fn flags_typosquat() {
        let target = make_target(vec![Dependency {
            name: "reqeusts".into(), // typo of "requests"
            version_constraint: Some("2.31.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "pypi".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = TyposquatDetector.run(&target);
        assert!(!findings.is_empty());
        assert_eq!(findings[0].rule_id, "SHIELD-010");
    }

    #[test]
    fn passes_exact_match() {
        let target = make_target(vec![Dependency {
            name: "requests".into(),
            version_constraint: Some("2.31.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "pypi".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = TyposquatDetector.run(&target);
        assert!(findings.is_empty());
    }

    #[test]
    fn flags_npm_typosquat() {
        let target = make_target(vec![Dependency {
            name: "expresss".into(), // extra 's'
            version_constraint: Some("^4.18.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "npm".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = TyposquatDetector.run(&target);
        assert!(!findings.is_empty());
    }

    #[test]
    fn vitest_not_flagged_as_typosquat() {
        let target = make_target(vec![Dependency {
            name: "vitest".into(),
            version_constraint: Some("^1.0.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "npm".into(),
            is_dev: true,
            location: None,
        }]);
        let findings = TyposquatDetector.run(&target);
        assert!(
            findings.is_empty(),
            "vitest should not be flagged as typosquat of pytest"
        );
    }

    #[test]
    fn nuxt_not_flagged_as_typosquat() {
        let target = make_target(vec![Dependency {
            name: "nuxt".into(),
            version_constraint: Some("^3.0.0".into()),
            locked_version: None,
            locked_hash: None,
            registry: "npm".into(),
            is_dev: false,
            location: None,
        }]);
        let findings = TyposquatDetector.run(&target);
        assert!(
            findings.is_empty(),
            "nuxt should not be flagged as typosquat of next"
        );
    }
}
