use std::path::{Path, PathBuf};

use crate::config::ScanPathFilter;
use crate::error::Result;
use crate::ir::taint_builder::build_data_surface;
use crate::ir::*;

/// OpenClaw Skills adapter.
///
/// Detects by presence of `SKILL.md` at repository root or under
/// `.agents/skills/<skill-name>/SKILL.md`.
pub struct OpenClawAdapter;

impl super::Adapter for OpenClawAdapter {
    fn framework(&self) -> Framework {
        Framework::OpenClaw
    }

    fn detect(&self, root: &Path) -> bool {
        !find_openclaw_skill_roots(root).is_empty()
    }

    fn load(&self, root: &Path, ignore_tests: bool) -> Result<Vec<ScanTarget>> {
        let filter = ScanPathFilter::for_ignore_tests(ignore_tests);
        self.load_with_filter(root, &filter)
    }

    fn load_with_filter(&self, root: &Path, filter: &ScanPathFilter) -> Result<Vec<ScanTarget>> {
        find_openclaw_skill_roots(root)
            .into_iter()
            .map(|skill_root| load_skill_target(root, &skill_root, filter))
            .collect()
    }
}

fn load_skill_target(
    scan_root: &Path,
    skill_root: &Path,
    filter: &ScanPathFilter,
) -> Result<ScanTarget> {
    let name = skill_root
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| "openclaw-skill".to_owned());
    let source_files = collect_skill_source_files(scan_root, skill_root, filter)?;
    let execution = super::pipeline::build_execution_surface(&source_files);
    let tools = Vec::new();
    let data = build_data_surface(&tools, &execution);

    Ok(ScanTarget {
        name,
        framework: Framework::OpenClaw,
        root_path: skill_root.to_path_buf(),
        tools,
        execution,
        data,
        dependencies: Default::default(),
        provenance: Default::default(),
        source_files,
    })
}

fn collect_skill_source_files(
    scan_root: &Path,
    skill_root: &Path,
    filter: &ScanPathFilter,
) -> Result<Vec<SourceFile>> {
    let walker = ignore::WalkBuilder::new(skill_root)
        .hidden(true)
        .git_ignore(true)
        .max_depth(Some(3))
        .build();
    let mut source_files = Vec::new();

    for entry in walker.flatten() {
        let path = entry.path();
        if !path.is_file()
            || (filter.ignore_tests() && super::mcp::is_test_file(path))
            || !filter.allows_path(scan_root, path)
        {
            continue;
        }

        let extension = path
            .extension()
            .map(|extension| extension.to_string_lossy())
            .unwrap_or_default();
        let language = Language::from_extension(&extension);
        if !matches!(
            language,
            Language::Python | Language::Shell | Language::Markdown
        ) {
            continue;
        }

        let metadata = std::fs::metadata(path)?;
        if metadata.len() > 1_048_576 {
            continue;
        }

        if let Ok(content) = std::fs::read_to_string(path) {
            use sha2::Digest;
            let content_hash = format!(
                "{:x}",
                sha2::Sha256::new()
                    .chain_update(content.as_bytes())
                    .finalize()
            );
            source_files.push(SourceFile {
                path: path.to_path_buf(),
                language,
                size_bytes: metadata.len(),
                content_hash,
                content,
            });
        }
    }

    Ok(source_files)
}

fn find_openclaw_skill_roots(root: &Path) -> Vec<PathBuf> {
    let mut skills = Vec::new();

    if root.join("SKILL.md").is_file() {
        skills.push(root.to_path_buf());
    }

    let agents_dir = root.join(".agents").join("skills");
    if !agents_dir.is_dir() {
        return skills;
    }

    if let Ok(entries) = std::fs::read_dir(agents_dir) {
        for entry in entries.flatten() {
            let is_directory = entry
                .file_type()
                .map(|file_type| file_type.is_dir())
                .unwrap_or(false);
            if is_directory && entry.path().join("SKILL.md").is_file() {
                skills.push(entry.path());
            }
        }
    }

    skills.sort();
    skills.dedup();
    skills
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use super::OpenClawAdapter;
    use crate::adapter::Adapter;
    use tempfile::tempdir;

    fn write_skill(root: &Path, name: &str, source: &str) -> PathBuf {
        let skill_root = root.join(".agents").join("skills").join(name);
        std::fs::create_dir_all(&skill_root).expect("create skill dir");
        std::fs::write(skill_root.join("SKILL.md"), format!("# {name}\n"))
            .expect("write skill file");
        std::fs::write(skill_root.join("tool.py"), source).expect("write source file");
        skill_root
    }

    #[test]
    fn detects_agents_skills_layout() {
        let temp = tempdir().expect("create tempdir");
        let skill_root = write_skill(temp.path(), "mbras-harness", "def process():\n    pass\n");

        let adapter = OpenClawAdapter;
        let root = temp.path();

        assert!(adapter.detect(root));

        let targets = adapter
            .load(root, false)
            .expect("openclaw load should succeed");
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].name, "mbras-harness");
        assert_eq!(targets[0].root_path, skill_root);
        assert!(!targets[0].source_files.is_empty());
    }

    #[test]
    fn loads_each_skill_as_an_isolated_target_in_stable_order() {
        let temp = tempdir().expect("create tempdir");
        let alpha = write_skill(
            temp.path(),
            "alpha",
            "import subprocess\nsubprocess.run(user_input, shell=True)\n",
        );
        let zulu = write_skill(
            temp.path(),
            "zulu",
            "import requests\nrequests.get(user_url)\n",
        );

        let targets = OpenClawAdapter
            .load(temp.path(), false)
            .expect("load isolated skills");

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].name, "alpha");
        assert_eq!(targets[0].root_path, alpha);
        assert!(targets[0]
            .source_files
            .iter()
            .all(|source| source.path.starts_with(&targets[0].root_path)));
        assert!(!targets[0].execution.commands.is_empty());
        assert!(targets[0].execution.network_operations.is_empty());

        assert_eq!(targets[1].name, "zulu");
        assert_eq!(targets[1].root_path, zulu);
        assert!(targets[1]
            .source_files
            .iter()
            .all(|source| source.path.starts_with(&targets[1].root_path)));
        assert!(targets[1].execution.commands.is_empty());
        assert!(!targets[1].execution.network_operations.is_empty());
    }

    #[test]
    fn does_not_treat_deeper_nested_skill_as_direct_layout() {
        let temp = tempdir().expect("create tempdir");
        let nested = temp
            .path()
            .join(".agents")
            .join("skills")
            .join("group")
            .join("nested");
        std::fs::create_dir_all(&nested).expect("create nested dir");
        std::fs::write(nested.join("SKILL.md"), "# nested\n").expect("write nested skill");

        assert!(!OpenClawAdapter.detect(temp.path()));
    }

    #[test]
    fn root_skill_and_agents_skill_remain_separate_targets() {
        let temp = tempdir().expect("create tempdir");
        std::fs::write(temp.path().join("SKILL.md"), "# root\n").expect("write root skill");
        let nested = write_skill(temp.path(), "nested", "def nested():\n    pass\n");

        let targets = OpenClawAdapter
            .load(temp.path(), false)
            .expect("load root and nested skills");

        assert_eq!(targets.len(), 2);
        assert_eq!(targets[0].root_path, temp.path());
        assert_eq!(targets[1].root_path, nested);
    }
}
