use std::path::{Path, PathBuf};

use agentshield::error::Result;
use agentshield::fix::FixEngine;
use agentshield::{ScanOptions, scan};

pub struct FixArgs {
    pub path: PathBuf,
    pub dry_run: bool,
    pub rules: Vec<String>,
}

pub fn cmd_fix(args: FixArgs) -> Result<i32> {
    let scan_path = if args.path.is_file() {
        args.path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        args.path.clone()
    };

    println!(
        "Scanning target for fixable findings: {}",
        scan_path.display()
    );

    let options = ScanOptions::default();
    let report = scan(&scan_path, &options)?;

    if report.findings.is_empty() {
        println!("No findings detected to fix.");
        return Ok(0);
    }

    let filter_rules = if args.rules.is_empty() {
        None
    } else {
        Some(args.rules.as_slice())
    };

    let engine = FixEngine::new();
    let patches = engine.generate_patches(&report.findings, &report.scan_root, filter_rules)?;

    if patches.is_empty() {
        println!("No autofixes available for detected findings.");
        return Ok(0);
    }

    let total_fixes: usize = patches.iter().map(|p| p.applied_fixes.len()).sum();

    if args.dry_run {
        println!(
            "\n[DRY RUN] Proposed {} fix(es) across {} file(s):\n",
            total_fixes,
            patches.len()
        );
        for patch in &patches {
            println!("{}", patch.render_diff());
        }
        return Ok(0);
    }

    println!(
        "\nApplying {} fix(es) across {} file(s)...",
        total_fixes,
        patches.len()
    );

    for patch in &patches {
        patch
            .write_to_disk()
            .map_err(agentshield::error::ShieldError::Io)?;
        println!("  Fixed: {}", patch.file_path.display());
        for fix in &patch.applied_fixes {
            println!(
                "    - [{}] line {}: {}",
                fix.rule_id, fix.line_number, fix.description
            );
        }
    }

    println!(
        "\nSuccessfully applied {} fix(es). Run `agentshield scan` to verify.",
        total_fixes
    );
    Ok(0)
}
