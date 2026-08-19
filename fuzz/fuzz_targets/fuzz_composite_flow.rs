#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

use agentshield::analysis::composite_flow::{
    SourceUnit, ToolFlowInput, build_composite_flow_candidates,
};
use agentshield::ir::SourceLocation;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let path = Path::new("src/server.ts");
        let tools = [ToolFlowInput {
            tool_name: "fuzz_tool".into(),
            handler: SourceLocation {
                file: path.to_path_buf(),
                line: 1,
                column: 0,
                end_line: None,
                end_column: None,
            },
        }];
        let sources = [SourceUnit {
            path,
            content: s,
        }];
        let _ = build_composite_flow_candidates(&tools, &sources);
    }
});
