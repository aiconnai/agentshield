use std::path::Path;

use proptest::prelude::*;

use agentshield::adapter::mcp::extract_mcp_tools_from_source;
use agentshield::analysis::composite_flow::{
    SourceUnit, ToolFlowInput, build_composite_flow_candidates,
};
use agentshield::ir::{Language, SourceLocation};
use agentshield::parser::parser_for_language;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn proptest_typescript_parser_never_panics(s in "\\PC*") {
        if let Some(parser) = parser_for_language(Language::TypeScript) {
            let path = Path::new("server.ts");
            let _ = parser.parse_file(path, &s);
        }
    }

    #[test]
    fn proptest_python_parser_never_panics(s in "\\PC*") {
        if let Some(parser) = parser_for_language(Language::Python) {
            let path = Path::new("server.py");
            let _ = parser.parse_file(path, &s);
        }
    }

    #[test]
    fn proptest_shell_parser_never_panics(s in "\\PC*") {
        if let Some(parser) = parser_for_language(Language::Shell) {
            let path = Path::new("script.sh");
            let _ = parser.parse_file(path, &s);
        }
    }

    #[test]
    fn proptest_mcp_tools_extractor_never_panics(s in "\\PC*") {
        let _ = extract_mcp_tools_from_source(Path::new("server.ts"), &s);
        let _ = extract_mcp_tools_from_source(Path::new("server.py"), &s);
    }

    #[test]
    fn proptest_composite_flow_builder_never_panics(s in "\\PC*") {
        let path = Path::new("src/server.ts");
        let tools = [ToolFlowInput {
            tool_name: "test_tool".into(),
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
            content: &s,
        }];
        let _ = build_composite_flow_candidates(&tools, &sources);
    }
}
