use super::*;
use crate::parser;
use std::path::Path;

#[test]
fn test_file_detection_covers_shell_and_suffix_python_tests() {
    assert!(is_test_file(Path::new("scripts/check.test.sh")));
    assert!(is_test_file(Path::new("scripts/check.spec.sh")));
    assert!(is_test_file(Path::new("scripts/import_data_test.py")));
    assert!(is_test_file(Path::new("tests/unit.py")));
    assert!(!is_test_file(Path::new("scripts/load.py")));
}

#[test]
fn extracts_typescript_mcp_server_tool_declarations() {
    let content = r#"
const server = new McpServer({ name: "demo" })

server.tool(
  'search_party',
  'Busca fuzzy por nome.',
  {},
  async () => ({ content: [] })
)

server.registerTool("create_report", { description: "Create report" }, async () => {})
"#;

    let tools =
        extract_mcp_tool_declarations_from_source(Path::new("src/mcp/server.ts"), content)
            .into_iter()
            .map(|declaration| declaration.tool)
            .collect::<Vec<_>>();
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "search_party");
    assert_eq!(
        tools[0].description.as_deref(),
        Some("Busca fuzzy por nome.")
    );
    assert_eq!(tools[0].defined_at.as_ref().map(|loc| loc.line), Some(4));
    assert_eq!(tools[1].name, "create_report");
    assert_eq!(tools[1].description.as_deref(), Some("Create report"));
}

#[test]
fn extracts_config_description_and_inline_handler_binding() {
    let content = r#"
server.registerTool(
  "create_report",
  {
    description: "Create a local report",
    inputSchema: { path: { type: "string", description: "Output path" } },
  },
  async ({ path }) => {
    await writeFile(path, "report");
  },
)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].tool.name, "create_report");
    assert_eq!(
        declarations[0].tool.description.as_deref(),
        Some("Create a local report")
    );
    assert!(matches!(
        declarations[0].handler,
        Some(McpToolHandler::Inline { .. })
    ));
}

#[test]
fn extracts_named_handler_binding_without_using_nested_descriptions() {
    let content = r#"
server.registerTool(
  "fetch_report",
  {
    inputSchema: { url: { type: "string", description: "Remote URL" } },
    description: "Fetch a report from a URL",
  },
  fetchReport,
)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(
        declarations[0].tool.description.as_deref(),
        Some("Fetch a report from a URL")
    );
    assert!(matches!(
        declarations[0].handler,
        Some(McpToolHandler::Named { ref symbol }) if symbol == "fetchReport"
    ));
}

#[test]
fn extracts_tool_callback_after_description_and_schema_arguments() {
    let content = r#"
server.tool(
  "read_file",
  "Read a local file",
  { path: z.string() },
  handleReadFile,
)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(
        declarations[0].tool.description.as_deref(),
        Some("Read a local file")
    );
    assert!(matches!(
        declarations[0].handler,
        Some(McpToolHandler::Named { ref symbol }) if symbol == "handleReadFile"
    ));
}

#[test]
fn duplicate_tool_prefers_declaration_with_handler_binding() {
    let content = r#"
server.registerTool("report", { description: "Incomplete declaration" })
server.registerTool(
  "report",
  { description: "Bound declaration" },
  async () => ({ content: [] }),
)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(
        declarations[0].tool.description.as_deref(),
        Some("Bound declaration")
    );
    assert!(matches!(
        declarations[0].handler,
        Some(McpToolHandler::Inline { .. })
    ));
}

#[test]
fn schema_arrow_function_is_not_misclassified_as_handler() {
    let content = r#"
server.tool(
  "read_file",
  "Read a local file",
  { path: z.string().transform(value => value.trim()) },
)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].handler, None);
}

#[test]
fn arrow_text_in_config_description_is_not_misclassified_as_handler() {
    let content = r#"
server.registerTool("map_value", {
  description: "Maps a => b",
  inputSchema: { value: { type: "string" } },
})
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(
        declarations[0].tool.description.as_deref(),
        Some("Maps a => b")
    );
    assert_eq!(declarations[0].handler, None);
}

#[test]
fn reserved_literals_are_not_named_handlers() {
    for candidate in ["async", "true", "false", "null", "undefined", "this"] {
        assert_eq!(
            parse_mcp_tool_handler(Path::new("src/server.ts"), candidate, 0, candidate.len()),
            None,
            "{candidate} must not be classified as a named handler"
        );
    }
}

#[test]
fn handler_names_with_function_prefix_remain_named() {
    let candidate = "functionHandler";
    assert!(matches!(
        parse_mcp_tool_handler(Path::new("src/server.ts"), candidate, 0, candidate.len()),
        Some(McpToolHandler::Named { ref symbol }) if symbol == candidate
    ));

    let inline = "async() => ({ content: [] })";
    assert!(matches!(
        parse_mcp_tool_handler(Path::new("src/server.ts"), inline, 0, inline.len()),
        Some(McpToolHandler::Inline { .. })
    ));
}

#[test]
fn ignores_tool_calls_inside_comments_and_strings() {
    let content = r#"
// server.tool("commented", "Nope", async () => {})
const docs = 'call server.registerTool("string", {}, handler)'
/* server.registerTool("blocked", {}, handler) */
server.registerTool("real", { description: "Real tool" }, handlers.run)
"#;

    let declarations =
        extract_mcp_tool_declarations_from_source(Path::new("src/server.ts"), content);

    assert_eq!(declarations.len(), 1);
    assert_eq!(declarations[0].tool.name, "real");
    assert!(matches!(
        declarations[0].handler,
        Some(McpToolHandler::Named { ref symbol }) if symbol == "handlers.run"
    ));
}

#[cfg(feature = "typescript")]
#[test]
fn binds_named_handlers_without_cross_tool_operation_leakage() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("read_file", { description: "Read a file" }, handleRead)
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)

async function handleRead(path: string) {
  return readFile(path)
}

async function handleFetch(url: string) {
  return fetch(url)
}
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 2);
    assert!(bindings[0].handler_resolved);
    assert!(bindings[0].observation_complete);
    assert_eq!(bindings[0].execution.file_operations.len(), 1);
    assert!(bindings[0].execution.network_operations.is_empty());
    assert!(bindings[1].handler_resolved);
    assert!(bindings[1].observation_complete);
    assert!(bindings[1].execution.file_operations.is_empty());
    assert_eq!(bindings[1].execution.network_operations.len(), 1);
}

#[cfg(feature = "typescript")]
#[test]
fn binds_inline_handler_and_one_hop_in_project_callee() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool(
  "fetch_report",
  { description: "Fetch a report" },
  async (url: string) => {
    await writeFile("audit.log", "started")
    return fetchThroughClient(url)
  },
)

async function fetchThroughClient(url: string) {
  return fetch(url)
}
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(bindings[0].observation_complete);
    assert_eq!(bindings[0].resolved_callees, vec!["fetchThroughClient"]);
    assert_eq!(bindings[0].execution.file_operations.len(), 1);
    assert_eq!(bindings[0].execution.network_operations.len(), 1);
}

#[cfg(feature = "typescript")]
#[test]
fn operation_binding_stops_after_one_callee_hop() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("report", { description: "Build report" }, handleReport)

async function handleReport() {
  return firstHop()
}

async function firstHop() {
  return secondHop()
}

async function secondHop() {
  return fetch("https://example.com")
}
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(!bindings[0].observation_complete);
    assert_eq!(bindings[0].resolved_callees, vec!["firstHop"]);
    assert!(
        bindings[0].execution.network_operations.is_empty(),
        "depth-2 operations must not be attributed to the tool"
    );
}

#[cfg(feature = "typescript")]
#[test]
fn opaque_call_keeps_operation_observation_incomplete() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("report", { description: "Fetch URLs" }, handleReport)

async function handleReport(url: string) {
  return externalClient(url)
}
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(!bindings[0].observation_complete);
    assert!(bindings[0].execution.network_operations.is_empty());
}

#[cfg(feature = "typescript")]
#[test]
fn dynamic_execution_keeps_operation_observation_incomplete() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("evaluate", { description: "Evaluate arbitrary code" }, handleEval)
function handleEval(code: string) { return eval(code) }
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(!bindings[0].observation_complete);
    assert_eq!(bindings[0].execution.dynamic_exec.len(), 1);
}

#[cfg(feature = "typescript")]
#[test]
fn uncalled_nested_function_operations_are_not_attributed_to_handler() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("report", { description: "Build report" }, handleReport)

async function handleReport() {
  async function unusedNetworkHelper() {
    return fetch("https://example.com")
  }
  return "local report"
}
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(bindings[0].observation_complete);
    assert!(bindings[0].resolved_callees.is_empty());
    assert!(
        bindings[0].execution.network_operations.is_empty(),
        "an uncalled nested function is not part of handler execution"
    );
}

#[cfg(feature = "typescript")]
#[test]
fn ambiguous_named_handler_stays_unresolved() {
    use crate::parser::LanguageParser;

    let registration_path = Path::new("src/server.ts");
    let registration =
        r#"server.registerTool("report", { description: "Report" }, handleReport)"#;
    let first_path = Path::new("src/first.ts");
    let first = "function handleReport() { return readFile('report.txt') }";
    let second_path = Path::new("src/second.ts");
    let second = "function handleReport() { return fetch('https://example.com') }";

    let declarations =
        extract_mcp_tool_declarations_from_source(registration_path, registration);
    let parsed_files = vec![
        (
            first_path.to_path_buf(),
            parser::typescript::TypeScriptParser
                .parse_file(first_path, first)
                .unwrap(),
        ),
        (
            second_path.to_path_buf(),
            parser::typescript::TypeScriptParser
                .parse_file(second_path, second)
                .unwrap(),
        ),
    ];

    let bindings = bind_mcp_tool_operations(&declarations, &parsed_files);

    assert_eq!(bindings.len(), 1);
    assert!(!bindings[0].handler_resolved);
    assert!(!bindings[0].observation_complete);
    assert!(bindings[0].execution.file_operations.is_empty());
    assert!(bindings[0].execution.network_operations.is_empty());
}

#[cfg(feature = "typescript")]
#[test]
fn resolves_named_handler_across_source_files() {
    use crate::parser::LanguageParser;

    let registration_path = Path::new("src/server.ts");
    let registration =
        r#"server.registerTool("report", { description: "Report" }, handleReport)"#;
    let handler_path = Path::new("src/handlers.ts");
    let handler = "function handleReport() { return readFile('report.txt') }";

    let declarations =
        extract_mcp_tool_declarations_from_source(registration_path, registration);
    let parsed_files = vec![(
        handler_path.to_path_buf(),
        parser::typescript::TypeScriptParser
            .parse_file(handler_path, handler)
            .unwrap(),
    )];

    let bindings = bind_mcp_tool_operations(&declarations, &parsed_files);

    assert_eq!(bindings.len(), 1);
    assert!(bindings[0].handler_resolved);
    assert!(bindings[0].observation_complete);
    assert_eq!(bindings[0].execution.file_operations.len(), 1);
}

#[cfg(feature = "typescript")]
#[test]
fn dotted_named_handler_stays_unresolved_without_member_resolution() {
    use crate::parser::LanguageParser;

    let path = Path::new("src/server.ts");
    let content = r#"
server.registerTool("report", { description: "Report" }, handlers.run)
function run() { return readFile("report.txt") }
"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);
    let parsed = parser::typescript::TypeScriptParser
        .parse_file(path, content)
        .unwrap();

    let bindings = bind_mcp_tool_operations(&declarations, &[(path.to_path_buf(), parsed)]);

    assert_eq!(bindings.len(), 1);
    assert!(!bindings[0].handler_resolved);
    assert!(!bindings[0].observation_complete);
    assert!(bindings[0].execution.file_operations.is_empty());
}

#[cfg(feature = "typescript")]
#[test]
fn adapter_load_projects_per_tool_observed_capabilities() {
    use crate::adapter::Adapter;

    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.path().join("server.ts"),
        r#"
server.registerTool("read_file", { description: "Read a file" }, handleRead)
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)

function handleRead(path: string) { return readFile(path) }
function handleFetch(url: string) { return fetch(url) }
"#,
    )
    .unwrap();

    let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
    let read = target
        .tools
        .iter()
        .find(|tool| tool.name == "read_file")
        .unwrap();
    let fetch = target
        .tools
        .iter()
        .find(|tool| tool.name == "fetch_url")
        .unwrap();

    assert_eq!(
        read.observed_capabilities,
        std::collections::BTreeSet::from([Capability::FsRead])
    );
    assert!(
        read.capability_evidence
            .iter()
            .all(|evidence| evidence.capability == Capability::FsRead)
    );
    assert_eq!(
        fetch.observed_capabilities,
        std::collections::BTreeSet::from([Capability::NetworkEgress])
    );
    assert!(read.capability_observation_complete);
    assert!(fetch.capability_observation_complete);
}

#[cfg(not(feature = "typescript"))]
#[test]
fn adapter_load_without_typescript_keeps_observed_capabilities_empty() {
    use crate::adapter::Adapter;

    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.path().join("server.ts"),
        r#"
server.registerTool("fetch_url", { description: "Fetch a URL" }, handleFetch)
function handleFetch(url: string) { return fetch(url) }
"#,
    )
    .unwrap();

    let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
    let tool = target
        .tools
        .iter()
        .find(|tool| tool.name == "fetch_url")
        .unwrap();

    assert!(tool.observed_capabilities.is_empty());
    assert!(tool.capability_evidence.is_empty());
    assert!(!tool.capability_observation_complete);
}

#[test]
fn adapter_load_projects_permissions_but_not_input_schema() {
    use crate::adapter::Adapter;

    let fixture = tempfile::tempdir().unwrap();
    std::fs::write(
        fixture.path().join("package.json"),
        r#"{"dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#,
    )
    .unwrap();
    std::fs::write(
        fixture.path().join("tools.json"),
        r#"{
  "tools": [
    {
      "name": "fetch_url",
      "description": "Fetch URLs",
      "inputSchema": {"properties": {"url": {"type": "string"}}}
    },
    {
      "name": "schema_only",
      "inputSchema": {"properties": {"url": {"type": "string"}}}
    }
  ]
}"#,
    )
    .unwrap();

    let target = McpAdapter.load(fixture.path(), false).unwrap().remove(0);
    let fetch = target
        .tools
        .iter()
        .find(|tool| tool.name == "fetch_url")
        .unwrap();
    let schema_only = target
        .tools
        .iter()
        .find(|tool| tool.name == "schema_only")
        .unwrap();

    assert_eq!(
        fetch.declared_capabilities,
        std::collections::BTreeSet::from([Capability::NetworkEgress])
    );
    assert_eq!(
        fetch
            .capability_declarations
            .iter()
            .filter(|declaration| {
                declaration.source == CapabilityDeclarationSource::Description
            })
            .count(),
        1
    );
    assert_eq!(
        fetch
            .capability_declarations
            .iter()
            .filter(|declaration| {
                declaration.source == CapabilityDeclarationSource::Permission
            })
            .count(),
        1
    );
    assert!(schema_only.declared_capabilities.is_empty());
    assert!(schema_only.capability_declarations.is_empty());
}

#[cfg(not(feature = "typescript"))]
#[test]
fn no_typescript_feature_keeps_operation_binding_unresolved() {
    let path = Path::new("src/server.ts");
    let content = r#"server.registerTool("fetch", { description: "Fetch" }, handleFetch)"#;
    let declarations = extract_mcp_tool_declarations_from_source(path, content);

    let bindings = bind_mcp_tool_operations(&declarations, &[]);

    assert_eq!(bindings.len(), 1);
    assert!(!bindings[0].handler_resolved);
    assert!(bindings[0].execution.network_operations.is_empty());
    assert!(bindings[0].resolved_callees.is_empty());
}

#[test]
fn extracts_python_mcp_tool_decorators() {
    let content = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool(name="search", description="Search web")
async def search(query: str):
    return []

@mcp.tool()
def status():
    return {}
"#;

    let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
    assert_eq!(tools.len(), 2);
    assert_eq!(tools[0].name, "search");
    assert_eq!(tools[0].description.as_deref(), Some("Search web"));
    assert_eq!(tools[1].name, "status");
}

#[test]
fn extracts_python_mcp_tool_call_syntax() {
    let content = r#"
server = FastMCP("demo")

server.tool("echo", "Run echo command")
"#;

    let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "echo");
    assert_eq!(tools[0].description.as_deref(), Some("Run echo command"));
}

#[test]
fn extracts_python_bare_mcp_tool_decorators() {
    let content = r#"
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool
def calculate(expr: str):
    return eval(expr)
"#;

    let tools = extract_mcp_tools_from_source(Path::new("src/mcp/server.py"), content);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "calculate");
}

#[test]
fn extracts_python_kwarg_tool_without_key_substring_collision() {
    let content = r#"
@mcp.tool(filename="report.txt", name="export_report", description="Export")
def export():
    pass
"#;
    let tools = extract_mcp_tools_from_source(Path::new("test.py"), content);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "export_report");
    assert_eq!(tools[0].description.as_deref(), Some("Export"));
}

#[test]
fn extracts_python_pep695_generic_function_name() {
    let content = r#"
@mcp.tool
def generic_runner[T: str](item: T):
    pass
"#;
    let tools = extract_mcp_tools_from_source(Path::new("test.py"), content);
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "generic_runner");
}

#[test]
fn adapter_load_succeeds_on_empty_directory() {
    use crate::adapter::Adapter;
    let temp = tempfile::tempdir().unwrap();
    let result = McpAdapter.load(temp.path(), false);
    assert!(result.is_ok());
    let targets = result.unwrap();
    assert_eq!(targets.len(), 1);
}
