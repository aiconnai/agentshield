//! Agent-facing entry points registered through framework APIs must never be
//! proven "safe" by an internal literal call site.
//!
//! Each case writes a handler with a SHIELD-001 sink and a non-test `cli`
//! file that calls it with a literal. Without the cli file the finding is
//! always present; with it, the finding must survive because the framework
//! (not the cli) supplies the handler's real arguments.

use std::path::Path;

use agentshield::{ScanOptions, scan};

type Files<'a> = &'a [(&'a str, &'a str)];

const PY_SINK_IMPORT: &str = "import subprocess\n";
const RUN_CMD_PY: &str =
    "def run_cmd(cmd: str):\n    return subprocess.run(cmd, shell=True).stdout\n";

fn write(root: &Path, rel: &str, content: &str) {
    let target = root.join(rel);
    std::fs::create_dir_all(target.parent().expect("fixture path has a parent"))
        .expect("create fixture dir");
    std::fs::write(target, content).expect("write fixture file");
}

fn has_command_injection(files: Files<'_>) -> bool {
    let dir = tempfile::tempdir().expect("create temp dir");
    for (rel, content) in files {
        write(dir.path(), rel, content);
    }
    scan(dir.path(), &ScanOptions::default())
        .expect("scan succeeds")
        .findings
        .iter()
        .any(|finding| finding.rule_id == "SHIELD-001")
}

/// The handler is flagged on its own and stays flagged when a literal-only
/// cli file calls it.
#[track_caller]
fn assert_survives_cli_call(files: Files<'_>, cli: (&str, &str)) {
    assert!(
        has_command_injection(files),
        "sanity: the handler must be flagged without the cli file"
    );
    let mut with_cli = files.to_vec();
    with_cli.push(cli);
    assert!(
        has_command_injection(&with_cli),
        "a literal call from {} must not clear the registered handler",
        cli.0
    );
}

#[track_caller]
fn assert_clean_with_cli(files: Files<'_>, cli: (&str, &str)) {
    let mut with_cli = files.to_vec();
    with_cli.push(cli);
    assert!(
        !has_command_injection(&with_cli),
        "a helper only called with literals must stay clean"
    );
}

const CLI_RUN_CMD: (&str, &str) = ("cli.py", "from tool import run_cmd\n\nrun_cmd(\"ls\")\n");

// --- 1. Class-based tools -------------------------------------------------

#[test]
fn langchain_base_tool_run_is_an_entry_point() {
    let tool = "import subprocess\nfrom langchain.tools import BaseTool\n\n\nclass RunTool(BaseTool):\n    name: str = \"run\"\n    description: str = \"run\"\n\n    def _run(self, cmd: str) -> str:\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[("tool.py", tool), ("requirements.txt", "langchain\n")],
        (
            "cli.py",
            "from tool import RunTool\n\nprint(RunTool()._run(\"ls\"))\n",
        ),
    );
}

#[test]
fn langchain_base_tool_async_run_is_an_entry_point() {
    let tool = "import subprocess\nfrom langchain_core.tools import BaseTool\n\n\nclass RunTool(BaseTool):\n    name: str = \"run\"\n    description: str = \"run\"\n\n    async def _arun(self, cmd: str) -> str:\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[("tool.py", tool), ("requirements.txt", "langchain\n")],
        (
            "cli.py",
            "from tool import RunTool\n\nRunTool()._arun(\"ls\")\n",
        ),
    );
}

#[test]
fn crewai_base_tool_run_is_an_entry_point() {
    let tool = "import subprocess\nfrom crewai.tools import BaseTool\n\n\nclass RunTool(BaseTool):\n    name: str = \"run\"\n    description: str = \"run\"\n\n    def _run(self, cmd: str) -> str:\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[("tool.py", tool), ("requirements.txt", "crewai\n")],
        (
            "cli.py",
            "from tool import RunTool\n\nRunTool()._run(\"ls\")\n",
        ),
    );
}

#[test]
fn llama_index_base_tool_call_is_an_entry_point() {
    let tool = "import subprocess\nfrom llama_index.core.tools import BaseTool\n\n\nclass RunTool(BaseTool):\n    def call(self, cmd: str):\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[("tool.py", tool), ("requirements.txt", "llama-index\n")],
        (
            "cli.py",
            "from tool import RunTool\n\nRunTool().call(\"ls\")\n",
        ),
    );
}

#[test]
fn llama_index_async_base_tool_acall_is_an_entry_point() {
    let tool = "import subprocess\nfrom llama_index.core.tools.types import AsyncBaseTool\n\n\nclass RunTool(AsyncBaseTool):\n    async def acall(self, cmd: str):\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[("tool.py", tool), ("requirements.txt", "llama-index\n")],
        (
            "cli.py",
            "from tool import RunTool\n\nRunTool().acall(\"ls\")\n",
        ),
    );
}

#[test]
fn tool_class_inherited_through_another_file_is_an_entry_point() {
    let base = "from langchain.tools import BaseTool\n\n\nclass SafeBase(BaseTool):\n    name: str = \"base\"\n    description: str = \"base\"\n";
    let tool = "import subprocess\nfrom base import SafeBase\n\n\nclass RunTool(SafeBase):\n    def _run(self, cmd: str) -> str:\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_survives_cli_call(
        &[
            ("base.py", base),
            ("tool.py", tool),
            ("requirements.txt", "langchain\n"),
        ],
        (
            "cli.py",
            "from tool import RunTool\n\nRunTool()._run(\"ls\")\n",
        ),
    );
}

#[test]
fn non_tool_class_run_method_can_still_be_proven_safe() {
    let tool = "import subprocess\n\n\nclass Runner:\n    def _run(self, cmd: str) -> str:\n        return subprocess.run(cmd, shell=True).stdout\n";
    assert_clean_with_cli(
        &[("tool.py", tool), ("requirements.txt", "langchain\n")],
        (
            "cli.py",
            "from tool import Runner\n\nRunner()._run(\"ls\")\n",
        ),
    );
}

#[test]
fn helper_called_with_literals_from_tool_class_stays_clean() {
    let tool = "import subprocess\nfrom langchain.tools import BaseTool\n\n\ndef list_dir(cmd: str):\n    return subprocess.run(cmd, shell=True).stdout\n\n\nclass RunTool(BaseTool):\n    name: str = \"run\"\n    description: str = \"run\"\n\n    def _run(self) -> str:\n        return list_dir(\"ls\")\n";
    assert_clean_with_cli(
        &[("tool.py", tool), ("requirements.txt", "langchain\n")],
        ("cli.py", "from tool import RunTool\n\nRunTool()._run()\n"),
    );
}

// --- 2. Function-reference registrations (Python) --------------------------

fn tool_with_registration(imports: &str, registration: &str) -> String {
    format!("{PY_SINK_IMPORT}{imports}\n\n{RUN_CMD_PY}\n\n{registration}\n")
}

#[test]
fn llama_index_function_tool_keyword_reference() {
    let tool = tool_with_registration(
        "from llama_index.core.tools import FunctionTool",
        "tool = FunctionTool.from_defaults(fn=run_cmd)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "llama-index\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn llama_index_function_tool_positional_reference() {
    let tool = tool_with_registration(
        "from llama_index.core.tools import FunctionTool",
        "tool = FunctionTool.from_defaults(run_cmd, name=\"run\")",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "llama-index\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn langchain_structured_tool_from_function() {
    let tool = tool_with_registration(
        "from langchain.tools import StructuredTool",
        "tool = StructuredTool.from_function(\n    func=run_cmd,\n    name=\"run\",\n    description=\"run\",\n)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "langchain\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn langchain_structured_tool_from_function_positional() {
    let tool = tool_with_registration(
        "from langchain.tools import StructuredTool",
        "tool = StructuredTool.from_function(run_cmd)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "langchain\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn langchain_tool_constructor_func_keyword() {
    let tool = tool_with_registration(
        "from langchain.agents import Tool",
        "tool = Tool(name=\"run\", func=run_cmd, description=\"run\")",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "langchain\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn autogen_register_function_positional() {
    let tool = tool_with_registration(
        "from autogen import register_function",
        "register_function(run_cmd, caller=assistant, executor=proxy, description=\"run\")",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "autogen\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn autogen_register_function_keyword() {
    let tool = tool_with_registration(
        "from autogen import register_function",
        "register_function(\n    f=run_cmd,\n    caller=assistant,\n    executor=proxy,\n    description=\"run\",\n)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "autogen\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn fastmcp_add_tool_reference() {
    let tool = tool_with_registration(
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"x\")",
        "mcp.add_tool(run_cmd)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "mcp\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn fastmcp_decorator_applied_as_call() {
    let tool = tool_with_registration(
        "from mcp.server.fastmcp import FastMCP\n\nmcp = FastMCP(\"x\")",
        "mcp.tool()(run_cmd)",
    );
    assert_survives_cli_call(
        &[("tool.py", &tool), ("requirements.txt", "mcp\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn registration_in_another_file_marks_the_definition() {
    let handlers = format!("{PY_SINK_IMPORT}\n\n{RUN_CMD_PY}");
    let register = "from llama_index.core.tools import FunctionTool\nfrom handlers import run_cmd\n\ntool = FunctionTool.from_defaults(fn=run_cmd)\n";
    assert_survives_cli_call(
        &[
            ("handlers.py", &handlers),
            ("register.py", register),
            ("requirements.txt", "llama-index\n"),
        ],
        (
            "cli.py",
            "from handlers import run_cmd\n\nrun_cmd(\"ls\")\n",
        ),
    );
}

#[test]
fn aliased_import_registration_marks_the_original_definition() {
    let handlers = format!("{PY_SINK_IMPORT}\n\n{RUN_CMD_PY}");
    let register = "from autogen import register_function\nfrom handlers import run_cmd as shell\n\nregister_function(shell, caller=a, executor=b, description=\"run\")\n";
    assert_survives_cli_call(
        &[
            ("handlers.py", &handlers),
            ("register.py", register),
            ("requirements.txt", "autogen\n"),
        ],
        (
            "cli.py",
            "from handlers import run_cmd\n\nrun_cmd(\"ls\")\n",
        ),
    );
}

#[test]
fn registration_text_in_strings_and_comments_marks_nothing() {
    let tool = tool_with_registration(
        "from llama_index.core.tools import FunctionTool",
        "# FunctionTool.from_defaults(fn=run_cmd)\nDOC = \"register_function(run_cmd)\"",
    );
    assert_clean_with_cli(
        &[("tool.py", &tool), ("requirements.txt", "llama-index\n")],
        CLI_RUN_CMD,
    );
}

#[test]
fn helper_called_with_literals_from_registered_function_stays_clean() {
    let tool = "import subprocess\nfrom llama_index.core.tools import FunctionTool\n\n\ndef list_dir(cmd: str):\n    return subprocess.run(cmd, shell=True).stdout\n\n\ndef listing():\n    return list_dir(\"ls\")\n\n\ntool = FunctionTool.from_defaults(fn=listing)\n";
    assert_clean_with_cli(
        &[("tool.py", tool), ("requirements.txt", "llama-index\n")],
        ("cli.py", "from tool import listing\n\nlisting()\n"),
    );
}

#[test]
fn unregistered_function_can_still_be_proven_safe() {
    let tool = tool_with_registration(
        "from llama_index.core.tools import FunctionTool",
        "def other():\n    return None\n\n\ntool = FunctionTool.from_defaults(fn=other)",
    );
    assert_clean_with_cli(
        &[("tool.py", &tool), ("requirements.txt", "llama-index\n")],
        CLI_RUN_CMD,
    );
}

// --- 3. Vercel AI SDK -------------------------------------------------------

const VERCEL_PACKAGE: &str = r#"{"name":"case","dependencies":{"ai":"4.0.0","zod":"3.0.0"}}"#;
const RUN_CMD_TS: &str = "export function runCmd(cmd: string) {\n  exec(cmd);\n}\n";
const CLI_RUN_CMD_TS: (&str, &str) = (
    "cli.ts",
    "import { runCmd } from \"./tool\";\n\nrunCmd(\"ls\");\n",
);

fn vercel_tool(import: &str, definition: &str) -> String {
    format!(
        "{import}\nimport {{ z }} from \"zod\";\nimport {{ exec }} from \"child_process\";\n\n{RUN_CMD_TS}\n{definition}\n"
    )
}

fn vercel_package(tool: &str) -> [(&str, &str); 2] {
    [("tool.ts", tool), ("package.json", VERCEL_PACKAGE)]
}

#[test]
fn vercel_execute_named_reference() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "export const run = tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: runCmd,\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[test]
fn vercel_execute_bound_reference() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "export const run = tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: runCmd.bind(null),\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[test]
fn vercel_execute_shorthand_property() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "const execute = runCmd;\nexport const run = tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute,\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[test]
fn vercel_aliased_tool_import() {
    let tool = vercel_tool(
        "import { tool as defineTool } from \"ai\";",
        "export const run = defineTool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: runCmd,\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[test]
fn vercel_namespace_tool_import() {
    let tool = vercel_tool(
        "import * as ai from \"ai\";",
        "export const run = ai.tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: runCmd,\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[test]
fn vercel_execute_reference_to_a_function_in_another_file() {
    let handlers = "import { exec } from \"child_process\";\n\nexport function runCmd(cmd: string) {\n  exec(cmd);\n}\n";
    let tool = "import { tool } from \"ai\";\nimport { z } from \"zod\";\nimport { runCmd } from \"./handlers\";\n\nexport const run = tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: runCmd,\n});\n";
    assert_survives_cli_call(
        &[
            ("handlers.ts", handlers),
            ("tool.ts", tool),
            ("package.json", VERCEL_PACKAGE),
        ],
        (
            "cli.ts",
            "import { runCmd } from \"./handlers\";\n\nrunCmd(\"ls\");\n",
        ),
    );
}

#[test]
fn vercel_inline_execute_forwarding_agent_input_stays_flagged() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "export const run = tool({\n  description: \"run\",\n  parameters: z.object({ cmd: z.string() }),\n  execute: async (args) => runCmd(args.cmd),\n});",
    );
    assert_survives_cli_call(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

// The regex fallback TypeScript parser records no call sites, so cross-file
// downgrading (and therefore these "stays clean" cases) needs tree-sitter.
#[cfg(feature = "typescript")]
#[test]
fn vercel_helper_called_with_literals_from_inline_execute_stays_clean() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "export const run = tool({\n  description: \"run\",\n  parameters: z.object({}),\n  execute: async () => runCmd(\"ls\"),\n});",
    );
    assert_clean_with_cli(&vercel_package(&tool), CLI_RUN_CMD_TS);
}

#[cfg(feature = "typescript")]
#[test]
fn vercel_unreferenced_function_can_still_be_proven_safe() {
    let tool = vercel_tool(
        "import { tool } from \"ai\";",
        "export const run = tool({\n  description: \"run\",\n  parameters: z.object({}),\n  execute: async () => \"done\",\n});",
    );
    assert_clean_with_cli(&vercel_package(&tool), CLI_RUN_CMD_TS);
}
