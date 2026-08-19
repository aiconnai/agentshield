#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

use agentshield::adapter::mcp::extract_mcp_tools_from_source;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = extract_mcp_tools_from_source(Path::new("server.ts"), s);
        let _ = extract_mcp_tools_from_source(Path::new("server.py"), s);
    }
});
