#![no_main]

use libfuzzer_sys::fuzz_target;
use std::path::Path;

use agentshield::ir::Language;
use agentshield::parser::parser_for_language;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Some(parser) = parser_for_language(Language::TypeScript) {
            let path = Path::new("server.ts");
            let _ = parser.parse_file(path, s);
        }
    }
});
