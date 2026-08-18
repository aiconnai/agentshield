use std::path::Path;

/// Check if a file path belongs to a test file or test directory.
///
/// Matches common conventions across Python, TypeScript, and JavaScript:
/// - Directories: `test/`, `tests/`, `__tests__/`, `__pycache__/`
/// - Suffixes: `.test.{ts,js,tsx,jsx,py,sh}`, `.spec.{ts,js,tsx,jsx,py,sh}`
/// - Python conventions: `test_*.py`, `*_test.py`
/// - Config files: `conftest.py`, `jest.config.*`, `vitest.config.*`, `pytest.ini`, `setup.cfg`
pub fn is_test_file(path: &Path) -> bool {
    // Check if any path component is a test directory
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            let name = name.to_string_lossy();
            if matches!(
                name.as_ref(),
                "test" | "tests" | "__tests__" | "__pycache__"
            ) {
                return true;
            }
        }
    }

    let file_name = match path.file_name() {
        Some(n) => n.to_string_lossy(),
        None => return false,
    };
    let file_name = file_name.as_ref();

    // Test config files
    if matches!(file_name, "conftest.py" | "pytest.ini" | "setup.cfg")
        || file_name.starts_with("jest.config.")
        || file_name.starts_with("vitest.config.")
    {
        return true;
    }

    // pytest conventions: test_*.py and *_test.py
    if file_name.ends_with(".py")
        && (file_name.starts_with("test_") || file_name.ends_with("_test.py"))
    {
        return true;
    }

    // Suffix conventions: *.test.{ts,js,tsx,jsx,py,sh}, *.spec.{ts,js,tsx,jsx,py,sh}
    for suffix in [
        ".test.ts",
        ".test.js",
        ".test.tsx",
        ".test.jsx",
        ".test.py",
        ".test.sh",
        ".spec.ts",
        ".spec.js",
        ".spec.tsx",
        ".spec.jsx",
        ".spec.py",
        ".spec.sh",
    ] {
        if file_name.ends_with(suffix) {
            return true;
        }
    }

    false
}
