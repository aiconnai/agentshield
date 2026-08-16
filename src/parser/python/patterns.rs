use once_cell::sync::Lazy;
use regex::Regex;

// Dangerous subprocess/exec functions
pub(crate) static SUBPROCESS_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "subprocess.run",
        "subprocess.call",
        "subprocess.check_call",
        "subprocess.check_output",
        "subprocess.Popen",
        "os.system",
        "os.popen",
        "os.exec",
        "os.execv",
        "os.execve",
        "os.execvp",
    ]
});

// GitPython's `repo.git.*` methods are dynamic dispatchers that execute
// `git <method> ...` as shell commands. We match the `.git.` segment.
pub(crate) static GITPYTHON_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)(\w+)\.git\.(\w+)\s*\(([^)]*)\)")
        .expect("pub(crate) static regex pattern is valid")
});

pub(crate) static NETWORK_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "requests.get",
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "requests.head",
        "requests.request",
        "urllib.request.urlopen",
        "httpx.get",
        "httpx.post",
        "httpx.put",
        // httpx.AsyncClient and aiohttp.ClientSession are tracked via
        // HTTP_CLIENT_CTX_RE + HTTP_CLIENT_METHODS instead, so their actual
        // method calls (client.get, session.post) are detected as network ops.
    ]
});

// HTTP method names used on client variables (e.g. `client.get(url)` where
// `client` was bound from `httpx.AsyncClient()` or `aiohttp.ClientSession()`).
// Checked separately from NETWORK_PATTERNS because the caller object is a
// variable, not a known module.
pub(crate) static HTTP_CLIENT_METHODS: Lazy<Vec<&str>> = Lazy::new(|| {
    vec![
        "get", "post", "put", "patch", "delete", "head", "options", "request", "fetch", "send",
    ]
});

// Regex to detect async context managers that produce HTTP clients.
// Matches: `async with httpx.AsyncClient(...) as <name>:`
//          `async with aiohttp.ClientSession(...) as <name>:`
pub(crate) static HTTP_CLIENT_CTX_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r"(?m)async\s+with\s+(?:\w+\.)*(?:AsyncClient|ClientSession)\s*\([^)]*\)\s+as\s+(\w+)",
    )
    .expect("pub(crate) static regex pattern is valid")
});

pub(crate) static DYNAMIC_EXEC_PATTERNS: Lazy<Vec<&str>> =
    Lazy::new(|| vec!["eval", "exec", "compile", "__import__"]);

pub(crate) static FILE_READ_PATTERNS: Lazy<Vec<&str>> = Lazy::new(|| vec!["open", "pathlib.Path"]);

// Regex to find function calls with arguments: func_name(args)
pub(crate) static CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)(\w+(?:\.\w+)*)\s*\(([^)]*)\)")
        .expect("pub(crate) static regex pattern is valid")
});

// Regex to find the start of a multi-line call: func_name( with no closing )
// Captures the function name so we can match it against patterns, then look
// ahead to the next line(s) for the first argument.
pub(crate) static PARTIAL_CALL_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+(?:\.\w+)*)\s*\(\s*$").expect("pub(crate) static regex pattern is valid")
});

// Regex to find os.environ / os.getenv patterns
pub(crate) static ENV_ACCESS_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(
        r#"(?m)os\.(?:environ\s*(?:\[\s*["']([^"']+)["']\s*\]|\.get\s*\(\s*["']([^"']+)["'])|getenv\s*\(\s*["']([^"']+)["']\s*\))"#,
    )
    .expect("pub(crate) static regex pattern is valid")
});

// Regex to find function definitions and their parameters
pub(crate) static FUNC_DEF_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?:async\s+)?def\s+(\w+)\s*\(([^)]*)\)")
        .expect("pub(crate) static regex pattern is valid")
});

// Sanitizer assignment: valid_path = validate_path(x) or valid_path = await validate_path(x)
pub(crate) static SANITIZER_ASSIGN_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(\w+)\s*=\s*(?:await\s+)?(\w+(?:\.\w+)*)\s*\(")
        .expect("pub(crate) static regex pattern is valid")
});
