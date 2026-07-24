# Detection Rules

AgentShield ships with 20 built-in detectors targeting the most common security
issues in AI agent extensions. Each rule has an ID, severity, confidence level,
and CWE mapping where applicable.

Each rule also maps to a primary category in the [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) (2025). Rules that additionally touch a secondary category note it in parentheses. The mapping is emitted in SARIF (`tool.driver.taxonomies` plus per-rule `relationships`) and in `agentshield list-rules`.

---

## SHIELD-001: Command Injection

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-78](https://cwe.mitre.org/data/definitions/78.html) |
| Category | Command Injection |
| OWASP MCP | MCP05 (also: MCP02) |

**What it detects:** Calls to `subprocess.run`, `subprocess.Popen`, `subprocess.call`,
`subprocess.check_output`, or `os.system` where the command argument comes from a
tool parameter, interpolated string, or other tainted source.

**Why it matters:** An attacker controlling the command string can execute arbitrary
OS commands on the host machine.

**Example (flagged):**
```python
@server.tool()
def run_command(command: str):
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout
```

**Example (safe):**
```python
@server.tool()
def list_files():
    result = subprocess.run(["ls", "-la"], capture_output=True)
    return result.stdout
```

**Remediation:** Use an allowlist of permitted commands. Avoid `shell=True`.
Pass arguments as a list, not a string.

---

## SHIELD-002: Credential Exfiltration

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-522](https://cwe.mitre.org/data/definitions/522.html) |
| Category | Credential Exfiltration |
| OWASP MCP | MCP06 (also: MCP01) |

**What it detects:** A file that both accesses sensitive environment variables
(`os.environ`, `os.getenv`, `os.environ.get`) and makes outbound HTTP requests
(`requests.post`, `requests.put`, `urllib`, `httpx`). Findings are scoped by file
with proximity-based confidence (same region = High, far apart = Medium).

**Why it matters:** A malicious extension can read API keys, database credentials,
or tokens from environment variables and exfiltrate them to an attacker-controlled server.

**Remediation:** Audit all environment variable access. Ensure secrets are never
passed to outbound HTTP calls. Use an allowlist for permitted outbound domains.

---

## SHIELD-003: SSRF (Server-Side Request Forgery)

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| Category | SSRF |
| OWASP MCP | MCP05 (also: MCP08) |

**What it detects:** HTTP client calls (`requests.get`, `requests.post`, `urllib`,
`httpx`, `aiohttp`, `fetch`) where the URL argument comes from a tool parameter.

**Why it matters:** An attacker can use the extension as a proxy to access internal
services, cloud metadata endpoints (169.254.169.254), or other restricted resources.

**Remediation:** Validate URLs against an allowlist of permitted domains and schemes.
Block private IP ranges and metadata endpoints.

---

## SHIELD-004: Arbitrary File Access

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| Category | Arbitrary File Access |
| OWASP MCP | MCP02 (also: MCP06) |

**What it detects:** File operations (`open`, `read`, `write`, `Path`) where the
file path comes from a tool parameter, allowing path traversal.

**Why it matters:** An attacker can read sensitive files (`/etc/passwd`, `.env`,
SSH keys) or write to arbitrary locations on the filesystem.

**Remediation:** Validate and sanitize file paths. Use a chroot or restrict access
to a specific directory. Reject paths containing `..`.

---

## SHIELD-005: Runtime Package Install

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-829](https://cwe.mitre.org/data/definitions/829.html) |
| Category | Supply Chain |
| OWASP MCP | MCP07 (also: MCP09) |

**What it detects:** Commands that install packages at runtime: `pip install`,
`npm install`, `yarn add`, `apt-get install`, `brew install`.

**Why it matters:** Runtime installation bypasses code review and lockfile
verification. A compromised or typosquatted package gets installed silently.

**Remediation:** Pre-install all dependencies at build time. Never install
packages inside tool handlers.

---

## SHIELD-006: Self-Modification

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) |
| Category | Self-Modification |
| OWASP MCP | MCP09 (also: MCP05) |

**What it detects:** File write operations targeting the extension's own source
files, or write operations with dynamic/parameter-derived paths.

**Why it matters:** A self-modifying extension can inject backdoors, persist
malicious code, or escalate privileges across restarts.

**Remediation:** Extensions should never write to their own source directory.
Write to designated output directories only.

---

## SHIELD-007: Prompt Injection Surface

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | — |
| Category | Prompt Injection Surface |
| OWASP MCP | MCP04 (also: MCP03) |

**What it detects:** Tools that fetch external content via HTTP GET requests and
return it to the LLM without sanitization. External content can contain prompt
injection payloads.

**Why it matters:** An attacker can plant malicious instructions on a web page
that gets fetched by the tool and injected into the LLM's context.

**Remediation:** Sanitize external content before returning it to the LLM.
Strip or escape instruction-like patterns. Consider content-type validation.

---

## SHIELD-008: Excessive Permissions

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-250](https://cwe.mitre.org/data/definitions/250.html) |
| Category | Excessive Permissions |
| OWASP MCP | MCP02 |

**What it detects:** Tools that declare permissions (network, filesystem, process
execution) in their tool surface but don't actually use those capabilities in
their implementation.

**Why it matters:** Overly broad permissions violate the principle of least
privilege and increase the attack surface if the extension is compromised.

**Remediation:** Request only the permissions your extension actually uses.
Remove unused capability declarations.

---

## SHIELD-009: Unpinned Dependencies

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-1104](https://cwe.mitre.org/data/definitions/1104.html) |
| Category | Supply Chain |
| OWASP MCP | MCP07 (also: MCP09) |

**What it detects:** Dependencies with loose version constraints: `>=`, `~=`,
`^`, `*`, or no version at all.

**Why it matters:** Unpinned dependencies can silently upgrade to compromised
versions. A supply chain attacker who publishes a malicious patch version
automatically affects all consumers.

**Remediation:** Pin dependencies to exact versions (e.g., `requests==2.31.0`).
Use a lockfile with hashes for verification.

---

## SHIELD-010: Typosquat Detection

| Field | Value |
|-------|-------|
| Severity | Medium |
| CWE | [CWE-506](https://cwe.mitre.org/data/definitions/506.html) |
| Category | Supply Chain |
| OWASP MCP | MCP07 |

**What it detects:** Package names with Levenshtein distance 1-2 from popular
packages (requests, flask, django, numpy, express, react, etc.). Distance 1
gets High confidence, distance 2 gets Medium.

**Why it matters:** Typosquatting is a common supply chain attack. Packages
like `reqeusts` or `djang0` contain malware but look legitimate at a glance.

**Remediation:** Verify package names carefully. Use `pip install --require-hashes`
or equivalent. Review new dependencies in code review.

---

## SHIELD-011: Dynamic Code Execution

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-95](https://cwe.mitre.org/data/definitions/95.html) |
| Category | Code Injection |
| OWASP MCP | MCP05 |

**What it detects:** Calls to `eval()` or `exec()` where the code argument
comes from a tool parameter, interpolated string, or other tainted source.

**Why it matters:** Dynamic code execution with user-controlled input allows
arbitrary code execution — the most severe class of vulnerability.

**Remediation:** Never use `eval`/`exec` with external input. Use safe
alternatives like `ast.literal_eval` for data parsing, or a proper parser.

---

## SHIELD-012: No Lockfile

| Field | Value |
|-------|-------|
| Severity | Low |
| CWE | — |
| Category | Supply Chain |
| OWASP MCP | MCP07 (also: MCP09) |

**What it detects:** Projects that declare dependencies (in `requirements.txt`,
`pyproject.toml`, `package.json`) but have no corresponding lockfile
(`Pipfile.lock`, `poetry.lock`, `uv.lock`, `package-lock.json`, `yarn.lock`,
`pnpm-lock.yaml`).

**Why it matters:** Without a lockfile, dependency resolution is non-deterministic.
Different environments may install different versions, and there's no cryptographic
verification of package integrity.

**Remediation:** Generate a lockfile: `poetry lock`, `uv lock`, `npm install`,
`yarn install`, or `pip freeze > requirements.txt` with `--require-hashes`.

---

## SHIELD-013: Metadata SSRF

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-918](https://cwe.mitre.org/data/definitions/918.html) |
| Category | SSRF |
| OWASP MCP | MCP05 (also: MCP08) |

**What it detects:** Tool arguments flowing to HTTP requests that could target
cloud metadata endpoints or private networks, plus literal requests to known
metadata or private-network addresses.

**Why it matters:** Metadata endpoints can expose cloud credentials, workload
identity tokens, and instance configuration. A tool that proxies requests to
these addresses can turn ordinary SSRF into credential theft.

**Remediation:** Validate URLs against an allowlist before making requests.
Block private IP ranges, link-local ranges, loopback addresses, and cloud
metadata endpoints such as `169.254.169.254`.

---

## SHIELD-014: Download-Write-Execute Chain

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-494](https://cwe.mitre.org/data/definitions/494.html) |
| Category | Supply Chain |
| OWASP MCP | MCP07 (also: MCP05) |

**What it detects:** HTTP downloads that flow to file writes and then process
execution, or the same high-risk combination appearing in one scan target.

**Why it matters:** Downloading code, writing it to disk, and executing it is a
classic supply-chain compromise path. It bypasses normal dependency review,
lockfiles, and integrity checks.

**Remediation:** Do not execute downloaded files directly. Use package managers
with lockfiles where possible. If download logic is unavoidable, verify content
with trusted checksums or signatures before writing or executing anything.

---

## SHIELD-015: Overbroad Filesystem Scope

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-552](https://cwe.mitre.org/data/definitions/552.html) |
| Category | Arbitrary File Access |
| OWASP MCP | MCP02 (also: MCP06) |

**What it detects:** File operations using overly broad paths such as root,
home directories, glob-all patterns, path traversal patterns, interpolated
paths, or unvalidated path parameters.

**Why it matters:** Agent tools often run with the user's filesystem access. A
tool that accepts broad or unscoped paths can expose private files, source code,
SSH keys, environment files, or writeable locations outside the intended area.

**Remediation:** Restrict file operations to explicit directories. Canonicalize
paths and verify the resolved path remains inside the allowed scope. Reject
root, home, absolute, traversal, and glob-all inputs unless explicitly intended.

---

## SHIELD-016: Unsafe Deserialization

| Field | Value |
|-------|-------|
| Severity | Critical |
| CWE | [CWE-502](https://cwe.mitre.org/data/definitions/502.html) |
| Category | Code Injection |
| OWASP MCP | MCP05 |

**What it detects:** Unsafe deserializers and code execution patterns such as
`pickle.loads`, unsafe `yaml.load`, JavaScript VM execution, or `new Function`
used for data parsing.

**Why it matters:** Deserializing untrusted input with unsafe primitives can
execute attacker-controlled code inside the tool process.

**Remediation:** Use safe data formats and schema validation. Prefer JSON with
validation, `yaml.safe_load()` or an explicit safe loader, and avoid VM/code
execution APIs for deserialization.

---

## SHIELD-017: Archive Traversal (Zip Slip)

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-22](https://cwe.mitre.org/data/definitions/22.html) |
| Category | Arbitrary File Access |
| OWASP MCP | MCP02 (also: MCP05) |

**What it detects:** Archive extraction operations such as `extractall`,
`unpack_archive`, `ZipFile.extract`, `TarFile.extract`, `tar.extract`, or
related libraries without nearby path validation.

**Why it matters:** Crafted archive entries can contain absolute paths or `..`
segments. Extracting them without validation can write files outside the target
directory, overwrite application files, or plant executable payloads.

**Remediation:** Validate every extracted file path before writing. Resolve the
destination path and ensure it stays within the intended directory using
`os.path.commonpath()`, `os.path.realpath()`, `path.resolve()`, or equivalent.
Reject absolute paths and entries containing traversal segments.

---

## SHIELD-018: Secret Leakage

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-532](https://cwe.mitre.org/data/definitions/532.html) |
| Category | Data Exfiltration |
| OWASP MCP | MCP06 (also: MCP10) |

**What it detects:** Secret-store or sensitive environment values flowing to
logs or LLM responses without redaction, plus secret-like environment accesses
near log or response sinks.

**Why it matters:** Agent tools often return data directly to a model or write
verbose diagnostics. Leaking secrets into logs, tool responses, or model context
can expose credentials to users, third-party services, or later prompt context.

**Remediation:** Redact or mask sensitive values before logging or returning
responses. Use a secrets manager, keep raw secrets out of model-visible output,
and centralize redaction helpers for tokens, API keys, passwords, and private
keys.

---

## SHIELD-019: Capability / Description Mismatch

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | — |
| Category | Capability Mismatch |
| OWASP MCP | MCP03 |

**What it detects:** Explicit tool descriptions that declare one or more
capabilities while handler-bound code performs additional, undisclosed
capabilities. Matching uses a small deterministic English phrase table and
does not infer intent from vague descriptions or input-schema field names.
It also reports capabilities promised by the description but absent from code
only when the handler and its in-project callees are completely resolved and no
opaque relevant calls remain.

**Why it matters:** A tool can present itself to the model and user as a narrow
file reader or calculator while quietly making network requests, executing
processes, reading credentials, or performing other sensitive actions.

**Remediation:** Make the description accurately disclose every material
capability, or remove the hidden behavior. Permissions do not substitute for an
honest natural-language description.

---

## SHIELD-020: Arbitrary Read Exfiltration Chain

| Field | Value |
|-------|-------|
| Severity | High |
| CWE | [CWE-200](https://cwe.mitre.org/data/definitions/200.html) |
| Category | Data Exfiltration |
| OWASP MCP | MCP06 |

**What it detects:** A complete, tool-scoped value-flow chain where a tool
argument controls a file-read path and the resulting file content reaches an
HTTP request payload. The detector uses the scanner's precomputed contextual
analysis and does not reparse source code.

**Why it matters:** A malicious or overpowered tool can let an attacker select
a local file and send its contents to a network destination in one invocation.
SHIELD-004 may coexist to identify the arbitrary file access; SHIELD-020
captures the additional exfiltration impact.

**Remediation:** Restrict file reads to an allowlisted root, reject paths outside
that boundary, and never forward raw file contents to an untrusted endpoint.

---

## Severity Levels

| Level | Meaning | Default action |
|-------|---------|----------------|
| Critical | Immediate exploitation risk | Fail scan |
| High | Significant security risk | Fail scan (default threshold) |
| Medium | Moderate risk, may need context | Pass (configurable) |
| Low | Best practice recommendation | Pass |
| Info | Informational | Pass |

## Confidence Levels

| Level | Meaning |
|-------|---------|
| High | Strong pattern match, likely true positive |
| Medium | Pattern match with some ambiguity |
| Low | Heuristic match, may be false positive |
