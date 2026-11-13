//! End-to-end DSSE v1.0 + in-toto Statement v1 + AgentShield Attestation v2
//! interoperability tests.
//!
//! Verifies that `agentshield certify` output (via `--sign-key <file>` and
//! `--sign-key -` on stdin) validates against a standalone, spec-only DSSE v1.0
//! Pre-Authentication Encoding (PAE) + Ed25519 strict verifier and an
//! independent `agentshield-source-manifest-v1` SHA-256 implementation without
//! calling `agentshield::certify` verification helpers.

use std::collections::BTreeMap;
#[cfg(feature = "python")]
use std::io::Write;
use std::path::Path;
use std::process::Command;
#[cfg(feature = "python")]
use std::process::Stdio;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// RFC 8032 §7.1 Test Vector 1 secret seed (32 bytes, hex).
const RFC8032_TV1_SECRET_HEX: &str =
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// RFC 8032 §7.1 Test Vector 1 corresponding public key (32 bytes, hex).
const RFC8032_TV1_PUBLIC_HEX: &str =
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

const PACKAGE_JSON: &str = r#"{"name":"interop-mcp","version":"1.0.0","dependencies":{"@modelcontextprotocol/sdk":"1.0.0"}}"#;

const SAFE_SERVER_PY: &str = r#"from mcp import Server

server = Server("interop-mcp")

@server.tool("add")
def add(a: int, b: int) -> int:
    return a + b
"#;

#[cfg(feature = "python")]
const VULN_TOOL_PY: &str = r#"import subprocess
from mcp import Server

server = Server("interop-mcp")

@server.tool("run_cmd")
def run_cmd(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout
"#;

fn write_file(root: &Path, rel: &str, content: impl AsRef<[u8]>) {
    let full = root.join(rel);
    if let Some(parent) = full.parent() {
        std::fs::create_dir_all(parent).expect("create parent directory");
    }
    std::fs::write(&full, content).expect("write fixture file");
}

/// Standalone DSSE v1.0 Pre-Authentication Encoding per
/// <https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md>:
/// `"DSSEv1" SP LEN(type) SP type SP LEN(body) SP body`
fn spec_dsse_v1_pae(payload_type: &str, raw_body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload_type.as_bytes());
    out.push(b' ');
    out.extend_from_slice(raw_body.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(raw_body);
    out
}

/// Standalone external DSSE v1.0 verifier operating strictly on raw JSON.
/// Returns `(decoded_statement_json, verified_keyids)`.
fn verify_dsse_v1_external(envelope_json: &str) -> (Value, Vec<String>) {
    let env: Value = serde_json::from_str(envelope_json).expect("valid DSSE JSON");
    let payload_type = env["payloadType"]
        .as_str()
        .expect("DSSE payloadType string");
    assert_eq!(payload_type, "application/vnd.in-toto+json");

    let payload_b64 = env["payload"].as_str().expect("DSSE base64 payload string");
    let raw_payload = BASE64
        .decode(payload_b64)
        .expect("DSSE payload must be valid standard base64");

    let sigs = env["signatures"].as_array().expect("DSSE signatures array");
    assert!(!sigs.is_empty(), "expected at least one DSSE signature");

    let pae_bytes = spec_dsse_v1_pae(payload_type, &raw_payload);
    // Construct legacy non-standard PAE (over base64 text) to assert it does NOT verify.
    let legacy_pae_bytes = spec_dsse_v1_pae(payload_type, payload_b64.as_bytes());

    let mut verified_keyids = Vec::with_capacity(sigs.len());
    for entry in sigs {
        let keyid = entry["keyid"].as_str().expect("signature keyid string");
        let pub_bytes: [u8; 32] = hex::decode(keyid)
            .expect("hex keyid")
            .try_into()
            .expect("32-byte Ed25519 public key");
        let verifying_key =
            VerifyingKey::from_bytes(&pub_bytes).expect("valid Ed25519 public key point");

        let sig_b64 = entry["sig"].as_str().expect("signature sig base64 string");
        let sig_bytes: [u8; 64] = BASE64
            .decode(sig_b64)
            .expect("valid base64 signature")
            .try_into()
            .expect("64-byte Ed25519 signature");
        let signature = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify_strict(&pae_bytes, &signature)
            .expect("DSSE v1.0 standard PAE signature must verify strictly");
        assert!(
            verifying_key
                .verify_strict(&legacy_pae_bytes, &signature)
                .is_err(),
            "Attestation v2 signature must cover raw payload bytes, never base64 text"
        );

        verified_keyids.push(keyid.to_owned());
    }

    let statement: Value =
        serde_json::from_slice(&raw_payload).expect("decoded DSSE payload is JSON statement");
    (statement, verified_keyids)
}

/// Standalone `agentshield-source-manifest-v1` SHA-256 recomputation over an
/// explicit list of relative file paths on disk.
fn independent_manifest_sha256(root: &Path, relative_files: &[&str]) -> String {
    let mut sorted = BTreeMap::new();
    for &rel in relative_files {
        let bytes = std::fs::read(root.join(rel)).expect("read scanned source file");
        let file_sha256 = hex::encode(Sha256::digest(&bytes));
        sorted.insert(rel.replace('\\', "\\\\").replace('\n', "\\n"), file_sha256);
    }

    let mut manifest = String::new();
    for (path, digest) in sorted {
        manifest.push_str(&digest);
        manifest.push_str("  ");
        manifest.push_str(&path);
        manifest.push('\n');
    }
    hex::encode(Sha256::digest(manifest.as_bytes()))
}

#[test]
fn dsse_v1_pae_and_rfc8032_known_answer_vector() {
    let secret_bytes: [u8; 32] = hex::decode(RFC8032_TV1_SECRET_HEX)
        .expect("hex decode secret")
        .try_into()
        .expect("32 bytes");

    let payload_type = "application/vnd.in-toto+json";
    let body = br#"{"_type":"https://in-toto.io/Statement/v1","predicateType":"https://agentshield.dev/attestation/v2"}"#;
    let pae = agentshield::certify::envelope::pae(payload_type, body);
    assert_eq!(
        pae,
        spec_dsse_v1_pae(payload_type, body),
        "PAE byte framing must match DSSE v1.0 specification byte-for-byte"
    );
    assert!(pae.starts_with(b"DSSEv1 28 application/vnd.in-toto+json 100 {"));

    let root = tempfile::tempdir().expect("tempdir");
    let att = agentshield::certify::envelope::build_attestation(root.path(), &[], &[], &[], None);
    let mut env = agentshield::certify::envelope::DsseEnvelope::new(&att).expect("new envelope");
    env.sign(&secret_bytes).expect("sign with RFC 8032 TV1 key");

    let serialized = serde_json::to_string_pretty(&env).expect("serialize DSSE envelope");
    let (statement, keyids) = verify_dsse_v1_external(&serialized);
    assert_eq!(keyids, vec![RFC8032_TV1_PUBLIC_HEX.to_owned()]);
    assert_eq!(statement["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(
        statement["predicateType"],
        "https://agentshield.dev/attestation/v2"
    );
}

#[test]
fn cli_certify_keyfile_interoperates_with_independent_dsse_and_manifest_verifier() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let pkg_a = workspace.path().join("alpha-server");
    write_file(&pkg_a, "package.json", PACKAGE_JSON);
    write_file(&pkg_a, "src/server.py", SAFE_SERVER_PY);
    write_file(&pkg_a, "src/helper.py", "VALUE = 1\n");

    let key_path = workspace.path().join("ed25519.key");
    let secret_bytes = hex::decode(RFC8032_TV1_SECRET_HEX).expect("valid hex");
    std::fs::write(&key_path, &secret_bytes).expect("write key file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 keyfile");
    }

    let out_a = workspace.path().join("alpha.dsse.json");
    let status = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .arg("certify")
        .arg(&pkg_a)
        .arg("--sign-key")
        .arg(&key_path)
        .arg("--output")
        .arg(&out_a)
        .status()
        .expect("invoke agentshield certify");
    assert!(status.success(), "agentshield certify exited with {status}");

    let raw_env_a = std::fs::read_to_string(&out_a).expect("read emitted DSSE file");
    let (stmt_a, keyids_a) = verify_dsse_v1_external(&raw_env_a);
    assert_eq!(keyids_a, vec![RFC8032_TV1_PUBLIC_HEX.to_owned()]);
    assert_eq!(stmt_a["_type"], "https://in-toto.io/Statement/v1");
    assert_eq!(
        stmt_a["predicateType"],
        "https://agentshield.dev/attestation/v2"
    );
    assert_eq!(stmt_a["subject"][0]["name"], "alpha-server");

    let expected_digest_a =
        independent_manifest_sha256(&pkg_a, &["package.json", "src/helper.py", "src/server.py"]);
    assert_eq!(
        stmt_a["subject"][0]["digest"]["sha256"].as_str(),
        Some(expected_digest_a.as_str()),
        "subject sha256 must match standalone agentshield-source-manifest-v1 digest"
    );

    // Identical content under a renamed root directory produces the exact same
    // content-bound subject sha256 digest.
    let pkg_renamed = workspace.path().join("renamed-server");
    write_file(&pkg_renamed, "package.json", PACKAGE_JSON);
    write_file(&pkg_renamed, "src/server.py", SAFE_SERVER_PY);
    write_file(&pkg_renamed, "src/helper.py", "VALUE = 1\n");

    let out_renamed = workspace.path().join("renamed.dsse.json");
    let status = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .arg("certify")
        .arg(&pkg_renamed)
        .arg("--sign-key")
        .arg(&key_path)
        .arg("--output")
        .arg(&out_renamed)
        .status()
        .expect("invoke agentshield certify on renamed root");
    assert!(status.success());

    let (stmt_renamed, _) =
        verify_dsse_v1_external(&std::fs::read_to_string(&out_renamed).expect("read renamed DSSE"));
    assert_eq!(stmt_renamed["subject"][0]["name"], "renamed-server");
    assert_eq!(
        stmt_renamed["subject"][0]["digest"]["sha256"], stmt_a["subject"][0]["digest"]["sha256"],
        "subject digest must be invariant to directory rename"
    );

    // Single-byte edit to a scanned file changes the subject digest deterministically.
    write_file(&pkg_a, "src/helper.py", "VALUE = 2\n");
    let out_mutated = workspace.path().join("mutated.dsse.json");
    let status = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .arg("certify")
        .arg(&pkg_a)
        .arg("--sign-key")
        .arg(&key_path)
        .arg("--output")
        .arg(&out_mutated)
        .status()
        .expect("invoke agentshield certify after mutation");
    assert!(status.success());

    let (stmt_mutated, _) =
        verify_dsse_v1_external(&std::fs::read_to_string(&out_mutated).expect("read mutated DSSE"));
    let expected_mutated =
        independent_manifest_sha256(&pkg_a, &["package.json", "src/helper.py", "src/server.py"]);
    assert_ne!(expected_mutated, expected_digest_a);
    assert_eq!(
        stmt_mutated["subject"][0]["digest"]["sha256"].as_str(),
        Some(expected_mutated.as_str())
    );
}

#[cfg(feature = "python")]
#[test]
fn cli_certify_stdin_hex_key_verifies_and_ignores_untrusted_target_config() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let untrusted = workspace.path().join("untrusted-pkg");
    write_file(&untrusted, "package.json", PACKAGE_JSON);
    write_file(&untrusted, "src/vuln.py", VULN_TOOL_PY);
    // An attacker-controlled `.agentshield.toml` inside the target directory
    // attempting to exclude `src/**` must NOT blind `agentshield certify`.
    write_file(
        &untrusted,
        ".agentshield.toml",
        "[scan]\nexclude = [\"src/**\"]\n",
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_agentshield"))
        .current_dir(workspace.path())
        .arg("certify")
        .arg(&untrusted)
        .arg("--sign-key")
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn agentshield certify --sign-key -");

    {
        let stdin = child.stdin.as_mut().expect("child stdin");
        writeln!(stdin, "{RFC8032_TV1_SECRET_HEX}").expect("write hex key + newline to stdin");
    }

    let output = child.wait_with_output().expect("wait for certify");
    assert!(
        output.status.success(),
        "certify failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("UTF-8 DSSE stdout");
    let (stmt, keyids) = verify_dsse_v1_external(&stdout);
    assert_eq!(keyids, vec![RFC8032_TV1_PUBLIC_HEX.to_owned()]);

    let expected_digest = independent_manifest_sha256(
        &untrusted,
        &[".agentshield.toml", "package.json", "src/vuln.py"],
    );
    assert_eq!(
        stmt["subject"][0]["digest"]["sha256"].as_str(),
        Some(expected_digest.as_str()),
        "untrusted target config must not drop src/vuln.py from attested manifest"
    );

    let findings = stmt["predicate"]["findings"]
        .as_array()
        .expect("predicate.findings array");
    let direct_scan =
        agentshield::scan(&untrusted, &agentshield::ScanOptions::default()).expect("direct scan");
    let direct_fps = direct_scan.finding_fingerprints();
    let expected_shield001_fp = direct_scan
        .findings
        .iter()
        .zip(direct_fps.iter())
        .find(|(f, _)| f.rule_id == "SHIELD-001")
        .map(|(_, fp)| fp.as_str())
        .expect("direct scan detects SHIELD-001");
    assert_eq!(expected_shield001_fp.len(), 64);

    assert!(
        findings.iter().any(|f| {
            f["rule_id"] == "SHIELD-001" && f["fingerprint"].as_str() == Some(expected_shield001_fp)
        }),
        "SHIELD-001 with matching 64-hex fingerprint must be recorded in attestation: {findings:?}"
    );
}
