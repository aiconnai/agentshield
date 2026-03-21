//! DSSE envelope and in-toto attestation payload types.
//!
//! Implements the DSSE specification (<https://github.com/secure-systems-lab/dsse>)
//! wrapping an in-toto Statement v1 (<https://in-toto.io/Statement/v1>) with an
//! AgentShield-specific predicate.

use std::collections::HashMap;
use std::path::Path;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::ir::ScanTarget;
use crate::rules::finding::Finding;
use crate::rules::policy::Suppression;

// ---------------------------------------------------------------------------
// DSSE envelope
// ---------------------------------------------------------------------------

/// DSSE envelope per <https://github.com/secure-systems-lab/dsse>.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64-encoded JSON payload.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    /// Base64-encoded Ed25519 signature.
    pub sig: String,
}

// ---------------------------------------------------------------------------
// In-toto attestation payload
// ---------------------------------------------------------------------------

/// In-toto Statement v1 with an AgentShield predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationPayload {
    #[serde(rename = "_type")]
    pub attestation_type: String,
    pub subject: Vec<AttestationSubject>,
    #[serde(rename = "predicateType")]
    pub predicate_type: String,
    pub predicate: ScanAttestation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSubject {
    pub name: String,
    pub digest: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAttestation {
    pub scanner: ScannerInfo,
    pub findings: Vec<FindingSummary>,
    pub suppressions: Vec<SuppressionSummary>,
    pub capabilities: CapabilitySummary,
    pub provenance: Option<ProvenanceSummary>,
    pub egress_policy_hash: Option<String>,
    pub scanned_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannerInfo {
    pub name: String,
    pub version: String,
    pub rule_count: usize,
    pub rules_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FindingSummary {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuppressionSummary {
    pub fingerprint: String,
    pub reason: String,
    pub expires: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitySummary {
    pub declared: Vec<String>,
    pub observed: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvenanceSummary {
    pub author: Option<String>,
    pub repository: Option<String>,
    pub license: Option<String>,
}

// ---------------------------------------------------------------------------
// DSSE PAE (Pre-Authentication Encoding)
// ---------------------------------------------------------------------------

/// Compute DSSE PAE string for signing/verification.
fn pae(payload_type: &str, payload: &str) -> String {
    format!(
        "DSSEv1 {} {} {} {}",
        payload_type.len(),
        payload_type,
        payload.len(),
        payload
    )
}

// ---------------------------------------------------------------------------
// DsseEnvelope implementation
// ---------------------------------------------------------------------------

impl DsseEnvelope {
    /// Create an unsigned envelope from an attestation payload.
    pub fn new(payload: &AttestationPayload) -> Result<Self, crate::error::ShieldError> {
        let payload_json = serde_json::to_string(payload)?;
        let payload_b64 = BASE64.encode(payload_json.as_bytes());

        Ok(Self {
            payload_type: "application/vnd.in-toto+json".to_string(),
            payload: payload_b64,
            signatures: vec![],
        })
    }

    /// Sign the envelope with a 32-byte Ed25519 private key.
    ///
    /// Appends a new signature entry; can be called multiple times for
    /// multi-party signing.
    pub fn sign(&mut self, private_key_bytes: &[u8]) -> Result<(), crate::error::ShieldError> {
        use ed25519_dalek::{Signer, SigningKey};

        let key_array: [u8; 32] = private_key_bytes.try_into().map_err(|_| {
            crate::error::ShieldError::Internal("Invalid key length: expected 32 bytes".to_string())
        })?;
        let signing_key = SigningKey::from_bytes(&key_array);

        let pae_string = pae(&self.payload_type, &self.payload);
        let signature = signing_key.sign(pae_string.as_bytes());
        let public_key = signing_key.verifying_key();

        self.signatures.push(DsseSignature {
            keyid: hex::encode(public_key.as_bytes()),
            sig: BASE64.encode(signature.to_bytes()),
        });

        Ok(())
    }

    /// Verify all signatures in the envelope.
    ///
    /// Returns `Ok(false)` if the envelope is unsigned.
    /// Returns `Err` if any signature is invalid.
    pub fn verify(&self) -> Result<bool, crate::error::ShieldError> {
        if self.signatures.is_empty() {
            return Ok(false);
        }

        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        let pae_string = pae(&self.payload_type, &self.payload);

        for sig in &self.signatures {
            let key_bytes = hex::decode(&sig.keyid).map_err(|e| {
                crate::error::ShieldError::Internal(format!("Invalid keyid hex: {}", e))
            })?;
            let key_array: [u8; 32] = key_bytes.as_slice().try_into().map_err(|_| {
                crate::error::ShieldError::Internal("Invalid key length".to_string())
            })?;
            let verifying_key = VerifyingKey::from_bytes(&key_array).map_err(|e| {
                crate::error::ShieldError::Internal(format!("Invalid verifying key: {}", e))
            })?;

            let sig_bytes = BASE64.decode(&sig.sig).map_err(|e| {
                crate::error::ShieldError::Internal(format!("Invalid signature base64: {}", e))
            })?;
            let sig_array: [u8; 64] = sig_bytes.as_slice().try_into().map_err(|_| {
                crate::error::ShieldError::Internal("Invalid signature length".to_string())
            })?;
            let signature = Signature::from_bytes(&sig_array);

            verifying_key
                .verify(pae_string.as_bytes(), &signature)
                .map_err(|e| {
                    crate::error::ShieldError::Internal(format!(
                        "Signature verification failed: {}",
                        e
                    ))
                })?;
        }

        Ok(true)
    }

    /// Decode and deserialize the payload from the envelope.
    pub fn decode_payload(&self) -> Result<AttestationPayload, crate::error::ShieldError> {
        let payload_bytes = BASE64.decode(&self.payload).map_err(|e| {
            crate::error::ShieldError::Internal(format!("Invalid payload base64: {}", e))
        })?;
        let payload: AttestationPayload = serde_json::from_slice(&payload_bytes)?;
        Ok(payload)
    }
}

// ---------------------------------------------------------------------------
// Attestation builder
// ---------------------------------------------------------------------------

/// Build an in-toto attestation payload from scan results.
pub fn build_attestation(
    scan_root: &Path,
    findings: &[Finding],
    suppressions: &[Suppression],
    targets: &[ScanTarget],
    egress_policy_hash: Option<String>,
) -> AttestationPayload {
    // Subject: the scanned directory name + its hash
    let dir_name = scan_root
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let mut dir_hasher = Sha256::new();
    dir_hasher.update(dir_name.as_bytes());
    let dir_hash = hex::encode(dir_hasher.finalize());

    let subject = AttestationSubject {
        name: dir_name,
        digest: [("sha256".to_string(), dir_hash)].into_iter().collect(),
    };

    // Summarize findings
    let finding_summaries: Vec<FindingSummary> = findings
        .iter()
        .map(|f| FindingSummary {
            fingerprint: f.fingerprint(scan_root),
            rule_id: f.rule_id.clone(),
            severity: format!("{:?}", f.severity),
            confidence: format!("{:?}", f.confidence),
        })
        .collect();

    // Summarize suppressions
    let suppression_summaries: Vec<SuppressionSummary> = suppressions
        .iter()
        .map(|s| SuppressionSummary {
            fingerprint: s.fingerprint.clone(),
            reason: s.reason.clone(),
            expires: s.expires.clone(),
        })
        .collect();

    // Build capability summary from all targets
    let mut declared = Vec::new();
    let mut observed = Vec::new();
    for target in targets {
        for tool in &target.tools {
            for perm in &tool.declared_permissions {
                declared.push(format!("{:?}", perm.permission_type));
            }
        }
        if !target.execution.commands.is_empty() {
            observed.push("ProcessExec".to_string());
        }
        if !target.execution.network_operations.is_empty() {
            observed.push("NetworkAccess".to_string());
        }
        if !target.execution.file_operations.is_empty() {
            observed.push("FileAccess".to_string());
        }
        if !target.execution.dynamic_exec.is_empty() {
            observed.push("DynamicExec".to_string());
        }
    }
    declared.sort();
    declared.dedup();
    observed.sort();
    observed.dedup();

    // Provenance from first target
    let provenance = targets.first().map(|t| ProvenanceSummary {
        author: t.provenance.author.clone(),
        repository: t.provenance.repository.clone(),
        license: t.provenance.license.clone(),
    });

    // Scanner info
    let rule_count = crate::rules::RuleEngine::new().list_rules().len();
    let scanner = ScannerInfo {
        name: "agentshield".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        rule_count,
        rules_version: "v0.5".to_string(),
    };

    AttestationPayload {
        attestation_type: "https://in-toto.io/Statement/v1".to_string(),
        subject: vec![subject],
        predicate_type: "https://agentshield.dev/attestation/v1".to_string(),
        predicate: ScanAttestation {
            scanner,
            findings: finding_summaries,
            suppressions: suppression_summaries,
            capabilities: CapabilitySummary { declared, observed },
            provenance,
            egress_policy_hash,
            scanned_at: chrono::Utc::now().to_rfc3339(),
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::SourceLocation;
    use crate::rules::finding::{AttackCategory, Confidence, Evidence, Severity};
    use std::path::PathBuf;

    /// Helper: build a minimal finding for tests.
    fn make_test_finding(rule_id: &str, file: &str, evidence_desc: &str) -> Finding {
        Finding {
            rule_id: rule_id.to_string(),
            rule_name: "Test Rule".to_string(),
            severity: Severity::High,
            confidence: Confidence::High,
            attack_category: AttackCategory::CommandInjection,
            message: "test finding".to_string(),
            location: Some(SourceLocation {
                file: PathBuf::from(file),
                line: 10,
                column: 0,
                end_line: None,
                end_column: None,
            }),
            evidence: vec![Evidence {
                description: evidence_desc.to_string(),
                location: None,
                snippet: None,
            }],
            taint_path: None,
            remediation: Some("Fix it".to_string()),
            cwe_id: Some("CWE-78".to_string()),
        }
    }

    #[test]
    fn test_attestation_payload_serialization() {
        let scan_root = Path::new("/project");
        let findings = vec![make_test_finding(
            "SHIELD-001",
            "/project/src/main.py",
            "subprocess.run receives parameter",
        )];
        let suppressions = vec![Suppression {
            fingerprint: "abc123".to_string(),
            reason: "False positive".to_string(),
            expires: Some("2099-12-31".to_string()),
            created_at: None,
        }];

        let payload = build_attestation(scan_root, &findings, &suppressions, &[], None);

        let json = serde_json::to_string_pretty(&payload).expect("serialize payload");

        // Verify structure
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(
            parsed["_type"].as_str().unwrap(),
            "https://in-toto.io/Statement/v1"
        );
        assert_eq!(
            parsed["predicateType"].as_str().unwrap(),
            "https://agentshield.dev/attestation/v1"
        );
        assert_eq!(parsed["subject"].as_array().unwrap().len(), 1);
        assert_eq!(parsed["predicate"]["findings"].as_array().unwrap().len(), 1);
        assert_eq!(
            parsed["predicate"]["suppressions"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            parsed["predicate"]["scanner"]["name"].as_str().unwrap(),
            "agentshield"
        );
        assert!(parsed["predicate"]["scanned_at"].as_str().is_some());

        // Finding summary has expected fields
        let fs = &parsed["predicate"]["findings"][0];
        assert_eq!(fs["rule_id"].as_str().unwrap(), "SHIELD-001");
        assert!(fs["fingerprint"].as_str().is_some());
    }

    #[test]
    fn test_unsigned_envelope() {
        let scan_root = Path::new("/project");
        let payload = build_attestation(scan_root, &[], &[], &[], None);
        let envelope = DsseEnvelope::new(&payload).expect("create envelope");

        assert_eq!(envelope.payload_type, "application/vnd.in-toto+json");
        assert!(envelope.signatures.is_empty());

        // Should serialize to valid JSON
        let json = serde_json::to_string(&envelope).expect("serialize envelope");
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse JSON");
        assert_eq!(
            parsed["payloadType"].as_str().unwrap(),
            "application/vnd.in-toto+json"
        );
        assert!(parsed["signatures"].as_array().unwrap().is_empty());

        // Verify returns false for unsigned
        assert!(!envelope.verify().expect("verify unsigned"));
    }

    #[test]
    fn test_sign_and_verify() {
        let scan_root = Path::new("/project");
        let findings = vec![make_test_finding(
            "SHIELD-001",
            "/project/src/main.py",
            "subprocess.run receives parameter",
        )];
        let payload = build_attestation(scan_root, &findings, &[], &[], None);
        let mut envelope = DsseEnvelope::new(&payload).expect("create envelope");

        // Generate a deterministic test key
        let private_key: [u8; 32] = [42u8; 32];
        envelope.sign(&private_key).expect("sign envelope");

        assert_eq!(envelope.signatures.len(), 1);
        assert!(!envelope.signatures[0].keyid.is_empty());
        assert!(!envelope.signatures[0].sig.is_empty());

        // Verification should pass
        assert!(envelope.verify().expect("verify signed"));

        // Decoded payload should match original
        let decoded = envelope.decode_payload().expect("decode payload");
        assert_eq!(decoded.attestation_type, payload.attestation_type);
        assert_eq!(decoded.predicate.findings.len(), 1);
    }

    #[test]
    fn test_tampered_envelope_fails_verify() {
        let scan_root = Path::new("/project");
        let payload = build_attestation(scan_root, &[], &[], &[], None);
        let mut envelope = DsseEnvelope::new(&payload).expect("create envelope");

        let private_key: [u8; 32] = [42u8; 32];
        envelope.sign(&private_key).expect("sign envelope");

        // Tamper with the payload
        let tampered_payload = build_attestation(scan_root, &[], &[], &[], Some("tampered".into()));
        let tampered_json = serde_json::to_string(&tampered_payload).expect("serialize");
        envelope.payload = BASE64.encode(tampered_json.as_bytes());

        // Verification should fail
        let result = envelope.verify();
        assert!(
            result.is_err(),
            "Tampered envelope should fail verification"
        );
    }

    #[test]
    fn test_build_attestation_from_scan() {
        let fixture = Path::new("tests/fixtures/mcp_servers/vuln_cmd_inject");
        let opts = crate::ScanOptions::default();

        let report = crate::scan(fixture, &opts).expect("scan fixture");

        let payload = build_attestation(
            &report.scan_root,
            &report.findings,
            &[],
            &report.targets,
            None,
        );

        // Should contain at least one finding (SHIELD-001)
        assert!(
            !payload.predicate.findings.is_empty(),
            "Attestation should include findings from vuln_cmd_inject"
        );

        // At least one finding should be SHIELD-001
        assert!(
            payload
                .predicate
                .findings
                .iter()
                .any(|f| f.rule_id == "SHIELD-001"),
            "Expected SHIELD-001 in attestation findings"
        );

        // Scanner info should be populated
        assert_eq!(payload.predicate.scanner.name, "agentshield");
        assert!(payload.predicate.scanner.rule_count > 0);
    }
}
