# Certification

AgentShield can generate a DSSE attestation envelope for scan results. The envelope contains an in-toto statement with AgentShield-specific scan metadata, finding summaries, suppression summaries, capability information, provenance, and optional egress policy hash data.

Use certification when you need a portable trust artifact for CI, release review, or downstream policy checks.

## Create an unsigned attestation

Run:

```bash
agentshield certify . --output agentshield-attestation.dsse.json
```

This writes a DSSE envelope with the scan attestation payload and an empty `signatures` array.

Unsigned envelopes are useful as structured evidence, but they do not prove who produced the attestation or whether it has been modified after creation.

## Create a signed attestation

Run:

```bash
agentshield certify . --sign-key ./ed25519.key --output agentshield-attestation.dsse.json
```

`--sign-key` expects a raw 32-byte Ed25519 private key file. AgentShield signs the DSSE pre-authentication encoding (PAE) of the raw payload bytes, as the [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) defines it, and stores the signature plus the public-key-derived key ID (hex of the Ed25519 public key) in the envelope:

```text
PAE = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(body) SP body
```

`body` is the JSON statement before base64 encoding and `LEN` is its byte length in ASCII decimal. Standard DSSE verifiers accept these signatures.

Keep signing keys outside the repository and protect them as release credentials.

## Signed vs unsigned DSSE envelopes

A DSSE envelope has three primary fields:

```json
{
  "payloadType": "application/vnd.in-toto+json",
  "payload": "<base64 JSON payload>",
  "signatures": []
}
```

The `payload` is a base64-encoded in-toto statement. For AgentShield, that statement describes the scanned subject and includes the scan predicate.

## Subject digest and predicate versions

The statement's `predicateType` identifies the format:

| `predicateType` | Subject `digest.sha256` | Signed bytes | Written by |
|---|---|---|---|
| `https://agentshield.dev/attestation/v2` | SHA-256 of the source manifest (below) | standard DSSE PAE of the raw payload | current releases |
| `https://agentshield.dev/attestation/v1` | SHA-256 of the scan directory **name** | non-standard PAE over the base64 payload text | AgentShield 1.0.2 and earlier |

For `v2`, the subject `name` is the scan directory name, for display only, and `digest.sha256` binds the attestation to the scanned content. It is the SHA-256 of a source manifest that has one line per scanned source file, sorted by path in byte order:

```text
<sha256 of the file bytes, lowercase hex><two spaces><path relative to the scan root, / separators>\n
```

A `\` in a path is written as `\\` and a newline as `\n`. The file set is exactly the source files the scan loaded, after `--ignore-tests` and `[scan] include/exclude` filtering; files the adapters do not read are not covered. Changing, adding, removing or renaming a scanned file changes the digest, while renaming or moving the repository root does not. Finding fingerprints in the predicate use fingerprint scheme v2 (see [BASELINES.md](BASELINES.md#fingerprints-and-schema-versions)).

`v1` envelopes are not valid DSSE (standard verifiers reject their signatures) and their subject digest does not identify content. The library verifier (`DsseEnvelope::verify_detailed`) still verifies them and reports `VerifiedLegacy`. It accepts the legacy encoding only when the payload's `predicateType` is `v1`, so a `v2` envelope can never be verified with it. Re-run `agentshield certify` to produce a `v2` envelope.

An unsigned envelope has no signatures. It can be archived, inspected, and passed between systems, but consumers must treat it as unauthenticated evidence.

A signed envelope includes one or more Ed25519 signatures. Consumers can verify that the payload was signed by the corresponding key and detect payload tampering.

## CI usage pattern

A typical release job creates the attestation after scanning the release source:

```bash
agentshield certify . --sign-key ./ed25519.key --output agentshield-attestation.dsse.json
```

Publish the resulting `agentshield-attestation.dsse.json` with release artifacts so downstream systems can verify scan evidence independently of CI logs.
