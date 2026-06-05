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

`--sign-key` expects a raw 32-byte Ed25519 private key file. AgentShield signs the DSSE pre-authentication encoded payload and stores the signature plus the public-key-derived key ID in the envelope.

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

An unsigned envelope has no signatures. It can be archived, inspected, and passed between systems, but consumers must treat it as unauthenticated evidence.

A signed envelope includes one or more Ed25519 signatures. Consumers can verify that the payload was signed by the corresponding key and detect payload tampering.

## CI usage pattern

A typical release job creates the attestation after scanning the release source:

```bash
agentshield certify . --sign-key ./ed25519.key --output agentshield-attestation.dsse.json
```

Publish the resulting `agentshield-attestation.dsse.json` with release artifacts so downstream systems can verify scan evidence independently of CI logs.
