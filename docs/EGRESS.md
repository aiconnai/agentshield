# Egress Policy

AgentShield can emit a starter egress policy from scan results and use that policy to wrap a command with outbound network controls.

The generated policy is intended as a reviewable starting point. Operators can then tighten it before enforcement.

## Emit a starter policy

Run:

```bash
agentshield scan . --emit-egress-policy agentshield.egress.toml
```

AgentShield scans the project and writes `agentshield.egress.toml` with discovered allowed domains plus safe defaults for network blocking and rate limiting.

The policy schema includes domain allow and deny rules, network blocking settings, rate limits, and audit logging configuration.

## Build wrap support from source

The `wrap` command requires runtime support. When building from source, enable the full feature set:

```bash
cargo build --features full --release
```

The resulting binary includes egress wrapping support when the runtime feature is enabled by the selected feature set.

## Wrap a command

Use `--` before the command you want to run under the policy:

```bash
agentshield wrap --policy agentshield.egress.toml -- npm test
```

AgentShield starts a local HTTP proxy for the wrapped process and enforces the configured egress policy for outbound requests routed through that proxy.

## Restrictive operator override

Operators can provide a second policy that only restricts the generated policy; it cannot expand access.

```bash
agentshield wrap \
  --policy agentshield.egress.toml \
  --override-policy operator.egress.toml \
  -- npm test
```

Use `--override-policy operator.egress.toml` when platform, CI, or security teams need to impose stricter controls than the project-generated policy.

Override behavior is restrictive:

1. Domain allow lists are intersected when both policies specify allow lists.
2. Domain deny lists are combined.
3. Network blocks remain enabled if either policy blocks the range.
4. Rate limits can be tightened by the operator policy.

## Recommended workflow

1. Generate `agentshield.egress.toml` with `--emit-egress-policy`.
2. Review the allowed domains and remove anything unnecessary.
3. Commit the project policy if it represents expected application behavior.
4. Use `--override-policy` in CI or production-like environments for operator-owned restrictions.
5. Enable audit logging when investigating unexpected network behavior.
