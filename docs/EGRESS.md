# Egress Policy

AgentShield can emit a starter egress policy from scan results and use that policy to run a command behind a local proxy that applies it.

The generated policy is intended as a reviewable starting point. Operators can then tighten it before use.

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

The resulting binary includes `wrap` support when the runtime feature is enabled by the selected feature set.

## Wrap a command

Use `--` before the command you want to run under the policy:

```bash
agentshield wrap --policy agentshield.egress.toml -- npm test
```

AgentShield starts an HTTP/HTTPS forward proxy on a random `127.0.0.1` port, starts your command with its proxy environment pointed at that port, and applies the policy to every request that reaches the proxy. A blocked request gets `403 Forbidden` with a JSON body giving the reason.

### What `wrap` does and does not guarantee

`wrap` routes **proxy-aware clients** through the policy. It is **not a sandbox**.

The child process is started with these variables set to the proxy URL:

`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `http_proxy`, `https_proxy`, `all_proxy`

Any value of those variables inherited from your shell is overwritten.

`NO_PROXY` and `no_proxy` are **removed** from the child's environment, even if you set them. A bypass list sends the listed hosts straight to the network, which would make the hosts you care about most invisible to the policy. There is currently no opt-out; if a wrapped tool must reach a local service, allow it in the policy instead (for example `block_localhost = false` plus an allow rule).

What this means in practice:

- Clients that honour the proxy environment (curl, `npm`, `pip`, and most HTTP libraries) are checked.
- A process can ignore the environment and open a raw TCP or UDP socket, use its own DNS, or call a client that does not read proxy variables. Those connections do **not** pass through AgentShield.
- Only HTTP and HTTPS (`CONNECT`) traffic is understood; other protocols are not inspected.

For stronger isolation, combine `wrap` with OS-level controls such as a container with no direct network route, firewall rules, or a network namespace that only allows the proxy port.

Every upstream connection is made to the exact addresses that were resolved and checked against the network rules, so a hostname that resolves to a blocked address (DNS rebinding) is refused.

## Policy semantics

### Domains

```toml
[domains]
allow = ["*.example.com", "api.github.com"]
deny  = ["evil.example.com"]
```

- A pattern is an exact host (`api.github.com`), a subdomain wildcard (`*.example.com`, which matches `example.com` and every subdomain), or a bare `*` (every host). An exact pattern may also be an IP literal.
- `deny` wins over `allow`. An empty `allow` list allows every host that is not denied.
- Matching ignores ASCII case, a trailing root dot, and whether a name is written in Unicode or punycode: the rule `bücher.example` and the host `xn--bcher-kva.example` match each other. Names are normalized with IDNA (UTS #46).
- A host that is not valid IDNA, or that has an empty label (`a..b`), is never allowed.
- A rule that is not valid IDNA, or that has an empty label (`*.`, `.`, `*..x`, or an empty string), is rejected when the policy is loaded, with an error naming the field and the pattern. Earlier versions treated `*.` as `*`, which as a deny rule blocked everything and as an allow rule permitted everything. Write `*` if you mean every host.

### Networks

```toml
[networks]
block_private = true
block_link_local = true
block_localhost = true
block_metadata = true
```

Addresses are parsed and classified by range, not by text prefix, so `fd-cdn.example` is a hostname, not a private address. IPv6 forms that embed an IPv4 address are classified as that IPv4 address first: IPv4-mapped (`::ffff:127.0.0.1`), NAT64 (`64:ff9b::7f00:1`) and IPv4-compatible (`::127.0.0.1`). A 6to4 address (`2002:7f00:1::`) is blocked when either the address itself or the gateway it embeds is blocked. IPv6 zone identifiers (`fe80::1%eth0`, also bracketed or percent-encoded) are ignored.

| Setting | Blocks |
|---|---|
| `block_private` | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, carrier-grade NAT `100.64.0.0/10`, IPv6 unique-local `fc00::/7` |
| `block_link_local` | `169.254.0.0/16`, `fe80::/10` |
| `block_localhost` | `127.0.0.0/8`, `::1`, all of `0.0.0.0/8`, `::`, and the names `localhost` and `*.localhost` |
| `block_metadata` | `169.254.169.254` (AWS, GCP, Azure, Oracle, DigitalOcean), `169.254.170.2` (AWS ECS), `100.100.100.200` (Alibaba Cloud), `168.63.129.16` (Azure WireServer), `fd00:ec2::254` (AWS IMDS over IPv6), and `metadata.google.internal` |

These checks run on the host the client asked for and again on every address it resolves to.

### Rate limits

```toml
[rate_limits]
max_requests_per_minute = 60
[rate_limits.per_domain]
"api.github.com" = 30
```

The limit is per host, per minute. A per-domain entry overrides the global value. `0` means unlimited. Keys are normalized like domains, so `API.GitHub.com.` and `api.github.com` are the same entry.

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

1. Domain allow lists are intersected when both policies specify allow lists, keeping the narrower pattern of each overlapping pair. If only one policy has an allow list, that list is used.
2. **Disjoint allow lists merge to deny-all.** When both policies have allow lists and no entry overlaps, the result denies every host (a `*` deny rule is added). It never falls back to "allow everything".
3. Domain deny lists are combined.
4. Network blocks remain enabled if either policy blocks the range.
5. Rate limits take the stricter value, where **`0` means unlimited**: merging `0` with `30` gives `30`, not `0`. This applies to the global limit and to each per-domain entry.
6. Audit settings come from the operator policy.

## Recommended workflow

1. Generate `agentshield.egress.toml` with `--emit-egress-policy`.
2. Review the allowed domains and remove anything unnecessary.
3. Commit the project policy if it represents expected application behavior.
4. Use `--override-policy` in CI or production-like environments for operator-owned restrictions.
5. Enable audit logging when investigating unexpected network behavior.
6. Remember that `wrap` steers proxy-aware clients only; add OS-level isolation where bypass matters.
