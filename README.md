# dns

DNS toolkit for [Zap](https://github.com/zaplang-io/zap) — an official **non-core** package.

- Tracking issue: [zaplang-io/zap#325](https://github.com/zaplang-io/zap/issues/325)
- Contributor & agent conventions: [AGENTS.md](AGENTS.md)
- Design decisions: [DECISIONS.md](DECISIONS.md)

> **Status: docs-first.** No implementation yet — the planned surface is tracked in the [issues](https://github.com/zaplang-io/dns/issues) (see the Tier-1 scope epic).

## Goals

A typed Zap DNS library whose public API mirrors Python's [**dnspython**](https://www.dnspython.org/) as closely as Zap's static typing allows, with Go's [`miekg/dns`](https://github.com/miekg/dns) and the standard library [`net.Resolver`](https://pkg.go.dev/net#Resolver) as secondary design references. API-parity with the popular Python library is a project rule — see [AGENTS.md](AGENTS.md).

Planned scope (first cut):

- A **resolver** for the common record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `PTR`.
- DNS **message wire-format** encode/decode (header, questions, resource records, name compression).
- **Async resolution** over Zap's netpoller, so lookups cooperate with coroutines.
- **TTL-aware caching** of positive and negative answers.
- A clear **error and timeout model** (NXDOMAIN, SERVFAIL, truncation, timeout).

## Usage (planned — illustrative only)

```zap
import dns

# Resolve a single record type.
answers = dns.resolve("example.com", "A")
for rr in answers:
    print(rr.address)

# Reverse lookup.
names = dns.resolve_address("93.184.216.34")

# Lower-level message construction / parsing is also planned.
msg = dns.Message.query("example.com", "MX")
wire = msg.to_wire()
reply = dns.Message.from_wire(wire)
```

The exact signatures (keyword vs positional, defaults, return shapes) are not final. Any ambiguity is escalated to the maintainer with Python/Go examples and recorded in [DECISIONS.md](DECISIONS.md) rather than decided unilaterally.

## Build and test

Test cases live under `tests/` and run with the `zap test` methodology:

```
zap test tests/
```

GitHub Actions runs the suite on pull requests and pushes inside the
`ghcr.io/zaplang-io/zap:latest` container. CI stays pinned to `zap:latest`
until this module reaches a 1.0 release.

## Development

Read **[AGENTS.md](AGENTS.md)** before contributing — it covers the dnspython-parity rule, the one-issue-one-PR flow, how design decisions are recorded in **[DECISIONS.md](DECISIONS.md)**, and the rule for reporting core Zap language/stdlib defects upstream in `zaplang-io/zap` (rather than working around them here).
