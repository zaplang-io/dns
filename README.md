# dns

DNS toolkit for [Zap](https://github.com/zaplang-io/zap) — an official **non-core** package.

- Tracking issue: [zaplang-io/zap#325](https://github.com/zaplang-io/zap/issues/325)
- Contributor & agent conventions: [AGENTS.md](AGENTS.md)
- Design decisions: [DECISIONS.md](DECISIONS.md)

The [Tier-1 epic](https://github.com/zaplang-io/dns/issues/1) tracks the DNS implementation.

## Goals

A typed Zap DNS library whose public API mirrors Python's [**dnspython**](https://www.dnspython.org/) as closely as Zap's static typing allows, with Go's [`miekg/dns`](https://github.com/miekg/dns) and the standard library [`net.Resolver`](https://pkg.go.dev/net#Resolver) as secondary design references. API-parity with the popular Python library is a project rule — see [AGENTS.md](AGENTS.md).

Planned scope (first cut):

- A **resolver** for the common record types: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `SRV`, `PTR`.
- DNS **message wire-format** encode/decode (header, questions, resource records, name compression).
- **Async resolution** over Zap's netpoller, so lookups cooperate with coroutines.
- **TTL-aware caching** of positive and negative answers.
- A clear **error and timeout model** (NXDOMAIN, SERVFAIL, truncation, timeout).

## DNS wire codec

```zap
import dns

msg = dns.Message.query("example.com", "MX")
wire = msg.to_wire()
decoded = dns.Message.from_wire(wire)
```

`Message.query` creates a recursive IN query for the given ASCII name and
Tier-1 record type. Use `.` for the root. `Message.from_wire` parses a complete
message and raises `dns.WireFormatError` on malformed input.

## Resolver usage (planned)

```zap
import dns

# Resolve a single record type.
answers = dns.resolve("example.com", "A")
for rr in answers:
    print(rr.address)

# Reverse lookup.
names = dns.resolve_address("93.184.216.34")
```

The exact signatures (keyword vs positional, defaults, return shapes) are not final. Any ambiguity is escalated to the maintainer with Python/Go examples and recorded in [DECISIONS.md](DECISIONS.md) rather than decided unilaterally.

Resolver `timeout` and `lifetime` will be expressed in fractional seconds.
The planned resolver errors will share a catchable `DNSException` base.

## Build and test

The package entry point is `src/dns.zap`. Native Zap test suites live under
`tests/`. Run the formatting and test checks from the repository root:

```sh
zap fmt --check src tests
sh tools/run-tests.sh
```

The runner installs the checkout as a local Zap dependency in a temporary
environment, then runs `zap test tests/` against the public package API.

GitHub Actions runs both checks on pull requests and pushes to `main` inside
the `ghcr.io/zaplang-io/zap:latest` container.

## Development

Read **[AGENTS.md](AGENTS.md)** before contributing — it covers the dnspython-parity rule, the one-issue-one-PR flow, how design decisions are recorded in **[DECISIONS.md](DECISIONS.md)**, and the rule for reporting core Zap language/stdlib defects upstream in `zaplang-io/zap` (rather than working around them here).
