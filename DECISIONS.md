# dns package decisions

Design decisions for the Zap `dns` library, keyed to issues. Each records a
choice that could not be read straight off Python's [dnspython](https://www.dnspython.org/)
or Go's [`miekg/dns`](https://github.com/miekg/dns) / [`net.Resolver`](https://pkg.go.dev/net#Resolver),
with the reference it follows or departs from. Signature ambiguities are
resolved with the maintainer (with Python/Go examples) before being recorded here.

## Parity target: dnspython

The package tracks [**dnspython**](https://www.dnspython.org/) as its primary
API reference, with Go's `miekg/dns` and `net.Resolver` as secondary references.
Deviations are recorded below, keyed to the issue that introduces them.

## DNS message and record data ([#3](https://github.com/zaplang-io/dns/issues/3))

Use dnspython's `Message` model, with RRsets in the question, answer, authority,
and additional sections. The header stores the message ID and flags. The number
of questions and records in each section determines the wire counts.

Tier-1 record data uses typed variants with dnspython field names. A and AAAA
carry address text, name-bearing records carry absolute names as byte labels,
and TXT carries a list of byte strings. Unknown record types retain opaque bytes
with the original type code. Decoding coalesces records with the same owner,
class, and type within each section and uses the lowest TTL of the group.

Use Zap's associated functions for `Message.query` and `Message.from_wire`
([Zap #1260](https://github.com/zaplang-io/zap/issues/1260)). Use the stdlib's
`net.inet_pton` and `net.inet_ntop` for A and AAAA text conversion
([Zap #1261](https://github.com/zaplang-io/zap/issues/1261)).

`Message.query` uses class IN, sets recursion desired, and generates a random
16-bit ID. It accepts ASCII names with DNS escapes and case-insensitive Tier-1
type mnemonics. A trailing dot is optional for ordinary names, and `.` denotes
the root.

## DNS errors and deadlines ([#6](https://github.com/zaplang-io/dns/issues/6))

Follow dnspython's shared exception-family model with Zap's `@exception`
declarations ([Zap #1278](https://github.com/zaplang-io/zap/issues/1278)).
Callers can catch a concrete DNS error, the package-wide `DNSException`, or
Zap's general `Exception`. `ResponseError` groups `NXDOMAIN`, `ServFail`, and
server RCODEs without a dedicated type. `NoAnswer` represents a successful
response with no matching records after alias and record-type selection.
The query layer checks truncation before the response code so the transport
can retry a truncated UDP exchange over TCP.

Public `timeout` and `lifetime` values use fractional seconds. Internally, DNS
uses absolute monotonic nanosecond deadlines compatible with Zap networking.
Each attempt is limited by the earlier of its own timeout and the original
resolution lifetime, using exact integer `min`
([Zap #1279](https://github.com/zaplang-io/zap/issues/1279)). Zero means
immediate expiry. Fractional nanoseconds round up, finite values beyond the
representable range saturate, and negative or nonfinite values are invalid.

## Resolver configuration ([#7](https://github.com/zaplang-io/dns/issues/7))

The configuration parser understands `nameserver`, `search`, `domain`, and
`options ndots:`. A valid `search` list takes precedence over `domain`.
`ndots` from the file is capped at 15, following the system resolver
convention. Invalid entries are ignored.

Search qualification tries the bare name first at or above `ndots`, and
tries the configured suffixes first below it. An absolute name skips suffix
expansion. Duplicate candidates are compared case-insensitively, with the
first spelling preserved.

`Resolver()` constructs settings explicitly on any platform. Defaults are
`ndots=1`, `timeout=2.0` seconds, `lifetime=5.0` seconds, and an empty search
list. An empty nameserver list falls back to IPv4 then IPv6 loopback
(`127.0.0.1`, `::1`), as in Go's system resolver.

`Resolver.from_file(path)` reads an explicit file and returns default settings
when Zap raises `FileNotFoundError`. Other filesystem errors propagate
([Zap #1311](https://github.com/zaplang-io/zap/issues/1311)).
`Resolver.system()` loads `/etc/resolv.conf` on Linux and macOS and returns
default settings on other platforms.

## DNS query transport ([#4](https://github.com/zaplang-io/dns/issues/4))

Use direct-style calls on Zap's coroutine netpoller. The low-level transport
follows dnspython's `udp_with_fallback(message, where, timeout, port)` and
returns the response and a Boolean indicating whether TCP was used. The
destination is a numeric IPv4 or IPv6 address. Timeout defaults to 2 seconds
and the port to 53.

A connected UDP socket restricts replies to the destination peer. Match the
response bit, transaction ID, opcode, and question before accepting a reply
or retrying a truncated reply over TCP. Use one monotonic deadline across
both transports. The UDP size limit is 512 bytes unless the query advertises
a larger EDNS payload, and each TCP message has a two-octet length prefix.
