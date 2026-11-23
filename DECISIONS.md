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
