# Changelog

## Unreleased

- Added opt-in bounded LRU caching for positive and negative DNS replies.
- Added typed resolver lookups and IPv4 and IPv6 reverse lookup with iterable
  answers and response metadata.
- Added coroutine DNS exchanges over UDP with automatic TCP fallback.
- Added explicit, file-based, and system resolver configuration with
  nameserver fallback and DNS search-name qualification.
- Added internal per-attempt deadlines bounded by a single resolution lifetime.
- Added the catchable `DNSException` family, typed response errors, and
  truncation and timeout classification for the query layer.
- Added `Message.query`, `Message.from_wire`, and `Message.to_wire`, with DNS
  header and section framing, compressed names, and typed record data for
  A, AAAA, CNAME, MX, TXT, NS, SOA, SRV, and PTR.
- Added the initial Zap package layout and formatting checks for source and tests.
