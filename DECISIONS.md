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

## Decisions (2026-11-21)

_No decisions recorded yet. Add one section per decision as issues are implemented._
