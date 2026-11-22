#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM
mkdir "$scratch/tests"

# Test the internal decoder without adding a public entry point before
# Message.from_wire can be defined.
for suite in "$root"/tests/*_test.zap; do
    {
        cat "$root/src/dns.zap"
        printf '\n'
        cat "$suite"
    } > "$scratch/tests/$(basename "$suite")"
done

cd "$scratch"
zap test tests/
