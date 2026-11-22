#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf "$scratch"' EXIT
trap 'exit 1' HUP INT TERM

ln -s "$root" "$scratch/dns"
cat > "$scratch/zap.toml" <<'MANIFEST'
[package]
name = "dns_tests"
version = "0.0.0"

[dependencies]
dns = { path = "dns" }
MANIFEST

(cd "$scratch" && zap zenv create --no-venv)
mkdir "$scratch/tests"
cp "$root"/tests/*_test.zap "$scratch/tests/"
# Keep the deadline calculations private while exercising them with native tests.
{
    cat "$root/src/_deadlines.zap"
    printf '\n'
    cat "$root/tests/internal/deadlines_test.zap"
} > "$scratch/tests/deadlines_test.zap"

cd "$scratch"
ZAP_ZENV="$scratch/zenv" zap test tests/
