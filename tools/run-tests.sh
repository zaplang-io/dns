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
cd "$root"
ZAP_ZENV="$scratch/zenv" zap test tests/
