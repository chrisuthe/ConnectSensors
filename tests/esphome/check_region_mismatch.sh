#!/usr/bin/env bash
# Conformance item 8 (spec/06 section 14): a radio that differs from the region
# profile must fail validation. Detune each proxy config and require
# `esphome config` to reject it for that reason.
# Set ESPHOME to override the command, e.g. ESPHOME="uvx ... esphome".
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
build=$(mktemp -d)
trap 'rm -rf "$build"' EXIT
read -ra esphome <<< "${ESPHOME:-esphome}"
status=0
for config in "$repo/examples/proxy-heltec-v3.yaml" "$here/proxy-sx127x.yaml"; do
  name=$(basename "$config" .yaml)
  "$here/prepare.sh" "$build" "$config"
  sed -i 's/^\(  frequency:\) 918\.5MHz$/\1 915.0MHz/' "$build/$name.yaml"
  if ! grep -q '^  frequency: 915.0MHz$' "$build/$name.yaml"; then
    echo "FAIL $name: no 918.5MHz frequency line to detune"
    status=1
    continue
  fi
  if "${esphome[@]}" config "$build/$name.yaml" > "$build/$name.log" 2>&1; then
    echo "FAIL $name: esphome config accepted 915.0MHz"
    status=1
  elif grep -q 'frequency must be 918.5MHz for US915' "$build/$name.log"; then
    echo "ok $name: rejected 915.0MHz"
  else
    cat "$build/$name.log"
    echo "FAIL $name: esphome config failed, but not on the region check"
    status=1
  fi
done
exit $status
