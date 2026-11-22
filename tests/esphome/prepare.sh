#!/usr/bin/env bash
# Usage: prepare.sh <out-dir> <config.yaml>...
# Copy configs into <out-dir> pointing at this checkout's components, with CI's
# dummy secrets beside them.
set -euo pipefail
repo=$(cd "$(dirname "$0")/../.." && pwd)
out=$1
shift
mkdir -p "$out"
printf 'wifi_ssid: "ci"\nwifi_password: "ci-password"\ncs_proxy_key: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a"\ncs_dev_eui: "c5c5000000000002"\ncs_root_key: "00112233445566778899aabbccddeeff"\n' > "$out/secrets.yaml"
for config in "$@"; do
  sed "s#source: github://chrisuthe/ConnectSensors@main#source:\n      type: local\n      path: $repo/components#" \
    "$config" > "$out/$(basename "$config")"
done
