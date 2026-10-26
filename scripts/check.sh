#!/usr/bin/env bash
set -euo pipefail
shopt -s nullglob
ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"

node_bin=${MFR_NODE_BIN:-node}
command -v "$node_bin" >/dev/null || { echo "缺少 Node.js，可设置 MFR_NODE_BIN。" >&2; exit 1; }
if [[ -z ${MFR_TEST_YQ:-} ]] && ! command -v yq >/dev/null; then
  echo "主机 HTTP 隔离检查需要 yq v4，请设置 MFR_TEST_YQ。" >&2
  exit 1
fi
command -v busybox >/dev/null || { echo "缺少用于 HTTP 隔离检查的 BusyBox。" >&2; exit 1; }

python3 -m unittest discover -s tests -v
"$node_bin" tests/test_webui.js
for script in webroot/*.js; do "$node_bin" --check "$script"; done
for script in ./*.sh box/settings.ini box/scripts/* .ops/scripts/*.sh scripts/*.sh; do
  bash -n "$script"
done
git diff --check
python3 scripts/verify-release.py
