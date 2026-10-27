#!/bin/sh
# Compile the module's own transport; no external Go dependencies are used.
set -eu
cd "$(dirname "$0")/.."
source=scripts/agh-dns-bridge/main.go
output=assets/arm64-v8a/agh-dns-bridge
if python3 - "$source" "$output" <<'PY'
import hashlib,json,sys
from pathlib import Path
source,output=map(Path,sys.argv[1:])
try:
 info=json.loads(Path('assets/VERSIONS.json').read_text())['files']['arm64-v8a/agh-dns-bridge']
 valid=info['source_sha256']==hashlib.sha256(source.read_bytes()).hexdigest() and info['sha256']==hashlib.sha256(output.read_bytes()).hexdigest()
except (OSError,KeyError,ValueError): valid=False
sys.exit(0 if valid else 1)
PY
then exit 0; fi
go_bin=${MFR_GO_BIN:-go}
command -v "$go_bin" >/dev/null || { echo 'DNS 转发器源码已更新，需要 Go 1.23+；可设置 MFR_GO_BIN。' >&2; exit 1; }
mkdir -p assets/arm64-v8a
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$go_bin" build -trimpath -ldflags='-s -w -buildid=' -o "$output.next" "$source"
chmod 700 "$output.next"
mv "$output.next" "$output"
MFR_BRIDGE_GO_VERSION=$("$go_bin" version) python3 - "$source" "$output" <<'PY'
import hashlib,json,sys,os
from pathlib import Path
source,output=map(Path,sys.argv[1:]);p=Path('assets/VERSIONS.json');info=json.loads(p.read_text())
info['files']['arm64-v8a/agh-dns-bridge']={'bytes':output.stat().st_size,'sha256':hashlib.sha256(output.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),'origin':'Module source: scripts/agh-dns-bridge/main.go','compiler':os.environ['MFR_BRIDGE_GO_VERSION']}
p.write_text(json.dumps(info,indent=2,ensure_ascii=False)+'\n')
PY
