#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
source=scripts/dns-gate/main.go
output=assets/arm64-v8a/dns-gate
if python3 - "$source" "$output" <<'PY'
import hashlib,json,sys
from pathlib import Path
s,b=map(Path,sys.argv[1:])
try:
 d=json.loads(Path('assets/VERSIONS.json').read_text())['files']['arm64-v8a/dns-gate']
 valid=d['source_sha256']==hashlib.sha256(s.read_bytes()).hexdigest() and d['sha256']==hashlib.sha256(b.read_bytes()).hexdigest()
except (OSError,KeyError,ValueError):valid=False
sys.exit(0 if valid else 1)
PY
then exit 0;fi
go_bin=${MFR_GO_BIN:-go}
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 "$go_bin" build -trimpath -ldflags='-s -w -buildid=' -o "$output.next" "$source"
chmod 700 "$output.next";mv "$output.next" "$output"
python3 - "$source" "$output" <<'PY'
import hashlib,json,sys
from pathlib import Path
s,b=map(Path,sys.argv[1:]);p=Path('assets/VERSIONS.json');d=json.loads(p.read_text())
d['files']['arm64-v8a/dns-gate']={'bytes':b.stat().st_size,'sha256':hashlib.sha256(b.read_bytes()).hexdigest(),'source_sha256':hashlib.sha256(s.read_bytes()).hexdigest(),'origin':'Module source: scripts/dns-gate/main.go'}
p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n')
PY
