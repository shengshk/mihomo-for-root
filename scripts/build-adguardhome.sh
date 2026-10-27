#!/bin/sh
# Build the pinned AGH fork, including the upstream web UI. Reuse only a
# matching, verified cache. No device configuration participates in this build.
set -eu
cd "$(dirname "$0")/.."
root=$(pwd)
pin=05ba17b282da1c4393d6a4ba4db0cf519194a362
version=v0.107.79-mfr.1
if python3 - <<'PY'
import hashlib,json,sys
from pathlib import Path
try:
 d=json.loads(Path('assets/VERSIONS.json').read_text())
 f=d['files']['arm64-v8a/AdGuardHome']
 valid=(d['adguardhome_version']=='v0.107.79-mfr.1' and
  f['upstream_commit']=='05ba17b282da1c4393d6a4ba4db0cf519194a362' and
  f['patch_sha256']==hashlib.sha256(Path('scripts/adguardhome/access-lock.patch').read_bytes()).hexdigest() and
  f['sha256']==hashlib.sha256(Path('assets/arm64-v8a/AdGuardHome').read_bytes()).hexdigest())
except (OSError,ValueError,KeyError):valid=False
sys.exit(0 if valid else 1)
PY
then exit 0; fi
go_bin=${MFR_GO_BIN:-go}
for tool in "$go_bin" npm git patch; do command -v "$tool" >/dev/null || { echo "AGH 构建缺少工具: $tool" >&2; exit 1; }; done
work=$(mktemp -d "${TMPDIR:-/tmp}/mfr-agh-build.XXXXXXXX")
trap 'rm -rf "$work"' EXIT HUP INT TERM
mkdir "$work/source"
if [ -n "${MFR_AGH_SOURCE:-}" ]; then
  [ "$(git -C "$MFR_AGH_SOURCE" rev-parse HEAD)" = "$pin" ] || { echo 'AGH 源码版本不匹配' >&2; exit 1; }
  # Export the pinned tree, never local uncommitted changes or ignored files.
  git -C "$MFR_AGH_SOURCE" archive --format=tar "$pin" > "$work/source.tar"
else
  git clone --quiet --depth 1 --branch v0.107.79 https://github.com/AdguardTeam/AdGuardHome.git "$work/upstream"
  [ "$(git -C "$work/upstream" rev-parse HEAD)" = "$pin" ] || exit 1
  git -C "$work/upstream" archive --format=tar HEAD > "$work/source.tar"
fi
tar -xf "$work/source.tar" -C "$work/source"
cd "$work/source"
patch --batch --fuzz=0 -p1 < "$root/scripts/adguardhome/access-lock.patch"
cp "$root/scripts/adguardhome/accounting_lock_test.go" internal/dnsforward/mfr_accounting_lock_test.go
"$go_bin" test ./internal/dnsforward -run '^TestMFRAccountingClientLookupWithPendingWriter$' -count=1 -timeout=30s
(cd client && npm ci --no-audit --no-fund && npm run build-prod) > "$work/frontend.log" 2>&1 || { tail -n 30 "$work/frontend.log" >&2; exit 1; }
[ -s build/static/index.html ] && [ -s build/static/install.html ] && [ -s build/static/login.html ] || exit 1
mkdir -p "$root/assets/arm64-v8a"
CHANNEL=release VERSION="$version" SOURCE_DATE_EPOCH=0 GO="$go_bin" GOOS=linux GOARCH=arm64 \
  OUT="$root/assets/arm64-v8a/AdGuardHome.next" sh scripts/make/go-build.sh
chmod 700 "$root/assets/arm64-v8a/AdGuardHome.next"
mv "$root/assets/arm64-v8a/AdGuardHome.next" "$root/assets/arm64-v8a/AdGuardHome"
cd "$root"
python3 - "$pin" "$version" <<'PY'
import hashlib,json,sys
from pathlib import Path
p=Path('assets/VERSIONS.json');d=json.loads(p.read_text());b=Path('assets/arm64-v8a/AdGuardHome')
d['adguardhome_version']=sys.argv[2]
d['adguardhome_source']='https://github.com/AdguardTeam/AdGuardHome/tree/'+sys.argv[1]
d['files']['arm64-v8a/AdGuardHome']={'bytes':b.stat().st_size,'sha256':hashlib.sha256(b.read_bytes()).hexdigest(),
 'upstream_commit':sys.argv[1],'patch_sha256':hashlib.sha256(Path('scripts/adguardhome/access-lock.patch').read_bytes()).hexdigest(),
 'origin':'Pinned upstream source with scripts/adguardhome/access-lock.patch; includes upstream web UI'}
p.write_text(json.dumps(d,indent=2,ensure_ascii=False)+'\n')
PY
