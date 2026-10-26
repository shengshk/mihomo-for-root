#!/bin/sh
set -eu
cd "$(dirname "$0")"
missing=false
for file in assets/arm64-v8a/AdGuardHome assets/arm64-v8a/mihomo assets/arm64-v8a/yq assets/arm64-v8a/curl assets/dashboard.zip assets/geodata/GeoIP.dat assets/geodata/GeoSite.dat assets/geodata/Country.mmdb assets/geodata/ASN.mmdb; do
  [ -s "$file" ] || missing=true
done
if [ "$missing" = true ]; then
  # A clean private clone can restore its ignored dependency cache from the
  # versioned offline module, without downloading a different upstream build.
  python3 scripts/verify-release.py --archive-only
  # zipfile extracts with host permissions, rather than restoring Android/NAS
  # archive directory modes that may be unreadable on a normal Linux clone.
  python3 - <<'PY'
import json
import zipfile
from pathlib import Path

archive = Path('releases') / json.loads(Path('releases/module.json').read_text())['file']
with zipfile.ZipFile(archive) as package:
    for entry in package.infolist():
        if entry.filename.startswith('assets/') and (entry.filename == 'assets/VERSIONS.json' or not Path(entry.filename).exists()):
            package.extract(entry)
PY
fi
for file in assets/arm64-v8a/AdGuardHome assets/arm64-v8a/mihomo assets/arm64-v8a/yq assets/arm64-v8a/curl assets/dashboard.zip assets/geodata/GeoIP.dat assets/geodata/GeoSite.dat assets/geodata/Country.mmdb assets/geodata/ASN.mmdb; do
  [ -s "$file" ] || { echo "缺少离线安装资源: $file" >&2; exit 1; }
done
mkdir -p dist
output="$(pwd)/dist/mihomo-for-root-1.0.zip"
rm -f "$output"
zip -q -r -X "$output" META-INF box webroot assets action.sh box_service.sh customize.sh module.prop uninstall.sh LICENSE
unzip -t "$output" >/dev/null
sha256sum "$output"
