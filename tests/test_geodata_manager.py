"""Geo updates: real Mihomo validation, isolated Android lifecycle and downloads."""
import hashlib
import json
import os
import shutil
import signal
import subprocess
import unittest
import urllib.error
from pathlib import Path
from test_manager import ManagerFixture, ROOT

CORE = os.environ.get('MFR_TEST_MIHOMO')
FILES = ('GeoSite.dat', 'GeoIP.dat', 'Country.mmdb', 'ASN.mmdb')

@unittest.skipUnless(CORE and Path(CORE).is_file() and (ROOT/'assets/geodata/GeoSite.dat').is_file(), 'set MFR_TEST_MIHOMO; requires public Geo assets')
class GeodataManagerTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture();self.base=self.fx.base
        shutil.copy(CORE,self.base/'bin/mihomo')
        for name in FILES:shutil.copy(ROOT/'assets/geodata'/name,self.base/'mihomo'/name)
        self.fx.write('scripts/box.dns-gate',f'''#!/bin/sh
printf 'sync\\n' >> '{self.base}/gate-calls'
[ ! -f '{self.base}/apply-fail' ] || {{ rm '{self.base}/apply-fail';exit 1; }}
''')
        self.fx.write('bin/curl',f'''#!/bin/sh
config=$(cat)
while [ "$#" -gt 0 ];do
 case "$1" in --output) shift;output="$1" ;; esac
 shift
done
name=${{output##*/}}
printf '%s\\n' "$name" >> '{self.base}/downloads'
printf '%s\\n' "$config" >> '{self.base}/requested-urls'
[ ! -f '{self.base}/download-fail' ] || exit 1
if [ "$(cat '{self.base}/corrupt' 2>/dev/null)" = "$name" ];then printf 'invalid data' > "$output";else cp '{ROOT}/assets/geodata/'"$name" "$output";fi
''')
        self.fx.call('geodata-progress',{'id':'init'})
    def tearDown(self):
        pid=self.base/'run/box.pid'
        if pid.exists():
            try:os.kill(int(pid.read_text()),signal.SIGTERM)
            except ProcessLookupError:pass
        self.fx.close()
    def hashes(self):
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.base/'mihomo').iterdir() if p.is_file() and p.name in FILES}
    def test_all_real_databases_and_cached_status(self):
        source=self.base/'mihomo/config.yaml'
        text=source.read_text().replace('https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat','https://example.invalid/custom-site.dat')
        source.write_text(text)
        before=source.read_bytes()
        result=self.fx.call('geodata-update',dict(kind='all',id='all-1'))
        self.assertEqual(set(result['files']),set(FILES));self.assertTrue(result['updated'])
        self.assertEqual((self.base/'downloads').read_text().splitlines(),list(FILES))
        self.assertIn('https://example.invalid/custom-site.dat',(self.base/'requested-urls').read_text())
        self.assertEqual(source.read_bytes(),before)
        self.assertEqual(self.fx.call('status')['geodata'],result)
        self.assertEqual(self.fx.call('geodata-progress',{'id':'other'}),{'phase':''})
        self.assertEqual(self.fx.call('geodata-progress',{'id':'all-1'})['phase'],'更新完成')
        self.assertFalse((self.base/'run/box.pid').exists(),'paused core must stay paused')
    def test_individual_groups_and_existing_alias_share(self):
        (self.base/'mihomo/GeoSite.dat').rename(self.base/'mihomo/gEoSiTe.dat')
        (self.base/'mihomo/Country.mmdb').rename(self.base/'mihomo/geoip.db')
        self.fx.call('geodata-update',dict(kind='geoip',id='ip'))
        self.assertEqual((self.base/'downloads').read_text().splitlines(),['GeoIP.dat','Country.mmdb'])
        self.assertFalse((self.base/'mihomo/Country.mmdb').exists())
        self.fx.call('geodata-update',dict(kind='geosite',id='site'))
        command=f'. "{self.base}/settings.ini"; . "{self.base}/scripts/dns-gate.utils"; gate_geosite'
        shared=subprocess.check_output(['bash','-c',command],env=self.fx.env,text=True).strip()
        self.assertEqual(shared,str(self.base/'mihomo/gEoSiTe.dat'))
        self.assertFalse((self.base/'mihomo/GeoSite.dat').exists())
        self.assertEqual((self.base/'gate-calls').read_text().splitlines(),['sync'])
    def test_corrupt_or_failed_download_keeps_originals_and_timestamp(self):
        self.fx.call('geodata-update',dict(kind='asn',id='first'))
        original=self.hashes();record=(self.base/'manage/geodata.json').read_bytes()
        for name in FILES:
            (self.base/'corrupt').write_text(name)
            with self.assertRaises(urllib.error.HTTPError):self.fx.call('geodata-update',dict(kind='all',id='bad'))
            self.assertEqual(self.hashes(),original)
            self.assertEqual((self.base/'manage/geodata.json').read_bytes(),record)
        (self.base/'download-fail').touch()
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('geodata-update',dict(kind='geosite',id='offline'))
        self.assertEqual(self.hashes(),original)
        self.assertFalse((self.base/'manage/operation.lock').exists())

    def test_live_core_uses_serialized_stop_then_policy_reconcile(self):
        self.fx.write('scripts/box.service',f'''#!/bin/bash
. '{self.base}/settings.ini'
printf '%s\\n' "$1" >> '{self.base}/service-calls'
case "$1" in
 stop) kill "$(cat "$box_pid")";rm -f "$box_pid" ;;
 restart) bash -c 'exec -a "$1" sleep 100' _ "$bin_path" </dev/null >/dev/null 2>&1 & echo $! > "$box_pid" ;;
esac
''')
        self.fx.write('scripts/box.policy',f'''#!/bin/sh
[ "$1" != reconcile ] || '{self.base}/scripts/box.service' restart
exit 0
''')
        subprocess.run(['bash',str(self.base/'scripts/box.service'),'restart'],env=self.fx.env,check=True)
        old=(self.base/'run/box.pid').read_text()
        self.fx.call('geodata-update',dict(kind='asn',id='live'))
        self.assertNotEqual((self.base/'run/box.pid').read_text(),old)
        self.assertEqual((self.base/'service-calls').read_text().splitlines(),['restart','stop','prepare','restart'])
    def test_apply_failure_restores_previous_bytes(self):
        # A semantically valid input whose trailing protobuf field differs from
        # the old snapshot lets us prove rollback, not just equal-file copying.
        previous=self.base/'mihomo/GeoSite.dat'
        previous.write_bytes(previous.read_bytes()+b'\xf8\x7f\x00')
        before=previous.read_bytes()
        (self.base/'apply-fail').touch()
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('geodata-update',dict(kind='geosite',id='rollback'))
        self.assertEqual(previous.read_bytes(),before)
        self.assertFalse((self.base/'manage/geodata.json').exists())
        self.assertEqual((self.base/'gate-calls').read_text().splitlines(),['sync','sync'])
        self.assertIn('已恢复原库',self.fx.call('geodata-progress',{'id':'rollback'})['phase'])
        self.assertFalse((self.base/'manage/operation.lock').exists())

if __name__=='__main__':unittest.main()
