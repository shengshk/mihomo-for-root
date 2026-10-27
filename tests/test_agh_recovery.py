"""Bounded AGH recovery: real daemon/DNS, emulated capture; no phone or firewall."""
import json
from pathlib import Path
import os
import subprocess
import unittest

import test_adguardhome as fixture
import test_manager as manager_fixture
from test_runtime_lifecycle import functions


@unittest.skipUnless(fixture.YQ and fixture.AGH and fixture.shutil.which("busybox"), "host AGH/yq required")
class AGHRecoveryTest(unittest.TestCase):
    setUp=fixture.AdGuardHomeTest.setUp
    write=fixture.AdGuardHomeTest.write
    spawn=fixture.AdGuardHomeTest.spawn
    run_adg=fixture.AdGuardHomeTest.run_adg
    api=fixture.AdGuardHomeTest.api
    query=fixture.AdGuardHomeTest.query
    status=fixture.AdGuardHomeTest.status
    close=fixture.AdGuardHomeTest.close
    def fault_api(self, failures):
        path=self.base/'scripts/adg.utils'
        text=path.read_text().replace('adg_api() {','fixture_real_api() {',1)
        text+='''
adg_api() {
  if [ "$1:$2" = POST:dns_config ]; then
    local n=$(cat "$box_dir/api-count" 2>/dev/null)
    n=$((${n:-0}+1)); echo "$n" > "$box_dir/api-count"
    if [ "$n" -le FAILURES ]; then return 28; fi
  fi
  fixture_real_api "$@"
}
'''.replace('FAILURES',str(failures))
        path.write_text(text)

    def test_one_failed_switch_restarts_once_then_recovers(self):
        self.fault_api(1)
        self.run_adg()
        self.assertEqual((self.base/'api-count').read_text().strip(),'2')
        self.assertTrue(json.loads((self.base/'manage/preferences.json').read_text())['adguardhome_enabled'])
        self.assertTrue(self.status()['api_available'])
        self.assertFalse((self.base/'manage/adguardhome-disabled').exists())
        self.assertFalse((self.base/'run/state/adguardhome.lock').exists())
        self.assertIn(bytes([203,0,113,7]),self.query('recovered.example'))

    def test_second_failure_disables_and_unlocks_without_retry_loop(self):
        self.fault_api(99)
        result=self.run_adg(check=False)
        self.assertEqual(result.returncode,78,result.stderr)
        self.assertEqual((self.base/'api-count').read_text().strip(),'2')
        self.assertFalse(json.loads((self.base/'manage/preferences.json').read_text())['adguardhome_enabled'])
        self.assertTrue((self.base/'manage/adguardhome-recovery-pending').exists())
        self.assertIn('已停用',self.status()['error'])
        self.assertFalse(self.status()['running'])
        self.assertFalse((self.base/'run/state/adguardhome.lock').exists())
        fw=json.loads((self.base/'firewall.json').read_text())
        for key,rules in fw.items():
            if key.endswith(':OUTPUT'):
                self.assertFalse(any(any('AGH' in item for item in rule) for rule in rules))
        self.run_adg()
        self.assertEqual((self.base/'api-count').read_text().strip(),'2')
        self.assertIn('已停用',self.status()['error'])

    def test_network_change_same_upstream_only_clears_cache(self):
        self.fault_api(0)
        self.run_adg()
        self.assertEqual((self.base/'api-count').read_text().strip(),'1')
        (self.base/'bin/system-dns.answer').write_text('203.0.113.8')
        self.assertIn(bytes([203,0,113,8]),self.query('cache.example'))
        # Enable cache through API, query once, then invalidate on network change.
        self.api('dns_config',{'cache_enabled':True,'cache_size':1048576})
        self.assertIn(bytes([203,0,113,8]),self.query('cache2.example'))
        (self.base/'bin/system-dns.answer').write_text('203.0.113.9')
        (self.base/'network-id').write_text('2\n')
        self.run_adg()
        self.assertEqual((self.base/'api-count').read_text().strip(),'1')
        self.assertIn(bytes([203,0,113,9]),self.query('cache2.example'))

    def test_live_core_unready_does_not_trip_circuit(self):
        self.run_adg()
        path=self.base/'scripts/box.adg'
        text=path.read_text().replace('adg_paths\n','adg_paths\nadg_core_alive() { return 0; }\nadg_dns_ready() { return 1; }\n',1)
        path.write_text(text)
        result=self.run_adg(check=False)
        self.assertEqual(result.returncode,1,result.stderr)
        self.assertTrue(json.loads((self.base/'manage/preferences.json').read_text())['adguardhome_enabled'])
        self.assertFalse((self.base/'manage/adguardhome-disabled').exists())
        self.assertTrue(self.status()['running'])


@unittest.skipUnless(manager_fixture.YQ and fixture.shutil.which('busybox'), 'host yq required')
class AGHRuntimeRecoveryTest(unittest.TestCase):
    def setUp(self):
        self.fx=manager_fixture.ManagerFixture()
        self.addCleanup(self.fx.close)
        self.fx.call('status')
        self.base=self.fx.base
        service=functions(fixture.ROOT/'box/scripts/box.service',[
            'prepare_mihomo_runtime','reload_mihomo','recover_adg_dns','commit_network_dns_state'])
        self.fx.write('scripts/box.service',f'''#!/bin/bash
. "{self.base}/settings.ini"
. "$scripts_dir/dns.utils"
. "$scripts_dir/profile.utils"
. "$scripts_dir/adg.utils"
. "$scripts_dir/config.utils"
box_dns_paths
adg_core_alive() {{ [ -f "$box_dir/live" ]; }}
find_packages_uid() {{ :; }}
mfr_apps_signature() {{ echo fixture; }}
set_description() {{ :; }}
mfr_action_progress() {{ :; }}
log() {{ :; }}
box_dns_api_reload() {{
 [ ! -f "$box_dir/reload-fail" ] || return 1
 cp "$1" "$box_dir/applied-runtime.yaml"
}}
auto_modify_config=false
{service}
case "$1" in prepare) prepare_mihomo_runtime ;; adg-recover) recover_adg_dns "$2" ;; esac
''')
        self.fx.write('bin/pidof','#!/bin/sh\nexit 0\n')
        self.fx.write('scripts/box.iptables',f'#!/bin/sh\necho "$1" >> "{self.base}/capture-events"\n')
        self.fx.write('scripts/box.adg','#!/bin/sh\nexit 0\n')

    def prefs(self, enabled, hijack='follow'):
        path=self.base/'manage/preferences.json';values=json.loads(path.read_text())
        values.update(adguardhome_enabled=enabled,dns_hijack_mode=hijack)
        path.write_text(json.dumps(values))
        # Model real settings.ini resolution, which fixture normally simplifies.
        if 'dns_hijack_setting=$' not in (self.base/'settings.ini').read_text():
            with (self.base/'settings.ini').open('a') as f:
                f.write('\ndns_hijack_setting=$("$bin_dir/yq" -r .dns_hijack_mode "$preferences_file")\n')

    def sync(self, phase='sync'):
        command=f'. "{self.base}/settings.ini"; . "$scripts_dir/adg.utils"; adg_sync {phase}'
        return subprocess.run(['bash','-c',command],env=self.fx.env,text=True,capture_output=True,timeout=8)

    def runtime(self):
        return json.loads(subprocess.check_output([manager_fixture.YQ,'-o=json','.',str(self.base/'mihomo/.box-runtime.yaml')]))

    def test_disabled_agh_restores_runtime_and_user_hijack_preference(self):
        for live,setting in [(False,'follow'),(True,'on'),(True,'off')]:
            with self.subTest(live=live,setting=setting):
                self.prefs(True,setting)
                subprocess.run(['bash',str(self.base/'scripts/box.service'),'prepare'],env=self.fx.env,check=True,capture_output=True)
                self.assertEqual(self.runtime()['tun']['dns-hijack'],[])
                self.prefs(False,setting)
                pending=self.base/'manage/adguardhome-recovery-pending';pending.touch()
                (self.base/'live').unlink(missing_ok=True)
                if live:(self.base/'live').touch()
                result=self.sync()
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertFalse(pending.exists())
                self.assertEqual(self.runtime()['tun']['dns-hijack'],[] if setting=='off' else ['any:53','tcp://any:53'])
                if live:self.assertTrue((self.base/'applied-runtime.yaml').exists())
                self.assertFalse(json.loads((self.base/'manage/preferences.json').read_text())['adguardhome_enabled'])

    def test_restore_failure_remains_pending_and_does_not_reenable_agh(self):
        self.prefs(True)
        subprocess.run(['bash',str(self.base/'scripts/box.service'),'prepare'],env=self.fx.env,check=True,capture_output=True)
        self.prefs(False)
        pending=self.base/'manage/adguardhome-recovery-pending';pending.touch()
        (self.base/'live').touch();(self.base/'reload-fail').touch()
        # Managed stop defers reload, then a failed live reload remains retryable.
        self.assertEqual(self.sync('before-stop').returncode,0)
        self.assertTrue(pending.exists())
        self.assertNotEqual(self.sync().returncode,0)
        self.assertTrue(pending.exists())
        self.assertFalse(json.loads((self.base/'manage/preferences.json').read_text())['adguardhome_enabled'])
        self.assertEqual(self.runtime()['tun']['dns-hijack'],[])
        (self.base/'reload-fail').unlink()
        self.assertEqual(self.sync().returncode,0)
        self.assertFalse(pending.exists())


if __name__=='__main__':unittest.main()
