"""Focused host integration for the real shell manager/HTTP bridge.
Uses fake Android commands; it does not claim Android routing validation.
"""
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
YQ = os.environ.get('MFR_TEST_YQ') or shutil.which('yq')

class ManagerFixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-manager-')
        self.base = Path(self.tmp.name)
        for d in ('bin', 'scripts', 'manage', 'mihomo', 'run/state', 'lists', 'web/cgi-bin', 'templates'):
            (self.base/d).mkdir(parents=True)
        shutil.copy(YQ, self.base/'bin/yq')
        for p in (ROOT/'box/scripts').iterdir():
            if p.is_file():
                self.write('scripts/'+p.name, p.read_text().replace('/system/bin/sh','/bin/bash').replace('/data/adb/box', str(self.base)))
        self.write('scripts/daemon.utils', '#!/bin/sh\nmfr_daemon_detach() { return 0; }\n')
        for p in (ROOT/'webroot').iterdir():
            if p.is_file(): shutil.copy(p,self.base/'web'/p.name)
        (self.base/'web/index.html').chmod(0o600)
        shutil.copy(ROOT/'webroot/manage.html',self.base/'web/index.html')
        shutil.copy(ROOT/'box/lists/china-apps.json',self.base/'lists/china-apps.json')
        shutil.copy(ROOT/'box/lists/proxy-apps.json',self.base/'lists/proxy-apps.json')
        shutil.copy(ROOT/'box/templates/default.yaml',self.base/'templates/default.yaml')
        shutil.copy(ROOT/'box/templates/AdGuardHome.yaml',self.base/'templates/AdGuardHome.yaml')
        shutil.copy(ROOT/'box/templates/default.yaml',self.base/'mihomo/config.yaml')
        for folder in ('web','lists','templates','mihomo'):
            for file in (self.base/folder).rglob('*'):
                if file.is_file():file.chmod(0o600)
        self.write('bin/mihomo', '#!/bin/sh\nprintf "Mihomo fixture\\n"\n')
        self.write('bin/curl', f'''#!/bin/sh
[ ! -f {self.base}/download-fail ] || exit 1
config=$(cat)
while [ "$#" -gt 0 ]; do
 case "$1" in --output) shift; output="$1" ;; esac
 shift
done
case "$config" in *proxy_package_name*) printf 'com.future.proxy\\ncom.android.settings\\n' > "$output" ;; *) printf 'payload:\\n  - PROCESS-NAME,com.future.app\\n  - PROCESS-NAME,com.android.settings\\n' > "$output" ;; esac
''')
        self.write('bin/cmd', '''#!/bin/sh
# Model Android Binder rejecting private regular stdout/stderr descriptors.
if [ "$1" = package ] && { [ ! -p /dev/stdout ] || [ ! -p /dev/stderr ]; }; then echo 'cmd: rejected output descriptor'; exit 1; fi
case "$*" in
 'package list packages -s --user 0') echo package:com.android.settings ;;
 'package list packages -U --user 0') printf 'package:com.android.settings uid:1000\\npackage:com.example.installed uid:10001\\n' ;;
 'wifi status') printf 'Wifi is connected to "Test WiFi"\\nWifiInfo: Supplicant state: COMPLETED\\n' ;;
esac
''')
        self.write('bin/dumpsys', '#!/bin/sh\nprintf "Active default network: 1\\nNetworkAgentInfo{network{1} InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1 ]}\\n"\n')
        self.write('scripts/box.policy', '#!/bin/sh\nexit 0\n')
        self.write('scripts/box.dns', '#!/bin/sh\nexit 0\n')
        self.write('scripts/box.adg', '#!/bin/sh\nexit 0\n')
        self.write('scripts/box.service', f'''#!/bin/bash
. {self.base}/settings.ini
. {self.base}/scripts/profile.utils
mfr_expand_config "$mihomo_config" "$box_dir/mihomo/.box-runtime.yaml"
''')
        self.write('settings.ini', f'''export PATH="{self.base}/bin:$PATH"
box_dir="{self.base}"
scripts_dir="$box_dir/scripts"
box_run="$box_dir/run"
box_run_state="$box_run/state"
box_pid="$box_run/box.pid"
bin_dir="$box_dir/bin"
bin_path="$bin_dir/mihomo"
bin_name=mihomo
manage_dir="$box_dir/manage"
preferences_file="$manage_dir/preferences.json"
mihomo_config="$box_dir/mihomo/config.yaml"
system_packages_file="$box_dir/packages.list"
routing_mode=rule
ipv6_mode=follow
dns_hijack_setting=follow
proxy_mode=core
follow_network_dns=true
if [ -f "$preferences_file" ]; then
 routing_mode=$("$bin_dir/yq" -r '.routing_mode // "rule"' "$preferences_file")
 tun_mode=$("$bin_dir/yq" -r '.tun_mode // "follow"' "$preferences_file")
 dns_mode=$("$bin_dir/yq" -r '.dns_mode // "follow"' "$preferences_file")
 ipv6_mode=$("$bin_dir/yq" -r '.ipv6_mode // "follow"' "$preferences_file")
 adguardhome_enabled=$("$bin_dir/yq" -r '.adguardhome_enabled // false' "$preferences_file")
 case $("$bin_dir/yq" -r .app_mode "$preferences_file") in exclude) proxy_mode=blacklist ;; include) proxy_mode=whitelist ;; esac
fi
. "$scripts_dir/network.utils"
''')
        (self.base/'packages.list').write_text('com.example.installed 10001\ncom.android.settings 1000\n')
        self.env={**os.environ,'PATH':str(self.base/'bin')+':'+os.environ['PATH']}
        with socket.socket() as sock:
            sock.bind(('127.0.0.1',0));self.port=sock.getsockname()[1]
        cgi=(self.base/'scripts/http.cgi').read_text().replace('9091',str(self.port))
        self.write('web/cgi-bin/manager',cgi)
        self.write('web/httpd.conf','.webmanifest:application/manifest+json\n.svg:image/svg+xml\n.js:application/javascript\n')
        self.http=subprocess.Popen(['busybox','httpd','-f','-p',f'127.0.0.1:{self.port}','-h',str(self.base/'web'),'-c',str(self.base/'web/httpd.conf')],env=self.env,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        for _ in range(50):
            try:
                urllib.request.urlopen(self.url(),timeout=1).close();break
            except OSError: time.sleep(.02)

    def write(self,name,content):
        p=self.base/name;p.write_text(content);p.chmod(0o700)
    def url(self,path='/'):
        return f'http://127.0.0.1:{self.port}{path}'
    def call(self,action,payload=None,headers=None):
        request=urllib.request.Request(self.url('/cgi-bin/manager?'+action),data=json.dumps(payload or {}).encode(),headers={'Content-Type':'application/json',**(headers or {})})
        with urllib.request.urlopen(request,timeout=20) as response:return json.load(response)
    def close(self):
        self.http.terminate();self.http.wait(timeout=5);self.tmp.cleanup()

@unittest.skipUnless(YQ and shutil.which('busybox'), 'set MFR_TEST_YQ to a host yq executable')
class ManagerIntegrationTest(unittest.TestCase):
    def setUp(self): self.fx=ManagerFixture()
    def tearDown(self): self.fx.close()
    def payload(self,mode='rule'):
        return dict(routing_mode=mode,ipv6_mode='follow',dns_hijack_mode='on',wifi_pause_enabled=False,wifi_pause_ssids=[],append_network_dns=True,app_mode='exclude',include_apps=[],exclude_apps=['com.future.app','com.example.installed'])
    def test_browser_status_and_system_apps(self):
        state=self.fx.call('status');self.assertEqual(state['dns_detected'],['10.0.0.1'])
        self.assertEqual(state['adg_controls']['filter_urls'],['https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt'])
        apps=self.fx.call('apps');self.assertTrue(next(a for a in apps if a['packageName']=='com.android.settings')['system'])
    def test_modes_and_pending_packages_persist(self):
        for mode in ('global','direct','rule'):
            self.fx.call('settings-save',self.payload(mode))
            state=self.fx.call('status');self.assertEqual(state['preferences']['routing_mode'],mode)
            self.assertIn('com.future.app',state['preferences']['exclude_apps'])
            runtime=subprocess.check_output([YQ,'-r','.mode',str(self.fx.base/'mihomo/.box-runtime.yaml')],text=True).strip()
            self.assertEqual(runtime,mode)
    def test_online_cache_and_builtin_fallback(self):
        online=self.fx.call('app-list-preview');self.assertEqual(online['origin'],'online')
        (self.fx.base/'download-fail').touch()
        cached=self.fx.call('app-list-preview');self.assertEqual(cached['origin'],'cache');self.assertEqual(cached['packages'],online['packages'])
        (self.fx.base/'manage/china-apps-cache.json').unlink()
        builtin=self.fx.call('app-list-preview');self.assertEqual(builtin['origin'],'builtin');self.assertGreater(len(builtin['packages']),3000)
    def test_invalid_and_cross_origin_requests_do_not_change_preferences(self):
        self.fx.call('settings-save',self.payload());before=(self.fx.base/'manage/preferences.json').read_bytes()
        invalid=self.payload();invalid['exclude_apps']=['bad name']
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',invalid)
        self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),before)
        with self.assertRaises(urllib.error.HTTPError) as error:self.fx.call('settings-save',self.payload(),{'Origin':'https://other.invalid'})
        self.assertEqual(error.exception.code,403)
    def test_install_refresh_only_when_uid_changes_and_running(self):
        self.fx.call('settings-save',self.payload())
        original=(ROOT/'box/scripts/box.policy').read_text().split('trap release EXIT')[0]
        self.fx.write('scripts/policy-functions',original.replace('/system/bin/sh','/bin/bash').replace('/data/adb/box',str(self.fx.base)))
        service=self.fx.base/'scripts/box.service'
        service.write_text(service.read_text()+f'\nif [ "$1" = restart ]; then echo restart >> "{self.fx.base}/restarts"; . "{self.fx.base}/scripts/apps.utils"; mfr_apps_signature > "$box_run_state/apps.applied"; fi\n')
        command=f'''set -e
. "{self.fx.base}/scripts/policy-functions"
live() {{ return 0; }}
mfr_apps_signature > "$box_run_state/apps.applied"
refresh_apps
[ ! -f "{self.fx.base}/restarts" ]
printf 'com.future.app 10002\\n' >> "$system_packages_file"
refresh_apps
[ "$(wc -l < "{self.fx.base}/restarts")" = 1 ]
refresh_apps
[ "$(wc -l < "{self.fx.base}/restarts")" = 1 ]
live() {{ return 1; }}
printf 'com.extra.app 10003\\n' >> "$system_packages_file"
refresh_apps
[ "$(wc -l < "{self.fx.base}/restarts")" = 1 ]
'''
        subprocess.run(['bash','-c',command],env=self.fx.env,check=True,capture_output=True)

    def test_large_browser_request_and_uid_refresh(self):
        payload=self.payload();payload['exclude_apps'] += [f'com.future.application{i}' for i in range(4000)]
        self.fx.call('settings-save',payload)
        self.assertEqual(len(self.fx.call('status')['preferences']['exclude_apps']),4002)
        command=f'. "{self.fx.base}/settings.ini"; . "{self.fx.base}/scripts/apps.utils"; mfr_apps_signature'
        before=subprocess.check_output(['bash','-c',command],env=self.fx.env,text=True)
        with (self.fx.base/'packages.list').open('a') as f:f.write('com.future.app 10002\n')
        after=subprocess.check_output(['bash','-c',command],env=self.fx.env,text=True)
        self.assertNotIn('10002',before);self.assertIn('10002',after)

if __name__ == '__main__':unittest.main()


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq/BusyBox')
class ShortcutManagerTest(unittest.TestCase):
    def setUp(self):self.fx=ManagerFixture();self.fx.call('status')
    def tearDown(self):self.fx.close()
    def payload(self):
        return dict(routing_mode='rule',tun_mode='follow',dns_mode='follow',ipv6_mode='follow',dns_hijack_mode='on',adguardhome_enabled=False,wifi_pause_enabled=False,wifi_pause_ssids=[],append_network_dns=True,app_mode='exclude',include_apps=['com.future.proxy'],exclude_apps=['com.example.installed','com.future.app'])
    def test_proxy_source_fallback_and_package_counts(self):
        self.fx.call('settings-save',self.payload())
        self.assertEqual(self.fx.call('status')['app_counts'],{'include':0,'exclude':1})
        online=self.fx.call('app-list-preview',{'kind':'proxy'});self.assertEqual(online['origin'],'online');self.assertIn('com.future.proxy',online['packages'])
        (self.fx.base/'download-fail').touch()
        self.assertEqual(self.fx.call('app-list-preview',{'kind':'proxy'})['origin'],'cache')
        (self.fx.base/'manage/proxy-apps-cache.json').unlink()
        fallback=self.fx.call('app-list-preview',{'kind':'proxy'});self.assertEqual(fallback['origin'],'builtin');self.assertIn('com.openai.chatgpt',fallback['packages'])
    def test_controls_validate_preserve_old_clients_and_skip_core_reload(self):
        values=self.payload();self.fx.call('settings-save',values)
        service=self.fx.base/'scripts/box.service';service.write_text(service.read_text()+f'\necho "$1" >> "{self.fx.base}/service-calls"\n')
        controls=dict(ipv6_filter=True,ipv6_allow=['EXAMPLE.COM'],adblock=False,filter_urls=['https://filters.example/one'])
        self.fx.call('settings-save',{**values,'adg_controls':controls})
        self.assertFalse((self.fx.base/'service-calls').exists())
        self.assertEqual(self.fx.call('status')['adg_controls']['ipv6_allow'],['example.com'])
        self.fx.call('settings-save',values)
        before=(self.fx.base/'manage/preferences.json').read_bytes()
        for bad in [{**controls,'filter_urls':['https://example.test/'+str(i) for i in range(4)]},{**controls,'ipv6_allow':['not a domain']},{**controls,'filter_urls':['file:///private']}]:
            with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',{**values,'adg_controls':bad})
            self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),before)

    def test_agh_comments_roundtrip_and_only_active_lines_count(self):
        values=self.payload()
        controls=dict(ipv6_filter=True,ipv6_allow=['# Allow Domains','  # OLD.EXAMPLE',' EXAMPLE.COM '],
            adblock=True,filter_urls=['# 允许增删或者注释','  # https://disabled.example/list','https://filters.example/list#fragment'])
        self.fx.call('settings-save',{**values,'adg_controls':controls})
        saved=self.fx.call('status')['adg_controls']
        self.assertEqual(saved['ipv6_allow'],['# Allow Domains','  # OLD.EXAMPLE','example.com'])
        self.assertEqual(saved['filter_urls'],controls['filter_urls'])
        self.fx.call('settings-save',values) # Older clients keep comments too.
        self.assertEqual(self.fx.call('status')['adg_controls'],saved)
        controls['filter_urls']=['# Entire list disabled',' # https://disabled.example/list']
        self.fx.call('settings-save',{**values,'adg_controls':controls})
        self.assertEqual(self.fx.call('status')['adg_controls']['filter_urls'],controls['filter_urls'])
        before=(self.fx.base/'manage/preferences.json').read_bytes()
        for bad in ({**controls,'filter_urls':['# header']+['https://example.test/'+str(i) for i in range(4)]},
                    {**controls,'ipv6_allow':['# header','not a domain']},
                    {**controls,'filter_urls':['# header',42]},
                    {**controls,'ipv6_allow':['# header\nnot-a-domain']}):
            with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',{**values,'adg_controls':bad})
            self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),before)
