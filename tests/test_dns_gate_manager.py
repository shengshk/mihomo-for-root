"""Focused migration, scoped save and observed-chain restriction tests."""
import hashlib,json,os,shutil,signal,subprocess,time,unittest,urllib.error
from pathlib import Path
from test_manager import ManagerFixture,YQ,ROOT
from test_dns_gate import port

GATE=os.environ.get('MFR_TEST_DNS_GATE')

@unittest.skipUnless(YQ and GATE and shutil.which('busybox'),'host gate/yq/BusyBox required')
class DNSGateManagerTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture();self.addCleanup(self.fx.close);self.fx.call('status')
        self.base=self.fx.base;self.pref=self.base/'manage/preferences.json'
    def bash(self,body):
        cmd=f'. "{self.base}/settings.ini"; . "$scripts_dir/dns-gate.utils"; gate_paths; '+body
        return subprocess.run(['bash','-c',cmd],text=True,capture_output=True,env=self.fx.env,check=True)
    def test_legacy_filter_migrates_once_with_comments(self):
        prefs=json.loads(self.pref.read_text());prefs['adg_controls']=dict(ipv6_filter=True,ipv6_allow=['# keep','example.com'],adblock=False,filter_urls=[]);self.pref.write_text(json.dumps(prefs))
        self.bash('gate_migrate');saved=json.loads(self.pref.read_text())
        self.assertEqual(saved['ipv6_dns'],dict(mode='whitelist',blacklist=[],whitelist=['# keep','example.com']))
        self.assertEqual(saved['adg_controls'],prefs['adg_controls'])
        self.bash('gate_migrate');self.assertEqual(json.loads(self.pref.read_text()),saved)
    def test_card_save_validation_and_no_core_restart(self):
        value=dict(mode='whitelist',china_ipv6=False,blacklist=['blocked.example'],whitelist=['# keep','example.com'])
        self.fx.write('scripts/box.service',f'#!/bin/sh\necho "$1" >> "{self.base}/service-calls"\n')
        self.fx.call('settings-save',dict(section='ipv6dns',ipv6_dns=value))
        self.assertFalse((self.base/'service-calls').exists())
        self.assertEqual(json.loads(self.pref.read_text())['ipv6_dns'],value)
        self.fx.call('settings-save',dict(section='wifi',wifi_pause_enabled=True,wifi_pause_ssids=['Test']))
        self.assertEqual(json.loads(self.pref.read_text())['ipv6_dns'],value)
        before=self.pref.read_bytes()
        for invalid in [dict(mode='on',china_ipv6='true',blacklist=[],whitelist=[]),dict(mode='bad',blacklist=[],whitelist=[]),dict(mode='on',blacklist=['bad name'],whitelist=[]),dict(mode='on',blacklist='example.com',whitelist=[])]:
            with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',dict(section='ipv6dns',ipv6_dns=invalid))
            self.assertEqual(self.pref.read_bytes(),before)
    def test_cn_preset_save_and_database_validation(self):
        (self.base/'bin/dns-gate').symlink_to(GATE)
        value=dict(mode='off',china_ipv6=True,blacklist=[],whitelist=[])
        before=self.pref.read_bytes()
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',dict(section='ipv6dns',ipv6_dns=value))
        self.assertEqual(self.pref.read_bytes(),before)
        import struct
        def field(n,data):
            length=len(data);out=bytes([n<<3|2])
            while length>=128:out+=bytes([(length&127)|128]);length>>=7
            return out+bytes([length])+data
        entry=field(1,b'CN')+field(2,b'\x08\x02'+field(2,b'example.cn'))
        (self.base/'mihomo/GeoSite.dat').write_bytes(field(1,entry))
        self.fx.call('settings-save',dict(section='ipv6dns',ipv6_dns=value))
        self.assertEqual(json.loads(self.pref.read_text())['ipv6_dns'],value)
        self.fx.call('settings-save',dict(section='wifi',wifi_pause_enabled=True,wifi_pause_ssids=['Test']))
        self.assertTrue(json.loads(self.pref.read_text())['ipv6_dns']['china_ipv6'])

    def test_actual_chain_restrictions_and_inactive_status(self):
        (self.base/'bin/dns-gate').symlink_to(GATE)
        config=self.base/'run/state/dns-gate.json';state=self.base/'run/state/dns-gate.applied.json';pid=self.base/'run/state/dns-gate.pid'
        def write(backend):
            config.write_text(json.dumps(dict(mode='whitelist',blacklist=[],whitelist=['example.com'],backend=backend,upstreams=['127.0.0.1:1'])))
        write('mihomo');number=port()
        proc=subprocess.Popen([str(self.base/'bin/dns-gate'),'-config',str(config),'-listen4',f'127.0.0.1:{number}','-ready-file',str(pid),'-state-file',str(state)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.addCleanup(lambda:(proc.terminate(),proc.wait(timeout=7)))
        def wait():
            for _ in range(100):
                try:
                    if json.loads(state.read_text())['digest']==hashlib.sha256(config.read_bytes()).hexdigest():return
                except (OSError,ValueError):pass
                time.sleep(.01)
            self.fail('no applied state')
        wait();(self.base/'run/state/dns-gate.capture').write_text('transparent-v2')
        prefs=json.loads(self.pref.read_text());prefs['ipv6_dns']=dict(mode='whitelist',blacklist=[],whitelist=['example.com']);self.pref.write_text(json.dumps(prefs))
        runtime=self.base/'mihomo/.box-runtime.yaml'
        runtime.write_text('ipv6: false\ndns:\n  ipv6: false\n')
        self.assertIn('Mihomo IPv6 已关闭',self.fx.call('status')['ipv6_dns']['summary'])
        runtime.write_text('ipv6: true\ndns:\n  ipv6: false\n')
        self.assertIn('Mihomo IPv6 解析已关闭',self.fx.call('status')['ipv6_dns']['summary'])
        write('agh');proc.send_signal(signal.SIGHUP);wait()
        with (self.base/'scripts/adg.utils').open('a') as f:f.write('''\nadg_status() { echo '{"running":true,"api_available":true,"upstream":"mihomo","aaaa_filter":"disabled","error":""}'; }\n''')
        self.assertIn('Mihomo IPv6 解析已关闭',self.fx.call('status')['ipv6_dns']['summary'])
        with (self.base/'scripts/adg.utils').open('a') as f:f.write('''\nadg_status() { echo '{"running":true,"api_available":true,"upstream":"system","aaaa_filter":"enabled","error":""}'; }\n''')
        self.assertIn('AGH 阻止 IPv6 解析',self.fx.call('status')['ipv6_dns']['summary'])
        (self.base/'run/state/dns-gate.capture').unlink()
        self.assertIn('未生效',self.fx.call('status')['ipv6_dns']['summary'])

if __name__=='__main__':unittest.main()
