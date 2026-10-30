"""Real DNS gate and AGH; Android firewall/routing commands use private emulation."""
import json,os,shutil,struct,subprocess,unittest
from pathlib import Path
import test_adguardhome as fixture
from test_dns_gate import port
GATE=os.environ.get('MFR_TEST_DNS_GATE')

@unittest.skipUnless(GATE and fixture.AGH and fixture.YQ and shutil.which('busybox'),'host gate/AGH/yq required')
class DNSGateLifecycleTest(unittest.TestCase):
    write=fixture.AdGuardHomeTest.write
    spawn=fixture.AdGuardHomeTest.spawn
    def run_adg(self,action='sync',check=True):
        result=fixture.AdGuardHomeTest.run_adg(self,action,check=False)
        if check and result.returncode:
            logs=[]
            for path in sorted((self.base/'run').glob('adguardhome*')):
                if path.is_file():logs.append(path.name+': '+path.read_text(errors='replace')[-3500:])
            self.fail(result.stdout+result.stderr+'\n'+'\n'.join(logs))
        return result
    api=fixture.AdGuardHomeTest.api
    status=fixture.AdGuardHomeTest.status
    close=fixture.AdGuardHomeTest.close
    def setUp(self):
        fixture.AdGuardHomeTest.setUp(self)
        self.number=port()
        for name in ['box.dns-gate','dns-gate.utils','dns-gate-capture.utils']:
            source=(fixture.ROOT/'box/scripts'/name).read_text().replace('/data/adb/box',str(self.base)).replace('/system/bin/sh','/bin/bash')
            # Transparent listeners require CAP_NET_ADMIN; this fixture tests real
            # backend lifecycle while firewall/route operations are emulated.
            if name=='box.dns-gate':source=source.replace('-transparent4 "127.0.0.1:$gate_bridge_port" -transparent6 "[::1]:$gate_bridge_port"','')
            self.write('scripts/'+name,source)
        (self.base/'bin/dns-gate').symlink_to(GATE)
        p=self.base/'scripts/ports.utils';p.write_text(p.read_text().replace('dns_gate_port=15354',f'dns_gate_port={self.number}').replace('adg_dns_port=1054',f'adg_dns_port={self.dns}'))
        with (self.base/'settings.ini').open('a') as f:f.write('\ndns_gate_managed=true\n. "$box_dir/scripts/ports.utils"\n')
        with (self.base/'scripts/dns.utils').open('a') as f:f.write(f'\nbox_dns_parse_network_all() {{ cat >/dev/null; echo "$(cat {self.base}/network-id)|wlan0|127.0.0.1:{self.system}"; }}\n')
        p=self.base/'bin/ip';p.write_text(p.read_text().replace('90:','91:').replace('0x8000000','0x10000000').replace('2054','2055'))
        self.write('templates/carrier-dns.txt',(fixture.ROOT/'box/templates/carrier-dns.txt').read_text())
        self.prefs(False)
        self.addCleanup(self.stop_gate)
    def prefs(self,enabled):
        path=self.base/'manage/preferences.json';value=json.loads(path.read_text());value.update(dict(adguardhome_enabled=enabled,adg_controls=dict(ipv6_filter=True,ipv6_allow=['example.com'],adblock=False,filter_urls=[])));path.write_text(json.dumps(value))
    def gate(self,phase='sync'):
        p=subprocess.run(['bash',str(self.base/'scripts/box.dns-gate'),'sync',phase],env={**os.environ,'MFR_ADG_OPERATION':'1'},capture_output=True,text=True,timeout=15)
        if p.returncode:
            diagnostic=''
            for name in ['run/state/dns-gate.error','run/dns-gate.log']:
                f=self.base/name
                if f.exists():diagnostic+='\n'+name+': '+f.read_text()
            trace=subprocess.run(['bash','-x',str(self.base/'scripts/box.dns-gate'),'sync',phase],env={**os.environ,'MFR_ADG_OPERATION':'1'},capture_output=True,text=True,timeout=15)
            self.fail(p.stdout+p.stderr+diagnostic+'\n'+trace.stderr[-6500:])
        return json.loads((self.base/'run/state/dns-gate.applied.json').read_text())
    def ask(self,name,kind):
        import socket
        q=b'\x12\x34'+struct.pack('!HHHHH',0x100,1,0,0,0)+b''.join(bytes([len(s)])+s.encode() for s in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:s.settimeout(2);s.sendto(q,('127.0.0.1',self.number));a=s.recv(4096)
        self.assertEqual(a[3]&15,0);return struct.unpack('!H',a[6:8])[0]
    def stop_gate(self):
        subprocess.run(['bash',str(self.base/'scripts/box.dns-gate'),'stop'],capture_output=True,timeout=10)
    def test_modes_survive_backend_changes_and_capture_is_idempotent(self):
        self.assertEqual(self.gate()['backend'],'system')
        self.assertEqual(self.ask('other.example',28),0);self.assertEqual(self.ask('sub.example.com',28),1)
        first=(self.base/'run/state/dns-gate.pid').read_text()
        self.gate();self.assertEqual((self.base/'run/state/dns-gate.pid').read_text(),first)
        core=self.spawn('mihomo',self.core,'198.18.0.7');(self.base/'run/box.pid').write_text(str(core.pid))
        with (self.base/'settings.ini').open('a') as f:f.write('\ndns_hijack_tcp=true;dns_hijack_udp=true\n')
        self.assertEqual(self.gate()['backend'],'mihomo')
        self.assertEqual(self.ask('sub.example.com',28),1);self.assertEqual(self.ask('other.example',28),0)
        self.assertEqual(self.gate('before-stop')['backend'],'system')
        self.prefs(True);self.run_adg()
        self.assertEqual(self.gate()['backend'],'agh')
        self.assertEqual(self.ask('sub.example.com',28),1);self.assertEqual(self.ask('other.example',28),0)
        self.assertFalse(any(rule.startswith('$dnstype=AAAA') for rule in self.api('filtering/status')['user_rules']))
        (self.base/'disabled').touch()
        self.run_adg();self.assertEqual(self.gate()['backend'],'mihomo')
        self.assertEqual(self.ask('other.example',1),1)
        self.assertEqual((self.base/'run/state/dns-gate.pid').read_text(),first)

if __name__=='__main__':unittest.main()
