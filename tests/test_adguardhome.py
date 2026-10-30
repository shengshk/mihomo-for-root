"""Real AGH/API/DNS checks in a private directory; firewall calls are emulated."""
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
YQ = os.environ.get('MFR_TEST_YQ') or shutil.which('yq')
AGH = os.environ.get('MFR_TEST_AGH')

_fixture_ports=set()
def port():
    # DNS fixtures bind both transports; a free TCP port can still have a live
    # UDP owner. Avoid collisions with that owner and our own earlier choices.
    for _ in range(100):
        with socket.socket() as tcp,socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
            tcp.bind(('127.0.0.1',0));number=tcp.getsockname()[1]
            if number in _fixture_ports:continue
            try:udp.bind(('127.0.0.1',number))
            except OSError:continue
            _fixture_ports.add(number);return number
    raise RuntimeError('no free TCP/UDP DNS fixture port')

DNS_SERVER = '''import socket,struct,sys
from pathlib import Path
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',int(sys.argv[1])))
while True:
 data,peer=s.recvfrom(4096);end=12;labels=[]
 while data[end]:
  size=data[end];labels.append(data[end+1:end+1+size].decode());end+=1+size
 end+=1;kind=struct.unpack('!H',data[end:end+2])[0];question=data[12:end+4]
 name='.'.join(labels)
 current=Path(sys.argv[0]+'.answer')
 address=current.read_text().strip() if current.exists() else sys.argv[2]
 ip='8.8.8.8' if 'google-public-dns' in name or name=='dns.google' else address
 payload=socket.inet_aton(ip) if kind==1 else socket.inet_pton(socket.AF_INET6,'2001:db8::7') if kind==28 else b''
 answer=struct.pack('!HHHLH',0xc00c,kind,1,600,len(payload))+payload if payload else b''
 s.sendto(data[:2]+struct.pack('!HHHHH',0x8180,1,bool(answer),0,0)+question+answer,peer)
'''

FIREWALL = '''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
base=Path(__file__).parent.parent;path=base/'firewall.json'
db=json.loads(path.read_text()) if path.exists() else {}
a=sys.argv[1:];a=a[2:] if a[:1]==['-w'] else a
table=a[1];a=a[2:];op=a[0];chain=a[1];rule=a[2:]
family=Path(sys.argv[0]).name
if 'REDIRECT' in rule and '-p' not in rule:sys.exit(2)
if family=='ip6tables' and table=='nat' and (base/'no-nat6').exists():sys.exit(1)
key=family+':'+table+':'+chain
if chain in ('OUTPUT','PREROUTING'):db.setdefault(key,[])
ok=True
if op=='-N':
 ok=key not in db
 if ok:db[key]=[]
elif op=='-C':ok=rule in db.get(key,[])
elif op=='-S':ok=key in db
elif op in ['-A','-I']:
 ok=key in db
 if op=='-I':rule=rule[1:]
 if ok:db[key].append(rule)
elif op=='-F':ok=key in db;db[key]=[]
elif op=='-X':db.pop(key,None)
elif op=='-D':
 ok=rule in db.get(key,[])
 if ok:db[key].remove(rule)
else:sys.exit('unexpected firewall operation')
path.write_text(json.dumps(db));sys.exit(0 if ok else 1)
'''

@unittest.skipUnless(YQ and AGH and shutil.which('busybox'), 'set MFR_TEST_AGH to official host AGH binary')
class AdGuardHomeTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-adg-')
        self.base = Path(self.tmp.name)
        self.children = []
        for d in ('bin', 'scripts', 'templates', 'manage', 'run/state', 'adguardhome'):
            (self.base/d).mkdir(parents=True)
        self.http, self.dns, self.core, self.system = [port() for _ in range(4)]
        # This host has IPv6 disabled; exercise the phone's no-NAT6 path.
        (self.base/'no-nat6').touch()
        (self.base/'bin/yq').symlink_to(YQ)
        (self.base/'bin/curl').symlink_to(shutil.which('curl'))
        (self.base/'bin/AdGuardHome').symlink_to(AGH)
        self.write('bin/busybox', '#!/bin/sh\nif [ "$1" = setuidgid ]; then shift 2; exec "$@"; fi\nexec /usr/bin/busybox "$@"\n')
        for family in ('iptables', 'ip6tables'): self.write('bin/'+family, FIREWALL)
        self.write('bin/dumpsys', '#!/bin/sh\nexit 0\n')
        self.write('bin/ip', f'''#!/bin/sh
case "$*" in
 '-6 rule show pref '*) cat "{self.base}/route-rule" 2>/dev/null; exit 0 ;;
 '-6 rule add '*) echo '90: from all fwmark 0x8000000/0x8000000 lookup 2054' > "{self.base}/route-rule" ;;
 '-6 rule del '*) rm -f "{self.base}/route-rule" ;;
esac
exit 0
''')
        self.write('bin/mihomo', DNS_SERVER)
        self.write('bin/system-dns', DNS_SERVER)
        for name in ('box.adg', 'box.daemon', 'daemon.utils', 'adg.utils', 'adg-capture.utils', 'dns.utils', 'network.utils', 'ports.utils', 'adg-controls.utils'):
            source = (ROOT/'box/scripts'/name).read_text().replace('/data/adb/box', str(self.base)).replace('/system/bin/sh', '/bin/bash')
            source = source.replace('/system/bin/curl', str(self.base/'bin/curl'))
            source = source.replace('127.0.0.1:9092', f'127.0.0.1:{self.http}').replace('mfr_dns_port=15353', f'mfr_dns_port={self.core}')
            source = source.replace('--no-check-update', '--no-check-update --no-permcheck')
            if name == 'box.adg':
                # Host fixtures emulate lifecycle only. Real IPv6 sockets/routes
                # are checked by fixtures/agh_dns_namespace.sh on Android.
                source=source.replace('. "$scripts_dir/adg-capture.utils"', '. "$scripts_dir/adg-capture.utils"\n'
                    'adg_bridge_start() { echo fixture > "$adg_bridge_pid"; }\n'
                    'adg_bridge_stop() { rm -f "$adg_bridge_pid"; }\n')
            self.write('scripts/'+name, source)
        self.write('scripts/daemon.utils', '#!/bin/sh\nmfr_daemon_detach() { return 0; }\n')
        # Model the default network; the Android dump parser has separate tests.
        self.write('network-id', '1\n')
        with (self.base/'scripts/dns.utils').open('a') as f:
            f.write(f'\nbox_dns_parse_network() {{ cat >/dev/null; echo "$(cat {self.base}/network-id)|wlan0|127.0.0.1:{self.system}"; }}\n')
        template=(ROOT/'box/templates/AdGuardHome.yaml').read_text().replace('127.0.0.1:9092', f'127.0.0.1:{self.http}').replace('port: 1054', f'port: {self.dns}')
        self.write('templates/AdGuardHome.yaml', template)
        self.write('settings.ini', f'''export PATH="{self.base}/bin:$PATH"
box_dir="{self.base}"
bin_dir="$box_dir/bin"
box_run="$box_dir/run"
box_run_state="$box_run/state"
box_pid="$box_run/box.pid"
manage_dir="$box_dir/manage"
preferences_file="$manage_dir/preferences.json"
adguardhome_enabled=$("$bin_dir/yq" -r '.adguardhome_enabled // false' "$preferences_file")
[ ! -f "$box_dir/disabled" ] || adguardhome_enabled=false
''')
        (self.base/'manage/preferences.json').write_text(json.dumps({'adguardhome_enabled':True}))
        self.spawn('system-dns', self.system, '203.0.113.7')
        self.addCleanup(self.close)

    def write(self, name, text):
        p=self.base/name;p.write_text(text);p.chmod(0o700)
    def spawn(self, name, number, address):
        p=subprocess.Popen(['python3',str(self.base/'bin'/name),str(number),address],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.children.append(p);time.sleep(.06);return p
    def run_adg(self, action='sync', check=True):
        return subprocess.run(['bash',str(self.base/'scripts/box.adg'),action],text=True,capture_output=True,timeout=45,check=check,env={**os.environ,'MFR_ADG_OPERATION':'1'})
    def api(self, path, data=None):
        req=urllib.request.Request(f'http://127.0.0.1:{self.http}/control/'+path, data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(req,timeout=5) as r:
            body=r.read();return json.loads(body) if body else None
    def query(self, name='sample.example', kind=1):
        question=b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(3);s.sendto(b'\x12\x34'+struct.pack('!HHHHH',0x100,1,0,0,0)+question,('127.0.0.1',self.dns));return s.recv(4096)
    def status(self):
        network=self.base/'detected.json';network.write_text(json.dumps([f'127.0.0.1:{self.system}']))
        command=f'. "{self.base}/settings.ini"; . "{self.base}/scripts/adg.utils"; adg_paths; adg_status "{self.base}" "{network}"'
        return json.loads(subprocess.check_output(['bash','-c',command],text=True))
    def close(self):
        try: self.run_adg('stop',check=False)
        except (OSError,subprocess.TimeoutExpired): pass
        for p in self.children:
            p.terminate();p.wait(timeout=5)
        self.tmp.cleanup()

    def test_system_core_stop_switch_clears_fakeip_cache(self):
        self.run_adg();self.assertEqual(self.api('dns_info')['fallback_dns'],[])
        self.assertEqual(self.api('querylog/config')['interval'],86400000)
        self.assertTrue(self.api('querylog/config')['enabled'])
        self.assertTrue(self.api('stats/config')['enabled'])
        self.assertEqual(self.api('stats/config')['interval'],86400000)
        self.assertTrue(self.query().endswith(socket.inet_aton('203.0.113.7')))
        self.api('dns_config',{'cache_enabled':True,'cache_size':4194304})
        p=self.spawn('mihomo',self.core,'198.18.0.7');(self.base/'run/box.pid').write_text(str(p.pid))
        self.run_adg();self.assertTrue(self.query().endswith(socket.inet_aton('198.18.0.7')))
        self.run_adg('before-stop')
        self.assertTrue(self.query().endswith(socket.inet_aton('203.0.113.7')))
        self.assertTrue(self.api('dns_info')['cache_enabled'])
        self.assertEqual(self.api('dns_info')['fallback_dns'],[])

    def test_aaaa_exceptions_keep_a_queries_and_blocklist_active(self):
        self.run_adg()
        self.api('filtering/set_rules',{'rules':['$dnstype=AAAA,denyallow=example.com|example.net,dnsrewrite=NOERROR;;','||ads.example.com^']})
        self.assertEqual(struct.unpack('!H',self.query('other.example',28)[6:8])[0],0)
        for name in ('example.com','sub.example.com','example.net'):
            self.assertEqual(struct.unpack('!H',self.query(name,28)[6:8])[0],1)
        self.assertTrue(self.query('other.example',1).endswith(socket.inet_aton('203.0.113.7')))
        self.assertTrue(self.query('ads.example.com',1).endswith(b'\0\0\0\0'))

    def filter_server(self):
        import http.server, threading
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == '/fail':self.send_error(404);return
                self.send_response(200);self.end_headers()
                self.wfile.write(b'! Test filter\n||ads.shortcut.test^\n')
            def log_message(self,*args):pass
        server=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
        thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(server.server_close);self.addCleanup(server.shutdown)
        return f'http://127.0.0.1:{server.server_port}'

    def controls(self, **changes):
        file=self.base/'manage/preferences.json'
        prefs=json.loads(file.read_text()) if file.exists() else {'adg_controls':{'ipv6_filter':False,'ipv6_allow':[],'adblock':False,'filter_urls':[]}}
        prefs['adg_controls'].update(changes);file.write_text(json.dumps(prefs))

    def test_shortcut_migration_reads_existing_urls_and_aaaa_exceptions(self):
        self.run_adg()
        self.api('filtering/set_rules',{'rules':['$dnstype=AAAA,denyallow=example.com|example.net,dnsrewrite=NOERROR;;']})
        command=f'. "{self.base}/settings.ini"; . "$box_dir/scripts/adg.utils"; . "$box_dir/scripts/adg-controls.utils"; adg_paths; adg_controls_read "{self.base}/controls.json"'
        subprocess.run(['bash','-c',command],text=True,capture_output=True,check=True)
        value=json.loads((self.base/'controls.json').read_text())
        self.assertEqual(value,dict(ipv6_filter=True,ipv6_allow=['example.com','example.net'],adblock=False,filter_urls=['https://raw.githubusercontent.com/217heidai/adblockfilters/main/rules/adblockdns.txt']))

    def test_shortcuts_toggle_lists_and_aaaa_independently_without_restart(self):
        url=self.filter_server()+'/list'
        self.run_adg();pid=(self.base/'run/state/adguardhome.pid').read_text()
        self.api('filtering/set_rules',{'rules':['||keep.user.test^']})
        self.api('dns_config',{'disable_ipv6':True})
        self.controls(ipv6_filter=True,ipv6_allow=['allow.example'],adblock=True,filter_urls=[url])
        self.run_adg()
        self.assertEqual((self.base/'run/state/adguardhome.pid').read_text(),pid)
        self.assertFalse(self.api('dns_info')['disable_ipv6'])
        self.assertEqual(struct.unpack('!H',self.query('other.example',28)[6:8])[0],0)
        self.assertEqual(struct.unpack('!H',self.query('sub.allow.example',28)[6:8])[0],1)
        self.assertTrue(self.query('ads.shortcut.test').endswith(b'\0\0\0\0'))
        self.controls(adblock=False);self.run_adg()
        self.assertTrue(self.query('ads.shortcut.test').endswith(socket.inet_aton('203.0.113.7')))
        self.assertEqual(struct.unpack('!H',self.query('other.example',28)[6:8])[0],0)
        self.controls(ipv6_filter=False,adblock=True);self.run_adg()
        self.assertEqual(struct.unpack('!H',self.query('other.example',28)[6:8])[0],1)
        self.assertTrue(self.query('ads.shortcut.test').endswith(b'\0\0\0\0'))
        self.assertIn('||keep.user.test^',self.api('filtering/status')['user_rules'])
        self.assertEqual((self.base/'run/state/adguardhome.pid').read_text(),pid)
        # Removing a URL disables its list instead of deleting its cached data.
        self.controls(adblock=False,filter_urls=[]);self.run_adg()
        self.assertFalse(next(x for x in self.api('filtering/status')['filters'] if x['url']==url)['enabled'])

    def test_shortcut_comments_disable_entries_without_losing_editor_content(self):
        url=self.filter_server()+'/list'
        self.run_adg();pid=(self.base/'run/state/adguardhome.pid').read_text()
        self.controls(ipv6_filter=True,ipv6_allow=['# keep comment','ALLOW.EXAMPLE','  # disabled.example'],
                      adblock=True,filter_urls=['# rules',url,'  # '+url+'/disabled'])
        self.run_adg()
        self.assertEqual(struct.unpack('!H',self.query('sub.allow.example',28)[6:8])[0],1)
        self.assertEqual(struct.unpack('!H',self.query('disabled.example',28)[6:8])[0],0)
        self.assertTrue(self.query('ads.shortcut.test').endswith(b'\0\0\0\0'))
        self.assertFalse(any(x['url'].endswith('/disabled') for x in self.api('filtering/status')['filters']))
        self.controls(ipv6_allow=['# ALLOW.EXAMPLE'],filter_urls=['# '+url])
        self.run_adg()
        self.assertEqual(struct.unpack('!H',self.query('sub.allow.example',28)[6:8])[0],0)
        self.assertTrue(self.query('ads.shortcut.test').endswith(socket.inet_aton('203.0.113.7')))
        self.assertFalse(next(x for x in self.api('filtering/status')['filters'] if x['url']==url)['enabled'])
        saved=json.loads((self.base/'manage/preferences.json').read_text())['adg_controls']
        self.assertEqual(saved['ipv6_allow'],['# ALLOW.EXAMPLE'])
        self.assertEqual(saved['filter_urls'],['# '+url])
        self.assertEqual((self.base/'run/state/adguardhome.pid').read_text(),pid)

    def test_shortcut_failure_restores_filters_rules_and_ipv6_state(self):
        url=self.filter_server();self.run_adg()
        self.api('filtering/set_rules',{'rules':['||keep.user.test^']})
        before=self.api('filtering/status');dns=self.api('dns_info')
        self.controls(ipv6_filter=True,ipv6_allow=['allow.example'],adblock=True,filter_urls=[url+'/good',url+'/fail'])
        result=self.run_adg(check=False);self.assertNotEqual(result.returncode,0)
        after=self.api('filtering/status')
        self.assertEqual(after['user_rules'],before['user_rules'])
        self.assertEqual([(x['url'],x['enabled']) for x in after['filters']],[(x['url'],x['enabled']) for x in before['filters']])
        self.assertEqual(self.api('dns_info')['disable_ipv6'],dns['disable_ipv6'])
        self.assertFalse((self.base/'run/state/adg-controls.applied').exists())

    def test_missing_nat6_uses_bridge_and_disable_removes_rules(self):
        (self.base/'no-nat6').touch();self.run_adg()
        self.assertEqual((self.base/'run/state/adguardhome.capture').read_text().strip(),'dual-tproxy')
        db=json.loads((self.base/'firewall.json').read_text());self.assertEqual(len(db['ip6tables:mangle:OUTPUT']),2);self.assertEqual(db['ip6tables:filter:OUTPUT'],[])
        (self.base/'disabled').touch();self.run_adg()
        db=json.loads((self.base/'firewall.json').read_text());self.assertEqual(db['iptables:nat:OUTPUT'],[]);self.assertEqual(db['ip6tables:filter:OUTPUT'],[]);self.assertEqual(db['ip6tables:mangle:OUTPUT'],[])
        self.assertFalse((self.base/'run/state/adguardhome-bridge.pid').exists())
        self.assertFalse((self.base/'run/state/adguardhome.pid').exists())

    def test_live_core_dns_timeout_never_falls_back(self):
        import signal
        self.run_adg()
        p=self.spawn('mihomo',self.core,'198.18.0.7');(self.base/'run/box.pid').write_text(str(p.pid))
        self.run_adg();self.api('dns_config',{'upstream_timeout':1})
        p.send_signal(signal.SIGSTOP)
        try:
            answer=self.query('timeout.example')
            self.assertEqual(answer[3]&15,2)  # SERVFAIL, not system's real IP.
            self.run_adg()
            self.assertEqual(self.api('dns_info')['upstream_dns'],[f'127.0.0.1:{self.core}'])
            self.assertEqual(self.api('dns_info')['fallback_dns'],[])
        finally:p.send_signal(signal.SIGCONT)

    def test_operation_lock_does_not_change_upstream_or_capture(self):
        (self.base/'manage/operation.lock').mkdir()
        self.assertEqual(self.run_adg(check=False).returncode,75)
        self.assertFalse((self.base/'firewall.json').exists())

    def test_status_reads_live_upstream_and_aaaa_filter_not_transport_guard(self):
        self.assertEqual(self.status()['aaaa_filter'],'unknown')
        self.run_adg()
        # Stale applied state must not override the live API.
        (self.base/'run/state/adguardhome.upstream').write_text('mihomo|99999\n')
        actual=self.status();self.assertEqual(actual['upstream'],'system');self.assertEqual(actual['aaaa_filter'],'disabled')
        self.assertEqual(actual['capture'],'dual-tproxy')
        self.api('filtering/set_rules',{'rules':['$dnstype=AAAA,denyallow=example.com|example.net,dnsrewrite=NOERROR;;']})
        self.assertEqual(self.status()['aaaa_filter'],'enabled')
        self.api('dns_config',{'upstream_dns':[f'127.0.0.1:{self.core}']})
        self.assertEqual(self.status()['upstream'],'mihomo')
        self.api('filtering/set_rules',{'rules':[]})
        self.assertEqual(self.status()['aaaa_filter'],'disabled')

    def test_network_change_clears_cache_even_with_same_local_mihomo_upstream(self):
        p=self.spawn('mihomo',self.core,'198.18.0.7');(self.base/'run/box.pid').write_text(str(p.pid))
        self.run_adg();self.api('dns_config',{'cache_enabled':True})
        pid=(self.base/'run/state/adguardhome.pid').read_text()
        self.assertTrue(self.query().endswith(socket.inet_aton('198.18.0.7')))
        (self.base/'bin/mihomo.answer').write_text('198.18.0.8')
        self.assertTrue(self.query().endswith(socket.inet_aton('198.18.0.7')))  # Cached.
        (self.base/'network-id').write_text('2\n')
        self.run_adg()
        self.assertTrue(self.query().endswith(socket.inet_aton('198.18.0.8')))
        self.assertEqual((self.base/'run/state/adguardhome.pid').read_text(),pid)

class AdGuardHomeDefaultsTest(unittest.TestCase):
    @unittest.skipUnless(YQ,'requires yq')
    def test_public_defaults_and_runtime_override_restore(self):
        template=ROOT/'box/templates/AdGuardHome.yaml'
        data=json.loads(subprocess.check_output([YQ,'-o=json','.',str(template)],text=True))
        self.assertFalse(data['dns']['cache_enabled']);self.assertFalse(data['filters'][0]['enabled'])
        self.assertEqual(data['dns']['cache_size'],1048576)
        self.assertEqual((data['dns']['cache_ttl_min'],data['dns']['cache_ttl_max']),(600,3600))
        self.assertTrue(data['statistics']['enabled'])
        self.assertTrue(data['querylog']['enabled'])
        self.assertEqual(data['querylog']['interval'],'24h')
        self.assertEqual(data['dns']['fallback_dns'],[])
        self.assertTrue(all(rule.startswith('! ') for rule in data['user_rules']))
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'runtime.yaml';p.write_text('dns: {enable: true}\ntun: {dns-hijack: [any:53]}\n')
            command=f'''. "{ROOT}/box/scripts/ports.utils"
. "{ROOT}/box/scripts/network.utils"
bin_dir="{d}"
adguardhome_enabled=true
dns_hijack_setting=on
mfr_dns_override "{p}" "{p}"
'''
            (Path(d)/'yq').symlink_to(YQ)
            subprocess.run(['bash','-c',command],check=True)
            actual=json.loads(subprocess.check_output([YQ,'-o=json','.',str(p)],text=True))
            self.assertEqual(actual['dns']['listen'],'127.0.0.1:15353');self.assertEqual(actual['tun']['dns-hijack'],[])
            subprocess.run(['bash','-c',command.replace('adguardhome_enabled=true','adguardhome_enabled=false')],check=True)
            actual=json.loads(subprocess.check_output([YQ,'-o=json','.',str(p)],text=True))
            self.assertEqual(actual['tun']['dns-hijack'],['any:53','tcp://any:53'])
