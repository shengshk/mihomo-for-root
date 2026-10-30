"""Only loopback DNS is used. Exercise UDP/TCP, all backends and live policy reload."""
import hashlib,json,os,shutil,socket,struct,subprocess,tempfile,threading,time,unittest
from pathlib import Path

GATE=os.environ.get('MFR_TEST_DNS_GATE')

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

def query(name,kind=28):
    return struct.pack('!HHHHHH',1234,0x100,1,0,0,0)+b''.join(bytes([len(x)])+x.encode() for x in name.split('.'))+b'\0'+struct.pack('!HH',kind,1)

def readall(s,n):
    b=b''
    while len(b)<n:
        v=s.recv(n-len(b))
        if not v:raise EOFError()
        b+=v
    return b

@unittest.skipUnless(GATE,'set MFR_TEST_DNS_GATE to a host binary')
class DNSGateTest(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(prefix='mfr-dns-gate-');self.base=Path(self.tmp.name)
        self.up,self.listen=port(),port();self.hits=0;self.stop=threading.Event()
        self.udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);self.udp.bind(('127.0.0.1',self.up));self.udp.settimeout(.1)
        self.tcp=socket.socket();self.tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);self.tcp.bind(('127.0.0.1',self.up));self.tcp.listen();self.tcp.settimeout(.1)
        def answer(q):
            self.hits+=1;k=struct.unpack('!H',q[-4:-2])[0]
            data=socket.inet_pton(socket.AF_INET6,'2001:db8::7') if k==28 else socket.inet_aton('203.0.113.7')
            return q[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+q[12:]+struct.pack('!HHHLH',0xc00c,k,1,120,len(data))+data
        def udp():
            while not self.stop.is_set():
                try:q,p=self.udp.recvfrom(65535);self.udp.sendto(answer(q),p)
                except socket.timeout:pass
                except OSError:return
        def tcp():
            while not self.stop.is_set():
                try:c,_=self.tcp.accept()
                except socket.timeout:continue
                except OSError:return
                with c:
                    c.settimeout(1)
                    try:
                        q=readall(c,struct.unpack('!H',readall(c,2))[0]);a=answer(q);c.sendall(struct.pack('!H',len(a))+a)
                    except (EOFError,OSError):pass
        self.threads=[threading.Thread(target=udp),threading.Thread(target=tcp)]
        for t in self.threads:t.start()
        self.process=None;self.configure('on','system')
        self.process=subprocess.Popen([GATE,'-config',str(self.base/'config.json'),'-listen4',f'127.0.0.1:{self.listen}','-ready-file',str(self.base/'pid'),'-state-file',str(self.base/'state.json')],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        self.wait_state();self.addCleanup(self.close)
    def close(self):
        if self.process:self.process.terminate();self.process.wait(timeout=7)
        self.stop.set();self.udp.close();self.tcp.close()
        for t in self.threads:t.join(timeout=1)
        self.tmp.cleanup()
    def configure(self,mode,backend,black=None,white=None):
        data=json.dumps(dict(mode=mode,backend=backend,upstreams=[f'127.0.0.1:{self.up}'],blacklist=black or [],whitelist=white or [],network='fixture'))
        (self.base/'next').write_text(data);os.replace(self.base/'next',self.base/'config.json')
        self.digest=hashlib.sha256(data.encode()).hexdigest()
        if self.process:self.process.send_signal(__import__('signal').SIGHUP);self.wait_state()
    def wait_state(self):
        for _ in range(100):
            try:
                if json.loads((self.base/'state.json').read_text())['digest']==self.digest:return
            except (OSError,ValueError):pass
            time.sleep(.02)
        self.fail('daemon did not apply config')
    def ask(self,name,kind=28,tcp=False):
        q=query(name,kind)
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
            s.settimeout(2);s.connect(('127.0.0.1',self.listen))
            if tcp:s.sendall(struct.pack('!H',len(q))+q);a=readall(s,struct.unpack('!H',readall(s,2))[0])
            else:s.send(q);a=s.recv(65535)
        self.assertEqual(a[:2],q[:2]);self.assertEqual(a[3]&15,0)
        return struct.unpack('!H',a[6:8])[0]
    def test_modes_reload_and_domain_boundaries_for_three_backends(self):
        for backend in ('system','agh','mihomo'):
            for tcp in (False,True):
                with self.subTest(backend=backend,tcp=tcp):
                    self.configure('on',backend);self.assertEqual(self.ask('example.com',tcp=tcp),1)
                    self.configure('off',backend);before=self.hits
                    self.assertEqual(self.ask('example.com',tcp=tcp),0);self.assertEqual(self.hits,before)
                    self.assertEqual(self.ask('example.com',kind=1,tcp=tcp),1)
                    self.configure('blacklist',backend,black=['# kept',' Example.COM '])
                    self.assertEqual(self.ask('sub.example.com',tcp=tcp),0)
                    self.assertEqual(self.ask('otherexample.com',tcp=tcp),1)
                    self.configure('whitelist',backend,white=['# kept','example.com'])
                    self.assertEqual(self.ask('sub.example.com',tcp=tcp),1)
                    self.assertEqual(self.ask('otherexample.com',tcp=tcp),0)
    def test_invalid_reload_keeps_applied_policy(self):
        self.configure('off','system')
        (self.base/'config.json').write_text('{broken')
        self.process.send_signal(__import__('signal').SIGHUP);time.sleep(.1)
        self.assertEqual(self.ask('example.com'),0)
        self.assertEqual(json.loads((self.base/'state.json').read_text())['digest'],self.digest)
    def test_malformed_compression_is_bounded(self):
        malformed=struct.pack('!HHHHHH',1234,0x100,1,0,0,0)+b'\xc0\x0c\0\x1c\0\x01'
        with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
            s.settimeout(1);s.sendto(malformed,('127.0.0.1',self.listen));a=s.recv(1024)
        self.assertEqual(a[3]&15,1)

class CarrierInventoryTest(unittest.TestCase):
    def test_network_inventory_keeps_dual_sim_and_shared_default_services(self):
        root=Path(__file__).resolve().parents[1]
        text="""Active default network: 101
NetworkAgentInfo{network{101} LinkProperties: {InterfaceName: wlan0 LinkAddresses: [ 192.0.2.18/24 ] DnsAddresses: [ /10.0.0.1 ]} nc{Capabilities: INTERNET&TRUSTED}}
NetworkAgentInfo{network{102} LinkProperties: {InterfaceName: rmnet_data1 LinkAddresses: [ 2001:db8::2/64 ] DnsAddresses: [ /fe80::a ]} nc{Capabilities: IMS&TRUSTED}}
    NetworkRequest [ REQUEST id=9, [ Capabilities: INTERNET&TRUSTED ] ]
NetworkAgentInfo{network{103} LinkProperties: {InterfaceName: rmnet_data2 LinkAddresses: [ 2001:db8::3/64 ] DnsAddresses: [ /fe80::b ]} nc{Capabilities: MMS&TRUSTED}}
NetworkAgentInfo{network{104} LinkProperties: {InterfaceName: rmnet_data0 LinkAddresses: [ 10.1.0.2/30 ] DnsAddresses: [ /10.1.0.1 ]} nc{Capabilities: SUPL&INTERNET}}
2026/10 old NetworkAgentInfo{network{105} InterfaceName: rmnet_old DnsAddresses: [ /1.2.3.4 ]}
"""
        result=subprocess.run(['bash','-c',f'. "{root}/box/scripts/dns-gate.utils";gate_networks'],input=text,text=True,capture_output=True,check=True)
        value=json.loads(result.stdout);self.assertEqual(value['default_network'],101)
        self.assertEqual([n['id'] for n in value['networks'] if n['protected']],[102,103])
        self.assertEqual(value['networks'][1]['dns'],['fe80::a%rmnet_data1'])
        self.assertEqual(value['networks'][1]['addresses'],['2001:db8::2'])
        self.assertEqual(len(value['networks']),4)

if __name__=='__main__':unittest.main()
