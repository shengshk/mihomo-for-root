"""Run in unshare -Urn. All addresses, routes and DNS servers are isolated."""
import ipaddress,json,os,signal,socket,struct,subprocess,sys,tempfile,threading,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
parent=os.environ.get('MFR_PARENT_NETNS')
assert parent and os.readlink('/proc/self/ns/net')!=parent,'isolated network namespace required'
GATE=os.environ['MFR_TEST_DNS_GATE'];YQ=os.environ['MFR_TEST_YQ']
def run(*args):subprocess.run(args,check=True,stdout=subprocess.DEVNULL)
run('ip','link','set','lo','up')
for ip in ['10.10.0.2/32','10.10.0.53/32','2001:db8::2/128','2001:db8::53/128']:
 run('ip',*(['-6'] if ':' in ip else []),'addr','add',ip,'dev','lo')
stop=threading.Event();hits={'managed':0,'original':0};sockets=[];threads=[]
def answer(q,name):
 hits[name]+=1;k=struct.unpack('!H',q[-4:-2])[0];last=7 if name=='managed' else 8
 data=socket.inet_pton(socket.AF_INET6,'2001:db8::'+str(last)) if k==28 else socket.inet_aton('203.0.113.'+str(last))
 return q[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+q[12:]+struct.pack('!HHHLH',0xc00c,k,1,60,len(data))+data

def read(s,n):
 out=b''
 while len(out)<n:
  chunk=s.recv(n-len(out))
  if not chunk:raise EOFError()
  out+=chunk
 return out

def serve(address,name):
 af=socket.AF_INET6 if ':' in address[0] else socket.AF_INET
 udp=socket.socket(af,socket.SOCK_DGRAM);udp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);udp.bind(address);udp.settimeout(.1)
 tcp=socket.socket(af,socket.SOCK_STREAM);tcp.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);tcp.bind(address);tcp.listen();tcp.settimeout(.1);sockets.extend([udp,tcp])
 def udploop():
  while not stop.is_set():
   try:q,peer=udp.recvfrom(4096);udp.sendto(answer(q,name),peer)
   except socket.timeout:pass
   except OSError:return
 def tcploop():
  while not stop.is_set():
   try:c,_=tcp.accept()
   except socket.timeout:continue
   except OSError:return
   with c:
    c.settimeout(2)
    try:q=read(c,struct.unpack('!H',read(c,2))[0]);a=answer(q,name);c.sendall(struct.pack('!H',len(a))+a)
    except (OSError,EOFError):pass
 for target in [udploop,tcploop]:
  t=threading.Thread(target=target,daemon=True);t.start();threads.append(t)
serve(('127.0.0.1',11054),'managed');serve(('10.10.0.53',53),'original');serve(('2001:db8::53',53),'original')
def query(host,destination,tcp=False,kind=28,mark=0):
 af=socket.AF_INET6 if ':' in destination[0] else socket.AF_INET
 q=struct.pack('!HHHHHH',0x1234,0x100,1,0,0,0)+b''.join(bytes([len(v)])+v.encode() for v in host.split('.'))+b'\0'+struct.pack('!HH',kind,1)
 with socket.socket(af,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as s:
  s.settimeout(3)
  s.bind(('2001:db8::2' if af==socket.AF_INET6 else '10.10.0.2',0))
  if mark:s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,mark)
  s.connect(destination)
  if tcp:s.sendall(struct.pack('!H',len(q))+q);a=read(s,struct.unpack('!H',read(s,2))[0])
  else:s.send(q);a=s.recv(4096)
 assert a[:2]==q[:2] and a[3]&15==0,(host,destination,tcp,a.hex())
 count=struct.unpack('!H',a[6:8])[0]
 return count,(ipaddress.ip_address(a[-(16 if kind==28 else 4):]) if count else None)

with tempfile.TemporaryDirectory(prefix='mfr-gate-netns-') as directory:
 base=Path(directory);(base/'run/state').mkdir(parents=True)
 carrier=base/'carrier.txt';carrier.write_text('3gppnetwork.org\n')
 config=base/'config.json';state=base/'state.json';pid=base/'pid'
 value=dict(mode='off',china_ipv6=True,geosite=str(ROOT/'assets/geodata/GeoSite.dat'),carrier_file=str(carrier),blacklist=[],whitelist=[],backend='agh',upstreams=['127.0.0.1:11054'],default_network=101,networks=[dict(id=101,interface='lo',dns=['10.0.0.1'],addresses=[]),dict(id=102,interface='lo',dns=['10.10.0.53','2001:db8::53'],addresses=['10.10.0.2','2001:db8::2']),dict(id=103,interface='lo',dns=[],addresses=[],protected=True)])
 config.write_text(json.dumps(value))
 proc=subprocess.Popen([GATE,'-config',str(config),'-listen4','127.0.0.1:15354','-transparent4','127.0.0.1:15355','-transparent6','[::1]:15355','-state-file',str(state),'-ready-file',str(pid)],stderr=subprocess.PIPE)
 try:
  for _ in range(100):
   if pid.exists():break
   if proc.poll() is not None:raise RuntimeError(proc.stderr.read().decode())
   time.sleep(.02)
  assert pid.exists()
  # A user namespace maps a single GID. Match the gate's marked carrier egress
  # in place of the production GID exemption; real kernel TPROXY is unchanged.
  source=(ROOT/'box/scripts/dns-gate-capture.utils').read_text()
  source=source.replace('for n in "$gate_group" 19054 3005;do "$tool" -w 3 -t mangle -A "$out" -m owner --uid-owner 0 --gid-owner "$n" -j ACCEPT || return 1;done', '"$tool" -w 3 -t mangle -A "$out" -m mark --mark 196608/196608 -j ACCEPT || return 1')
  capture=base/'capture.sh';capture.write_text(source)
  script=f'''set -e
box_dir='{base}'
box_run_state='{base}/run/state'
bin_dir=/tmp
. '{ROOT}/box/scripts/ports.utils'
. '{capture}'
gate_state='{state}'
gate_bridge_pid='{base}/not-used'
gate_bridge_alive() {{ return 1; }}
mkdir -p '{base}/bin'
ln -s '{YQ}' '{base}/bin/yq'
bin_dir='{base}/bin'
gate_capture install
'''
  subprocess.run(['bash'],input=script,text=True,check=True,capture_output=True)
  for tcp in [False,True]:
   for target in [('10.10.0.53',53),('2001:db8::53',53)]:
    before=hits.copy();count,ip=query('ims.mnc000.mcc460.3gppnetwork.org',target,tcp)
    assert count==1 and str(ip)=='2001:db8::8' and hits['managed']==before['managed'],('carrier',tcp,target,hits)
    count,ip=query('www.baidu.com',target,tcp)
    assert count==1 and str(ip)=='2001:db8::7',('CN',tcp,target,ip)
    before=hits.copy();assert query('foreign.example',target,tcp)[0]==0 and hits==before,('blocked',tcp,target)
    count,ip=query('foreign.example',target,tcp,kind=1);assert count==1 and str(ip)=='203.0.113.7'
    before=hits.copy();count,ip=query('foreign.example',target,tcp,mark=103|0x10000)
    assert count==1 and str(ip)=='2001:db8::8' and hits['managed']==before['managed'],('private network',tcp,target)
  value['china_ipv6']=False;config.write_text(json.dumps(value));proc.send_signal(signal.SIGHUP)
  for _ in range(100):
   if not json.loads(state.read_text())['china_ipv6']:break
   time.sleep(.01)
  assert query('www.baidu.com',('10.10.0.53',53))[0]==0
  print('PASS isolated kernel: IPv4/IPv6 UDP/TCP original carrier DNS, dedicated network bypass, CN managed upstream, A forwarding, disabled preset')
 finally:
  proc.terminate();proc.wait(timeout=7);proc.stderr.close()
  stop.set()
  for s in sockets:s.close()
  for t in threads:t.join(timeout=1)
