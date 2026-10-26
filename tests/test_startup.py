"""Delayed real UDP listener verifies startup ordering without Android routing."""
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('busybox'), 'requires BusyBox')
class StartupReadinessTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-startup-')
        self.base = Path(self.tmp.name)
        for name in ('bin', 'scripts', 'run', 'mihomo'):
            (self.base/name).mkdir()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0)); self.port = sock.getsockname()[1]
        self.write('bin/busybox', '#!/bin/sh\nif [ "$1" = setuidgid ]; then shift 2; exec "$@"; fi\nexec /usr/bin/busybox "$@"\n')
        self.write('bin/mihomo', '''#!/usr/bin/env python3
import os,socket,time,sys
time.sleep(float(os.environ.get('MFR_FAKE_DELAY','3')))
if os.environ.get('MFR_FAKE_EXIT'):sys.exit(1)
if os.environ.get('MFR_FAKE_BIND_ERROR'):
 print('Start DNS server(UDP) error: bind: address already in use',file=sys.stderr,flush=True)
 time.sleep(60);sys.exit(1)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(('127.0.0.1',int(os.environ['MFR_FAKE_PORT'])))
time.sleep(60)
''')
        self.write('scripts/ports.utils',(ROOT/'box/scripts/ports.utils').read_text().replace('mfr_dns_port=15353',f'mfr_dns_port={self.port}'))
        utils=(ROOT/'box/scripts/adg.utils').read_text()
        self.write('scripts/adg.utils', utils)
        service=(ROOT/'box/scripts/box.service').read_text()
        self.write('functions', '\n'.join(re.search(r'^'+name+r'\(\) \{.*?^\}',service,re.M|re.S).group() for name in ('wait_mihomo_dns','startup_adg_step','box_run_bin')))
        self.write('vars', f'''export PATH="{self.base}/bin:$PATH"
box_dir="{self.base}"
scripts_dir="$box_dir/scripts"
box_run="$box_dir/run"
box_run_state="$box_run"
box_pid="$box_dir/run/box.pid"
bin_path="$box_dir/bin/mihomo"
box_dns_runtime="$box_dir/mihomo/runtime.yaml"
bin_log="$box_dir/run/mihomo.log"
box_user_group=0:0
adguardhome_enabled=true
. "$scripts_dir/adg.utils"
''')
        self.write('scripts/box.adg', f'''#!/bin/bash
. "{self.base}/vars"
if [ "$1" = before-stop ]; then echo system >> "$box_dir/events"; exit 0; fi
adg_dns_ready || {{ echo early-switch >> "$box_dir/events"; exit 1; }}
echo mihomo >> "$box_dir/events"
''')
        self.write('scripts/box.dns', f'#!/bin/sh\necho watcher >> "{self.base}/events"\n')
        self.env={**os.environ,'MFR_FAKE_PORT':str(self.port)}

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, value):
        path=self.base/name;path.write_text(value);path.chmod(0o700)

    def command(self, body='box_run_bin'):
        return f'''. "{self.base}/vars"
. "{self.base}/functions"
log() {{ printf '%s\\n' "$*" >> "$box_dir/errors"; }}
prepare_mihomo_runtime() {{ echo prepared >> "$box_dir/events"; }}
commit_network_dns_state() {{ echo committed >> "$box_dir/events"; }}
trap 'if [ -n "$PID" ]; then kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; fi' EXIT
{body}
result=$?
exit "$result"
'''

    def events(self):
        path=self.base/'events'
        return path.read_text().splitlines() if path.exists() else []

    def test_slow_initialization_keeps_system_dns_until_real_listener_ready(self):
        start=time.monotonic()
        proc=subprocess.Popen(['bash','-c',self.command()],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            for _ in range(100):
                if (self.base/'run/box.pid').exists(): break
                time.sleep(.02)
            time.sleep(1.2)
            self.assertEqual(self.events(), ['prepared','system'])
            self.assertIsNone(proc.poll())
            stdout,stderr=proc.communicate(timeout=8)
            self.assertEqual(proc.returncode,0,stdout+stderr)
            self.assertGreaterEqual(time.monotonic()-start,3)
            self.assertEqual(self.events(),['prepared','system','mihomo','committed','watcher'])
        finally:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=3)

    def test_core_exit_never_switches_agh_or_commits_startup(self):
        env={**self.env,'MFR_FAKE_DELAY':'.1','MFR_FAKE_EXIT':'1'}
        proc=subprocess.run(['bash','-c',self.command()],env=env,capture_output=True,text=True,timeout=5)
        self.assertNotEqual(proc.returncode,0)
        self.assertEqual(self.events(),['prepared','system'])
        self.assertIn('启动期间退出',(self.base/'errors').read_text())

    def retry_script(self, phase='sync', failures=1, kill_core=False):
        self.env['MFR_FAKE_DELAY']='.1'
        self.write('scripts/box.adg', f'''#!/bin/bash
. "{self.base}/vars"
if [ "$1" = "{phase}" ]; then
  count=$(cat "$box_dir/attempts" 2>/dev/null || echo 0)
  count=$((count+1)); echo "$count" > "$box_dir/attempts"
  echo "attempt:$1:$(cat "$box_pid" 2>/dev/null)" >> "$box_dir/events"
  if [ "$count" -le {failures} ]; then
    {'kill "$(cat "$box_pid")"' if kill_core else ':'}
    exit 75
  fi
fi
if [ "$1" = before-stop ]; then echo system >> "$box_dir/events"; exit 0; fi
adg_dns_ready || exit 1
echo mihomo >> "$box_dir/events"
''')

    def test_transient_agh_failure_retries_same_core_without_preparation(self):
        self.retry_script(failures=1)
        result=subprocess.run(['bash','-c',self.command()],env=self.env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        events=self.events()
        self.assertEqual(events.count('prepared'),1)
        attempts=[x for x in events if x.startswith('attempt:')]
        self.assertEqual(len(attempts),2)
        self.assertEqual(attempts[0],attempts[1])  # Same live core PID.
        self.assertEqual(events[-3:],['mihomo','committed','watcher'])
        diagnostic=(self.base/'run/adguardhome-events.log')
        self.assertIn('exit=75',diagnostic.read_text())
        self.assertIn('recovered attempt=2',diagnostic.read_text())
        self.assertEqual(diagnostic.stat().st_mode & 0o777,0o600)

    def test_prelaunch_failure_retries_before_creating_core(self):
        self.retry_script(phase='before-stop',failures=1)
        result=subprocess.run(['bash','-c',self.command()],env=self.env,capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(self.events()[:4],['prepared','attempt:before-stop:','attempt:before-stop:','system'])

    def test_persistent_failure_is_bounded_and_does_not_commit(self):
        self.retry_script(failures=100)
        result=subprocess.run(['bash','-c',self.command()],env=self.env,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.base/'attempts').read_text().strip(),'3')
        self.assertEqual(self.events().count('prepared'),1)
        self.assertNotIn('committed',self.events())
        self.assertNotIn('watcher',self.events())

    def test_core_death_aborts_retry(self):
        self.retry_script(failures=100,kill_core=True)
        result=subprocess.run(['bash','-c',self.command()],env=self.env,capture_output=True,text=True,timeout=10)
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.base/'attempts').read_text().strip(),'1')
        self.assertNotIn('committed',self.events())
        self.assertIn('core exited',(self.base/'run/adguardhome-events.log').read_text())

    def test_bind_failure_reports_owner_without_waiting_twenty_seconds(self):
        self.write('bin/ss',f'''#!/bin/sh
printf '%s\\n' 'udp UNCONN 0 0 *:{self.port} *:* users:(("com.other.vpn",pid=999999999,fd=3))'
''')
        start=time.monotonic()
        result=subprocess.run(['bash','-c',self.command()],env={**self.env,'MFR_FAKE_DELAY':'.1','MFR_FAKE_BIND_ERROR':'1'},capture_output=True,text=True,timeout=5)
        self.assertNotEqual(result.returncode,0)
        self.assertLess(time.monotonic()-start,4)
        errors=(self.base/'errors').read_text()
        self.assertIn(f'DNS 端口 {self.port} 被占用',errors)
        self.assertIn('com.other.vpn',errors)
        self.assertNotIn('committed',self.events())
        self.assertNotIn('mihomo',self.events())

    def test_wait_has_a_deadline_and_never_changes_upstream(self):
        body='nohup "$bin_path" >/dev/null 2>&1 &\nPID=$!\nprintf "%s" "$PID" > "$box_pid"\nwait_mihomo_dns "$PID" 1'
        start=time.monotonic()
        proc=subprocess.run(['bash','-c',self.command(body)],env={**self.env,'MFR_FAKE_DELAY':'60'},capture_output=True,text=True,timeout=5)
        self.assertNotEqual(proc.returncode,0)
        self.assertLess(time.monotonic()-start,4)
        self.assertEqual(self.events(),[])
        self.assertIn('超时',(self.base/'errors').read_text())

if __name__ == '__main__':
    unittest.main()
