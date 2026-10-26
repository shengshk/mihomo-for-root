"""Real FIFO/timed-read checks with a controlled replacement for ip monitor."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
EVENTS = ROOT/'box/scripts/network.events'


class NetworkEventsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-events-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base/'bin').mkdir()
        self.env = {**os.environ, 'PATH': str(self.base/'bin')+':'+os.environ['PATH']}

    def ip(self, content):
        file = self.base/'bin/ip'
        file.write_text(content)
        file.chmod(0o700)

    def run_script(self, script):
        return subprocess.run(['bash', '-c', f'''
set -e
box_run_state="{self.base}"
. "{EVENTS}"
trap mfr_events_close EXIT
{script}
'''], env=self.env, text=True, capture_output=True, timeout=8, check=True).stdout

    def test_event_wakes_long_wait_merges_burst_and_cleans_child(self):
        self.ip('''#!/usr/bin/python3
import sys,time
assert sys.argv[1:] == ['monitor','link','address','route']
time.sleep(.1)
print('link changed\\n'*20, flush=True)
time.sleep(30)
''')
        start = time.monotonic()
        output = self.run_script('''
mfr_events_open test
child=$events_pid
mfr_events_wait 60
if mfr_events_wait 0.1; then echo 'burst was not drained' >&2; exit 1; fi
mfr_events_close
! kill -0 "$child" 2>/dev/null
[ ! -e "$events_fifo" ]
echo passed
''')
        self.assertEqual(output.strip(), 'passed')
        self.assertLess(time.monotonic()-start, 4)

    def test_failed_monitor_keeps_timed_fallback_and_can_restart(self):
        self.ip('#!/bin/sh\nexit 1\n')
        start = time.monotonic()
        self.run_script('''
mfr_events_open test
if mfr_events_wait 0.1; then exit 1; fi
mfr_events_ensure
if mfr_events_wait 0.1; then exit 1; fi
''')
        self.assertLess(time.monotonic()-start, 2)

    def test_legacy_fast_poll_values_use_60_second_fallback(self):
        result = self.run_script('''
for network_dns_interval in 15 5 invalid 0 301; do mfr_network_interval; done
network_dns_interval=120
mfr_network_interval
''')
        self.assertEqual(result.splitlines(), ['60']*5+['120'])
