"""Exercise the real Action policy with an isolated core and network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
YQ = os.environ.get('MFR_TEST_YQ') or shutil.which('yq')


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class ModuleActionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-action-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        for name in ('scripts', 'bin', 'manage', 'run/state', 'module'):
            (self.base/name).mkdir(parents=True)
        (self.base/'bin/yq').symlink_to(YQ)
        self.write('settings.ini', f'''export PATH="{self.base}/bin:$PATH"
box_dir="{self.base}"
scripts_dir="$box_dir/scripts"
box_run="$box_dir/run"
box_run_state="$box_run/state"
manage_dir="$box_dir/manage"
preferences_file="$manage_dir/preferences.json"
bin_dir="$box_dir/bin"
box_pid="$box_run/box.pid"
. "$scripts_dir/network.utils"
''')
        for name in ('network.utils', 'apps.utils', 'adg.utils', 'ports.utils', 'box.policy'):
            source = (ROOT/'box/scripts'/name).read_text()
            source = source.replace('/data/adb/modules/box_for_root', str(self.base/'module'))
            source = source.replace('/data/adb/box', str(self.base)).replace('/system/bin/sh', '/bin/bash')
            if name == 'box.policy':
                source = source.replace('trap release EXIT', 'live() { [ -f "$box_dir/core-running" ]; }\ntrap release EXIT')
            self.write('scripts/'+name, source)
        self.write('scripts/box.dns', f'#!/bin/sh\necho "dns $1" >> "{self.base}/operations"\n')
        self.write('scripts/box.iptables', f'#!/bin/sh\necho "iptables $1" >> "{self.base}/operations"\n')
        self.write('scripts/box.service', f'''#!/bin/sh
echo "service $1" >> "{self.base}/operations"
case "$1" in
 restart) touch "{self.base}/core-running" ;;
 stop) rm -f "{self.base}/core-running" ;;
esac
''')
        self.write('bin/cmd', f'''#!/bin/sh
[ ! -f "{self.base}/wifi-error" ] || exit 1
cat "{self.base}/wifi-status"
''')
        (self.base/'manage/preferences.json').write_text(json.dumps({
            'wifi_pause_enabled': True, 'wifi_pause_ssids': ['Home WiFi']}))
        self.wifi('Other WiFi')

    def write(self, name, content):
        file = self.base/name
        file.write_text(content)
        file.chmod(0o700)

    def wifi(self, name):
        (self.base/'wifi-status').write_text(
            f'Wifi is connected to "{name}"\nWifiInfo: Supplicant state: COMPLETED\n'
            if name else 'Wifi is disabled\n')

    def toggle(self):
        return subprocess.run(['bash', str(self.base/'scripts/box.policy'), 'toggle'],
                              text=True, capture_output=True)

    def test_matching_wifi_leaves_intent_pause_and_core_untouched(self):
        self.wifi('Home WiFi')
        for running, wanted, paused in ((False, 'running', True), (True, 'running', False), (False, 'stopped', False)):
            with self.subTest(running=running, wanted=wanted, paused=paused):
                marker = self.base/'core-running'
                if running: marker.touch()
                else: marker.unlink(missing_ok=True)
                intent = self.base/'manage/service-intent'
                intent.write_text(wanted+'\n')
                pause = self.base/'run/state/wifi-paused'
                if paused: pause.write_text('Home WiFi\n')
                else: pause.unlink(missing_ok=True)
                result = self.toggle()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), '当前 Wi-Fi 下暂停代理')
                self.assertEqual(intent.read_text(), wanted+'\n')
                self.assertEqual(pause.exists(), paused)
                self.assertEqual(marker.exists(), running)
                self.assertFalse((self.base/'operations').exists())

    def test_other_network_toggles_and_persists_manual_intent(self):
        for wifi in ('Other WiFi', ''):
            self.wifi(wifi)
            start = self.toggle()
            self.assertEqual(start.returncode, 0, start.stderr)
            self.assertEqual(start.stdout.strip(), '已启动')
            self.assertEqual((self.base/'manage/service-intent').read_text(), 'running\n')
            stop = self.toggle()
            self.assertEqual(stop.returncode, 0, stop.stderr)
            self.assertEqual(stop.stdout.strip(), '已停止')
            self.assertEqual((self.base/'manage/service-intent').read_text(), 'stopped\n')
            self.assertFalse((self.base/'core-running').exists())

    def test_stale_pause_does_not_block_after_leaving_wifi(self):
        (self.base/'run/state/wifi-paused').write_text('Home WiFi\n')
        result = self.toggle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '已启动')
        self.assertFalse((self.base/'run/state/wifi-paused').exists())

    def test_unreadable_network_does_not_change_intent(self):
        (self.base/'wifi-error').touch()
        (self.base/'manage/service-intent').write_text('stopped\n')
        result = self.toggle()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual((self.base/'manage/service-intent').read_text(), 'stopped\n')
        self.assertFalse((self.base/'operations').exists())

    def test_stable_wifi_policy_does_not_take_lock_or_cycle_dns(self):
        source = (self.base/'scripts/box.policy').read_text().split('trap release EXIT')[0]
        self.write('scripts/policy-functions', source)
        self.wifi('Home WiFi')
        (self.base/'manage/service-intent').write_text('running\n')
        (self.base/'run/state/wifi-paused').write_text('Home WiFi\n')
        command = f'''
set -e
. "{self.base}/scripts/policy-functions"
if policy_pending 'Home WiFi'; then acquire; reconcile; release; fi
[ ! -d "$manage_dir/operation.lock" ]
[ ! -f "$box_dir/operations" ]
'''
        subprocess.run(['bash', '-c', command], capture_output=True, text=True, check=True)
