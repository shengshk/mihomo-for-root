"""Exercise the real Action policy with an isolated core and network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
YQ = os.environ.get('MFR_TEST_YQ') or shutil.which('yq')


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class ModuleActionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-action-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        for name in ('scripts', 'bin', 'manage', 'run/state', 'module', 'mihomo'):
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
mihomo_config="$box_dir/mihomo/config.yaml"
. "$scripts_dir/network.utils"
''')
        for name in ('network.utils', 'apps.utils', 'adg.utils', 'ports.utils', 'dns.utils', 'status.utils', 'box.policy'):
            source = (ROOT/'box/scripts'/name).read_text()
            source = source.replace('/data/adb/modules/box_for_root', str(self.base/'module'))
            source = source.replace('/data/adb/box', str(self.base)).replace('/system/bin/sh', '/bin/bash')
            if name == 'box.policy':
                source = source.replace('trap release EXIT', 'live() { [ -f "$box_dir/core-running" ]; }\nadg_core_alive() { live; }\ntrap release EXIT')
            self.write('scripts/'+name, source)
        self.write('scripts/box.dns', f'#!/bin/sh\necho "dns $1" >> "{self.base}/operations"\n')
        self.write('scripts/box.iptables', f'#!/bin/sh\necho "iptables $1" >> "{self.base}/operations"\n')
        self.write('scripts/box.service', f'''#!/bin/sh
echo "service $1" >> "{self.base}/operations"
case "$1" in
 start) touch "{self.base}/core-running" ;;
 stop) rm -f "{self.base}/core-running" ;;
esac
''')
        self.write('bin/cmd', f'''#!/bin/sh
[ ! -f "{self.base}/wifi-error" ] || exit 1
cat "{self.base}/wifi-status"
''')
        (self.base/'manage/preferences.json').write_text(json.dumps({
            'wifi_pause_enabled': True, 'wifi_pause_ssids': ['Home WiFi']}))
        (self.base/'module/module.prop').write_text('description=idle\n')
        (self.base/'mihomo/config.yaml').write_text('mode: rule\nipv6: true\ntun: {enable: true}\ndns: {enhanced-mode: fake-ip}\n')
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

    def test_matching_wifi_toggles_intent_without_starting_core(self):
        for running, wanted, paused in ((False, 'running', True), (True, 'running', False), (False, 'stopped', False)):
            with self.subTest(running=running, wanted=wanted, paused=paused):
                self.wifi('Home WiFi')
                marker = self.base/'core-running'
                if running: marker.touch()
                else: marker.unlink(missing_ok=True)
                intent = self.base/'manage/service-intent'
                intent.write_text(wanted+'\n')
                pause = self.base/'run/state/wifi-paused'
                if paused: pause.write_text('Home WiFi\n')
                else: pause.unlink(missing_ok=True)
                operations = self.base/'operations'
                operations.unlink(missing_ok=True)
                result = self.toggle()
                self.assertEqual(result.returncode, 0, result.stderr)
                expected = 'stopped' if wanted == 'running' else 'running'
                self.assertEqual(intent.read_text(), expected+'\n')
                self.assertEqual(result.stdout.strip().splitlines()[-1], '停止完成' if expected == 'stopped' else '已暂停，离开指定 Wi-Fi 后恢复。')
                self.assertEqual(pause.exists(), expected == 'running')
                self.assertFalse(marker.exists())
                self.assertNotIn('service start', operations.read_text())
                # Leaving Wi-Fi resumes only when the toggled intent is running.
                self.wifi('Other WiFi')
                result = subprocess.run(['bash', str(self.base/'scripts/box.policy'), 'reconcile'],
                                        text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(marker.exists(), expected == 'running')
                self.assertEqual(intent.read_text(), expected+'\n')
                self.assertFalse(pause.exists())

    def test_other_network_toggles_and_persists_manual_intent(self):
        for wifi in ('Other WiFi', ''):
            self.wifi(wifi)
            start = self.toggle()
            self.assertEqual(start.returncode, 0, start.stderr)
            self.assertEqual(start.stdout.strip().splitlines()[-1], '启动完成')
            self.assertEqual((self.base/'manage/service-intent').read_text(), 'running\n')
            stop = self.toggle()
            self.assertEqual(stop.returncode, 0, stop.stderr)
            self.assertEqual(stop.stdout.strip().splitlines()[-1], '停止完成')
            self.assertEqual((self.base/'manage/service-intent').read_text(), 'stopped\n')
            self.assertFalse((self.base/'core-running').exists())

    def test_stale_pause_does_not_block_after_leaving_wifi(self):
        (self.base/'run/state/wifi-paused').write_text('Home WiFi\n')
        result = self.toggle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip().splitlines()[-1], '启动完成')
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

    def test_transition_blocks_duplicate_and_streams_only_stage_messages(self):
        helper = self.base/'scripts/box.service'
        source = helper.read_text()
        source = source.replace('case "$1" in', f'''if [ "$1" = start ]; then
 touch "{self.base}/entered"
 while [ ! -f "{self.base}/continue" ]; do sleep .05; done
 echo PRIVATE_LOG_ONLY
 printf '阶段进度已输出\\n' >&3
fi
case "$1" in''')
        self.write('scripts/box.service', source)
        child = subprocess.Popen(['bash', str(self.base/'scripts/box.policy'), 'toggle'],
                                 text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            for _ in range(100):
                if (self.base/'entered').exists(): break
                if child.poll() is not None: self.fail(child.communicate())
                time.sleep(.02)
            self.assertTrue((self.base/'entered').exists())
            self.assertTrue((self.base/'module/module.prop').read_text().startswith('description=启动中'))
            state = subprocess.check_output(['bash','-c',f'. "{self.base}/settings.ini"; . "$scripts_dir/status.utils"; mfr_transition_state'],text=True)
            self.assertEqual(state.strip(),'starting')
            before=(self.base/'manage/service-intent').read_bytes()
            duplicate=self.toggle()
            self.assertNotEqual(duplicate.returncode,0)
            self.assertIn('操作进行中，请勿重复执行',duplicate.stdout)
            self.assertEqual((self.base/'manage/service-intent').read_bytes(),before)
            (self.base/'continue').touch()
            stdout,stderr=child.communicate(timeout=5)
            self.assertEqual(child.returncode,0,stderr)
            self.assertIn('阶段进度已输出',stdout)
            self.assertNotIn('PRIVATE_LOG_ONLY',stdout+stderr)
            self.assertTrue((self.base/'module/module.prop').read_text().startswith('description=运行中'))
            self.assertFalse((self.base/'run/state/service-transition').exists())
            self.assertFalse((self.base/'manage/operation.lock').exists())
        finally:
            (self.base/'continue').touch()
            if child.poll() is None: child.kill(); child.communicate()

    def test_failure_clears_transition_and_lock(self):
        self.write('scripts/box.service', '#!/bin/sh\n[ "$1" != start ]\n')
        result=self.toggle()
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((self.base/'run/state/service-transition').exists())
        self.assertFalse((self.base/'manage/operation.lock').exists())
        self.assertTrue((self.base/'module/module.prop').read_text().startswith('description=启动失败'))
