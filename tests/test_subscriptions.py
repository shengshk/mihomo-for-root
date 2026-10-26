"""Subscription edits, cron validation and the refresh callback; no host DNS changes."""
import json
import os
import shutil
import subprocess
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class SubscriptionTest(unittest.TestCase):
    def setUp(self):
        self.fx = ManagerFixture()
        self.fx.call('status')
        self.fx.write('remote.yaml', 'proxies:\n  - {name: Example, type: socks5, server: 127.0.0.1, port: 1080}\n')
        self.fx.write('bin/curl', f'''#!/bin/sh
cat >/dev/null
[ ! -f {self.fx.base}/download-fail ] || exit 1
while [ "$#" -gt 0 ]; do
 case "$1" in --output) shift; output="$1" ;; esac
 shift
done
cp {self.fx.base}/remote.yaml "$output"
''')

    def tearDown(self):
        self.fx.close()

    def profile(self, ident):
        return next(p for p in self.fx.call('status')['configs']['profiles'] if p['id'] == ident)

    def add(self):
        return self.fx.call('profile-add', {'name':'Example', 'url':'https://example.invalid/config.yaml'})['id']

    def cron_support(self):
        # The host BusyBox lacks crond. Model availability, never a clock or daemon.
        self.fx.write('bin/busybox', '''#!/bin/sh
if [ "$1" = crond ] && [ "$2" = --help ]; then exit 0; fi
exec /usr/bin/busybox "$@"
''')

    def test_new_subscription_defaults_to_no_schedule_and_edit_preserves_config(self):
        ident = self.add()
        self.assertEqual(self.profile(ident)['cron'], '')
        self.assertFalse((self.fx.base/'run/state/subscription-cron.pid').exists())
        path = self.fx.base/f'manage/profiles/{ident}.yaml'
        before = path.read_bytes()
        self.fx.call('profile-edit', {'id':ident,'name':'Renamed','url':'https://example.invalid/config.yaml','cron':''})
        self.assertEqual(self.profile(ident)['name'], 'Renamed')
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_cron_and_failed_link_edit_preserve_original(self):
        ident = self.add()
        db = self.fx.base/'manage/profiles.json'
        before = db.read_bytes()
        for expression in ['60 2 * * *', '10 24 * * *', '* * * * *\necho bad', '10 2 * * *; true', '*/0 * * * *']:
            with self.assertRaises(urllib.error.HTTPError):
                self.fx.call('profile-edit', {'id':ident,'name':'Changed','url':'https://example.invalid/config.yaml','cron':expression})
            self.assertEqual(db.read_bytes(), before)
        (self.fx.base/'download-fail').touch()
        with self.assertRaises(urllib.error.HTTPError):
            self.fx.call('profile-edit', {'id':ident,'name':'Changed','url':'https://example.invalid/new.yaml','cron':''})
        self.assertEqual(db.read_bytes(), before)

    def test_schedule_table_update_removal_and_refresh_recheck(self):
        ident = self.add()
        self.cron_support()
        cron_dir = self.fx.base/'manage/cron'
        cron_dir.mkdir(exist_ok=True)
        # A named stand-in only keeps sync from launching a host daemon.
        sleeper = subprocess.Popen(['bash','-c',f'exec -a "crond {cron_dir}" sleep 30'])
        pidfile = self.fx.base/'run/state/subscription-cron.pid'
        pidfile.write_text(str(sleeper.pid))
        try:
            self.fx.call('profile-edit', {'id':ident,'name':'Scheduled','url':'https://example.invalid/config.yaml','cron':'10 2 * * *'})
            table = (cron_dir/'root').read_text()
            self.assertIn('10 2 * * *', table)
            self.assertIn('box.cron refresh '+ident, table)
            self.assertNotIn('https://', table)
            # The job must ignore inherited HTTP request files and use its own id.
            env = {**self.fx.env,'MFR_REQUEST_FILE':'/nonexistent/stale-http-request'}
            subprocess.run(['bash',str(self.fx.base/'scripts/box.cron'),'refresh',ident],env=env,check=True)
            self.assertTrue(self.profile(ident)['updated'])
            self.fx.call('profile-edit', {'id':ident,'name':'Scheduled','url':'https://example.invalid/config.yaml','cron':''})
            sleeper.wait(timeout=3)
            self.assertFalse(pidfile.exists())
            self.assertFalse((cron_dir/'root').exists())
            (self.fx.base/'download-fail').touch()
            subprocess.run(['bash',str(self.fx.base/'scripts/box.cron'),'refresh',ident],env=env,check=True)
        finally:
            if sleeper.poll() is None:
                sleeper.terminate(); sleeper.wait(timeout=3)

    def test_cron_numeric_ranges_lists_steps_and_injection(self):
        script = str(self.fx.base/'scripts/cron.utils')
        for value in ['10 2 * * *','*/15 0-23/2 * 1,6,12 0-6','0 0 1 * 0']:
            subprocess.run(['bash','-c','. "$1"; mfr_cron_valid "$2"','check',script,value],check=True)
        for value in ['', '* * * *', '1, 2 * * *', '* * 0 * *', '* * * 13 *', '* * * * 7', '0 0 31-1 * *','* * * * *\n', '* * * * *\ntrue']:
            result=subprocess.run(['bash','-c','. "$1"; mfr_cron_valid "$2"','check',script,value])
            self.assertNotEqual(result.returncode,0,value)

if __name__ == '__main__':
    unittest.main()
