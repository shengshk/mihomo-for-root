"""Help entry changes only the saved AGH switch and rolls back on failure."""
import json
import shutil
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires yq and BusyBox')
class AdgEnableTest(unittest.TestCase):
    def setUp(self):
        self.fx = ManagerFixture()
        self.addCleanup(self.fx.close)
        state = self.fx.call('status')
        saved = {**state['preferences'], 'include_apps':['com.future.keep'],
                 'adg_controls':state['adg_controls']}
        self.fx.call('settings-save', saved)
        self.pref = self.fx.base/'manage/preferences.json'
        self.db = self.fx.base/'manage/profiles.json'
        self.before = json.loads(self.pref.read_text())
        self.db_before = self.db.read_bytes()
        self.fx.write('scripts/box.adg', f'''#!/bin/bash
printf 'sync\\n' >> "{self.fx.base}/adg-calls"
[ ! -f "{self.fx.base}/fail-enable" ] || [ "$("{YQ}" -r '.adguardhome_enabled' "{self.pref}")" != true ]
''')

    def test_enable_ignores_drafts_and_preserves_profiles(self):
        self.fx.call('adg-enable', {'routing_mode':'global', 'exclude_apps':['com.bad.draft'],
                                  'adg_reset_defaults':True, 'dns_override':{'nameserver':['1.1.1.1']}})
        self.assertEqual(json.loads(self.pref.read_text()), {**self.before,'adguardhome_enabled':True})
        self.assertEqual(self.db.read_bytes(), self.db_before)

    def test_manual_enable_clears_circuit_notice(self):
        notice=self.fx.base/'manage/adguardhome-disabled'
        notice.write_text('AGH 连续切换失败，已停用；可在帮助中重新启用。')
        self.assertIn('已停用',self.fx.call('status')['adguardhome']['error'])
        self.fx.call('adg-enable')
        self.assertFalse(notice.exists())
        self.assertTrue(json.loads(self.pref.read_text())['adguardhome_enabled'])

    def test_already_enabled_does_not_reapply(self):
        self.fx.call('adg-enable')
        calls = (self.fx.base/'adg-calls').read_bytes()
        self.fx.call('adg-enable')
        self.assertEqual((self.fx.base/'adg-calls').read_bytes(), calls)

    def test_failed_enable_restores_saved_preferences_and_profiles(self):
        (self.fx.base/'fail-enable').touch()
        with self.assertRaises(urllib.error.HTTPError):
            self.fx.call('adg-enable')
        self.assertEqual(json.loads(self.pref.read_text()), self.before)
        self.assertEqual(self.db.read_bytes(), self.db_before)


if __name__ == '__main__':
    unittest.main()
