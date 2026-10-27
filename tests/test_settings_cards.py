"""Card writes merge saved state under the manager lock, not page-wide drafts."""
import json
import shutil
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires yq/BusyBox')
class SettingsCardsTest(unittest.TestCase):
    def setUp(self):
        self.fx = ManagerFixture()
        self.before = self.fx.call('status')

    def tearDown(self):
        self.fx.close()

    def saved(self):
        return json.loads((self.fx.base/'manage/preferences.json').read_text())

    def test_card_updates_preserve_latest_saved_values_and_profile_dns(self):
        self.fx.call('settings-save', {'section':'wifi','wifi_pause_enabled':True,'wifi_pause_ssids':['Saved WiFi']})
        self.fx.call('settings-save', {'section':'apps','app_mode':'exclude','include_apps':[],'exclude_apps':['com.future.app']})
        state=self.fx.call('status')
        self.fx.call('settings-save', {'section':'mihomo','ipv6_mode':'off','dns_profile_id':state['configs']['active'],
            'dns_override':{'nameserver':['https://resolver.example/dns-query']}})
        self.fx.call('settings-save', {'section':'routing','routing_mode':'global'})
        self.fx.call('settings-save', {'section':'agh','adguardhome_enabled':True,'adg_controls':state['adg_defaults']})
        saved=self.saved()
        self.assertEqual(saved['wifi_pause_ssids'],['Saved WiFi'])
        self.assertTrue(saved['wifi_pause_enabled'])
        self.assertEqual(saved['exclude_apps'],['com.future.app'])
        self.assertEqual(saved['ipv6_mode'],'off')
        self.assertEqual(saved['routing_mode'],'global')
        self.assertTrue(saved['adguardhome_enabled'])
        self.assertNotIn('section',saved)
        self.assertNotIn('adg_reset_defaults',saved)
        self.assertEqual(self.fx.call('status')['dns']['override']['nameserver'],['https://resolver.example/dns-query'])

    def test_cross_card_and_invalid_requests_leave_saved_settings_unchanged(self):
        prefs=(self.fx.base/'manage/preferences.json').read_bytes()
        profiles=(self.fx.base/'manage/profiles.json').read_bytes()
        for payload in ({'section':'wifi','routing_mode':'global'},
                        {'section':'apps','dns_override':{}},
                        {'section':'mihomo','adg_reset_defaults':True},
                        {'section':'unknown'},
                        {'section':'wifi','wifi_pause_enabled':True,'wifi_pause_ssids':[]}):
            with self.subTest(payload=payload):
                with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',payload)
                self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),prefs)
                self.assertEqual((self.fx.base/'manage/profiles.json').read_bytes(),profiles)
