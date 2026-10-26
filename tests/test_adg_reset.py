"""Focused recovery checks; the full suite is intentionally not required here."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ

@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires yq/BusyBox')
class AdgResetManagerTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture();self.before=self.fx.call('status')
        (self.fx.base/'adguardhome').mkdir()
        self.config=self.fx.base/'adguardhome/AdGuardHome.yaml'
        self.config.write_text('dns:\n  cache_enabled: true\nusers: []\nuser_rules: ["||private.example^"]\n')
        self.fx.write('bin/AdGuardHome','#!/bin/sh\nexit 0\n')
        self.fx.write('scripts/box.adg',f'''#!/bin/bash
if [ "$1" = replace-config ]; then
 cp "$2" "{self.config}" || exit 1
 echo replace >> "{self.fx.base}/adg-calls"
 [ ! -f "{self.fx.base}/fail-reset" ] || [ "$MFR_ADG_RESTORE" = 1 ] || exit 1
fi
''')
    def tearDown(self):self.fx.close()
    def payload(self):
        return {**self.before['preferences'],'adg_controls':self.before['adg_defaults'],'adg_reset_defaults':True}
    def test_defaults_are_read_only_and_save_backs_up_whole_config(self):
        old=self.config.read_bytes();pref=(self.fx.base/'manage/preferences.json').read_bytes()
        state=self.fx.call('status')
        self.assertFalse(state['adg_defaults']['ipv6_filter']);self.assertFalse(state['adg_defaults']['adblock'])
        self.assertEqual(self.config.read_bytes(),old);self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),pref)
        self.fx.call('settings-save',self.payload())
        self.assertEqual(self.config.read_bytes(),(self.fx.base/'templates/AdGuardHome.yaml').read_bytes())
        backup=list((self.fx.base/'manage/backups').glob('adguardhome-reset.*/AdGuardHome.yaml'));self.assertEqual(len(backup),1);self.assertEqual(backup[0].read_bytes(),old)
        saved=json.loads((self.fx.base/'manage/preferences.json').read_text());self.assertFalse(saved['adguardhome_enabled']);self.assertNotIn('adg_reset_defaults',saved)
        (self.fx.base/'adg-calls').unlink();self.fx.call('settings-save',{**saved,'adg_reset_defaults':False});self.assertFalse((self.fx.base/'adg-calls').exists())
    def test_failed_reset_restores_config_preferences_and_owned_urls(self):
        old=self.config.read_bytes();pref=(self.fx.base/'manage/preferences.json').read_bytes();owned=self.fx.base/'manage/adg-owned-urls.json';owned.write_text('["https://old.example/filter"]')
        (self.fx.base/'fail-reset').touch()
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('settings-save',self.payload())
        self.assertEqual(self.config.read_bytes(),old);self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),pref)
        self.assertEqual(json.loads(owned.read_text()),['https://old.example/filter'])
