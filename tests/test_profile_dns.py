"""Per-profile DNS overrides, subscription refresh and transactional failures."""
import base64
import json
import shutil
import subprocess
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class ProfileDnsTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture()
        self.fx.write('scripts/box.service', f'''#!/bin/bash
. {self.fx.base}/settings.ini
. {self.fx.base}/scripts/profile.utils
source="$mihomo_config"; output="$box_dir/mihomo/.box-runtime.yaml"
if [ "$1" = validate ]; then source="$2"; output="$box_run/check.yaml"; fi
mfr_expand_config "$source" "$output" || exit 1
# A failing core check exercises the manager rollback; this is not a real core.
! grep -q 'invalid-dns-test' "$output"
''')
        self.fx.call('status')

    def tearDown(self): self.fx.close()
    def state(self): return self.fx.call('status')
    def save(self, override, ident=None):
        state=self.state()
        return self.fx.call('settings-save',dict(state['preferences'],dns_profile_id=ident or state['configs']['active'],dns_override=override))
    def runtime(self):
        return json.loads(subprocess.check_output([YQ,'-o=json','.dns',str(self.fx.base/'mihomo/.box-runtime.yaml')],text=True))
    def source(self, dns):
        p=self.fx.base/'mihomo/config.yaml'
        p.write_text(json.dumps({'dns':dns,'proxies':[{'name':'A','type':'direct'}]}))
        (self.fx.base/'manage/profiles/current.yaml').write_bytes(p.read_bytes())
        return p.read_bytes()
    def add(self,name,dns):
        token=self.fx.call('upload-start')['token']
        data=json.dumps({'proxies':[{'name':'A','type':'direct'}],'dns':dns})
        self.fx.call('upload-chunk',{'token':token,'chunk':base64.b64encode(data.encode()).decode()})
        return self.fx.call('profile-add',{'token':token,'name':name})['id']

    def test_defaults_aliases_and_network_append_separation(self):
        self.source({})
        state=self.state()
        self.assertEqual(state['dns']['base']['default-nameserver'],['223.5.5.5','119.29.29.29'])
        self.assertEqual(len(state['dns']['base']['nameserver']),2)
        self.assertEqual(state['dns']['base']['fallback'],[])
        self.assertNotIn('10.0.0.1',state['dns']['effective']['nameserver'])
        p=self.fx.base/'mihomo/config.yaml'
        p.write_text('defaults: &dns\n  nameserver: [9.9.9.9]\n  default-nameserver: [8.8.8.8]\ndns:\n  <<: *dns\n')
        self.assertEqual(self.state()['dns']['base']['nameserver'],['9.9.9.9'])

    def test_follow_modes_report_source_presence_without_losing_false_or_aliases(self):
        p=self.fx.base/'mihomo/config.yaml'
        cases=[
            ('proxies: [{name: A, type: direct}]\n', (True,'fake-ip',True), (False,False,False)),
            ('tun: {enable: false}\ndns: {enhanced-mode: redir-host}\nipv6: false\n', (False,'redir-host',False), (True,True,True)),
            ('tun: {stack: system}\ndns: {ipv6: false}\n', (True,'fake-ip',True), (False,False,False)),
            ('t: &t {enable: false}\nd: &d {enhanced-mode: redir-host}\nv: &v {ipv6: false}\ntun: {<<: *t}\ndns: {<<: *d}\n<<: *v\n', (False,'redir-host',False), (True,True,True)),
            ('tun: {enable: true}\n', (True,'fake-ip',True), (True,False,False)),
        ]
        for source,values,presence in cases:
            with self.subTest(source=source):
                p.write_text(source)
                before=p.read_bytes()
                base=self.state()['mihomo_base']
                self.assertEqual(tuple(base[k] for k in ('tun','dns_mode','ipv6')),values)
                self.assertEqual(tuple(base['configured'][k] for k in ('tun','dns_mode','ipv6')),presence)
                self.assertEqual(p.read_bytes(),before)

    def test_save_empty_fallback_restore_and_old_client(self):
        original=self.source({'nameserver':['9.9.9.9'],'fallback':['1.0.0.1'],'default-nameserver':['8.8.8.8']})
        override={'nameserver':['1.1.1.1'],'fallback':[]}
        self.save(override)
        self.assertEqual(self.state()['dns']['override'],override)
        self.assertEqual(self.runtime()['nameserver'],['1.1.1.1'])
        self.assertEqual(self.runtime()['fallback'],[])
        self.assertEqual((self.fx.base/'mihomo/config.yaml').read_bytes(),original)
        self.fx.call('settings-save',self.state()['preferences'])  # Older client.
        self.assertEqual(self.state()['dns']['override'],override)
        self.save({})
        self.assertEqual(self.runtime()['nameserver'],['9.9.9.9'])
        self.assertEqual(self.runtime()['fallback'],['1.0.0.1'])

    def test_profile_switch_refresh_preserves_only_manual_fields(self):
        self.source({'nameserver':['9.9.9.9'],'default-nameserver':['8.8.8.8']})
        self.save({'nameserver':['1.1.1.1']})
        other=self.add('Other',{'nameserver':['8.8.4.4']})
        self.fx.call('profile-activate',{'id':other})
        self.assertEqual(self.runtime()['nameserver'],['8.8.4.4'])
        self.save({'fallback':['1.0.0.1']})
        self.fx.call('profile-activate',{'id':'current'})
        self.assertEqual(self.runtime()['nameserver'],['1.1.1.1'])
        # Convert this fixture profile to a subscription and supply its new YAML.
        database=self.fx.base/'manage/profiles.json';db=json.loads(database.read_text());db['profiles'][0]['url']='https://example.invalid/sub.yaml';database.write_text(json.dumps(db))
        self.fx.write('bin/curl','''#!/bin/sh
cat >/dev/null
while [ "$#" -gt 0 ]; do case "$1" in --output) shift; output="$1" ;; esac; shift; done
printf 'proxies: [{name: A, type: direct}]\ndns:\n  nameserver: [4.4.4.4]\n  default-nameserver: [223.6.6.6]\n' > "$output"
''')
        self.fx.call('profile-update',{'id':'current'})
        state=self.state()
        self.assertEqual(state['dns']['base']['nameserver'],['4.4.4.4'])
        self.assertEqual(state['dns']['effective']['nameserver'],['1.1.1.1'])
        self.assertEqual(self.runtime()['default-nameserver'],['223.6.6.6'])
        self.fx.call('profile-activate',{'id':other})
        self.assertEqual(self.runtime()['fallback'],['1.0.0.1'])

    def test_rejects_bad_payload_stale_profile_and_restores_failed_check(self):
        self.save({'nameserver':['1.1.1.1']})
        paths=[self.fx.base/'manage/profiles.json',self.fx.base/'manage/preferences.json',self.fx.base/'mihomo/config.yaml']
        before=[p.read_bytes() for p in paths]
        for override in ({'nameserver':[]},{'default-nameserver':[]},{'fallback':'invalid'}, {'other':[]}, {'nameserver':['x\ny']}):
            with self.assertRaises(urllib.error.HTTPError):self.save(override)
            self.assertEqual([p.read_bytes() for p in paths],before)
        with self.assertRaises(urllib.error.HTTPError):self.save({},ident='stale')
        with self.assertRaises(urllib.error.HTTPError):self.save({'nameserver':['invalid-dns-test']})
        self.assertEqual([p.read_bytes() for p in paths],before)
        self.assertEqual(self.runtime()['nameserver'],['1.1.1.1'])

    def test_failed_activation_restores_active_profile_and_dns(self):
        self.save({'nameserver':['1.1.1.1']})
        other=self.add('Other',{'nameserver':['8.8.4.4']})
        database=self.fx.base/'manage/profiles.json';db=json.loads(database.read_text());db['profiles'][-1]['dns_override']={'nameserver':['invalid-dns-test']};database.write_text(json.dumps(db))
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('profile-activate',{'id':other})
        self.assertEqual(self.state()['configs']['active'],'current')
        self.assertEqual(self.runtime()['nameserver'],['1.1.1.1'])
        # Validation passes, but applying the new active profile fails later.
        db=json.loads(database.read_text());db['profiles'][-1]['dns_override']={};database.write_text(json.dumps(db))
        service=self.fx.base/'scripts/box.service'
        service.write_text(service.read_text()+f'\nif [ "$1" = prepare ] && [ "$("$bin_dir/yq" -r .active "$manage_dir/profiles.json")" = "{other}" ]; then exit 1; fi\n')
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('profile-activate',{'id':other})
        self.assertEqual(self.state()['configs']['active'],'current')
        self.assertEqual(self.runtime()['nameserver'],['1.1.1.1'])

if __name__=='__main__':unittest.main()
