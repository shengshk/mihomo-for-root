"""Private fallback templates: candidate validation, precedence and rollback."""
import json
import os
import shutil
import subprocess
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ

@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires yq/BusyBox')
class AdvancedDefaultsTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture();self.fx.call('status')
        self.fx.write('scripts/box.service',f'''#!/bin/bash
. {self.fx.base}/settings.ini
. "$scripts_dir/profile.utils"
source="$mihomo_config"; output="$box_dir/mihomo/.box-runtime.yaml"
if [ "$1" = validate ]; then source="$2"; output="$box_run/check.yaml"; fi
mfr_expand_config "$source" "$output" || exit 1
! grep -q invalid-default-check "$output" || exit 1
[ "$1" != prepare ] || [ ! -f "$box_dir/fail-prepare" ]
''')
        self.source({'proxies':[{'name':'A','type':'direct'}]})

    def tearDown(self):self.fx.close()
    def source(self,value):
        text=json.dumps(value)
        (self.fx.base/'mihomo/config.yaml').write_text(text)
        (self.fx.base/'manage/profiles/current.yaml').write_text(text)
    def read(self):return self.fx.call('defaults-get')
    def save(self,yaml,revision=None):return self.fx.call('defaults-save',{'yaml':yaml,'revision':revision or self.read()['revision']})
    def parsed(self,text):
        return json.loads(subprocess.check_output([YQ,'-o=json','.', '-'],input=text.encode()))
    def runtime(self):return self.parsed((self.fx.base/'mihomo/.box-runtime.yaml').read_text())

    def test_comments_custom_defaults_user_precedence_and_restore(self):
        before=self.read();self.assertFalse(before['custom'])
        prefs=(self.fx.base/'manage/preferences.json').read_bytes();source=(self.fx.base/'mihomo/config.yaml').read_bytes()
        document=self.parsed(before['yaml']);document['tun']['enable']=False
        document['dns']['enhanced-mode']='redir-host';document['dns']['nameserver']=['1.1.1.1'];document['dns']['fallback']=['9.9.9.9'];document['ipv6']=False
        document['tun']['dns-hijack']=[]
        document['rules']=['DOMAIN-SUFFIX,example.com,DIRECT','MATCH,PROXY']
        document['proxy-groups'][0]['proxies']=['DIRECT','REJECT']
        text='# retained comment\n'+json.dumps(document,indent=2)+'\n'
        after=self.save(text)
        self.assertTrue(after['custom']);self.assertEqual(after['yaml'],text)
        custom=self.fx.base/'manage/defaults.yaml';self.assertEqual(custom.stat().st_mode & 0o777,0o600)
        state=self.fx.call('status');self.assertTrue(state['defaults_custom'])
        self.assertFalse(state['mihomo_base']['tun']);self.assertFalse(state['mihomo_base']['ipv6'])
        self.assertEqual(state['mihomo_base']['dns_mode'],'redir-host')
        self.assertEqual(state['dns']['base']['fallback'],['9.9.9.9'])
        self.assertFalse(self.runtime()['tun']['enable'])
        self.assertEqual(self.runtime()['rules'],document['rules'])
        self.assertEqual(self.runtime()['proxy-groups'][0]['proxies'],['DIRECT','REJECT','A'])
        # Runtime fallback readers use the same private template.
        command=f'. "{self.fx.base}/settings.ini"; mfr_tun_resolve "$mihomo_config"; printf "%s\\n" "$network_mode"; mfr_dns_yaml "$mihomo_config"'
        lines=subprocess.check_output(['bash','-c',command],env=self.fx.env,text=True,stderr=subprocess.DEVNULL).splitlines()
        self.assertEqual(lines,['tproxy',str(custom)])
        self.assertEqual((self.fx.base/'mihomo/config.yaml').read_bytes(),source)
        self.assertEqual((self.fx.base/'manage/preferences.json').read_bytes(),prefs)
        # Explicit values/lists in source beat custom fallback defaults.
        self.source({'proxies':[{'name':'A','type':'direct'}],'tun':{'enable':True,'route-exclude-address':[]},
                     'dns':{'enhanced-mode':'fake-ip','fallback':[]},'ipv6':True})
        subprocess.run(['bash',str(self.fx.base/'scripts/box.service'),'prepare'],env=self.fx.env,check=True)
        self.assertTrue(self.runtime()['tun']['enable']);self.assertTrue(self.runtime()['ipv6'])
        self.assertEqual(self.runtime()['tun']['route-exclude-address'],[])
        self.assertEqual(self.runtime()['dns']['fallback'],[])
        restored=self.fx.call('defaults-restore',{'revision':after['revision']})
        self.assertFalse(restored['custom']);self.assertEqual(restored['yaml'],before['yaml']);self.assertFalse(custom.exists())

    def test_bad_yaml_stale_large_input_and_apply_failure_preserve_state(self):
        before=self.read();self.save(before['yaml']+'# customized\n')
        custom=self.fx.base/'manage/defaults.yaml';old=custom.read_bytes()
        runtime=(self.fx.base/'mihomo/.box-runtime.yaml').read_bytes()
        for bad in ('dns: [', '[]','null','a: 1\n---\nb: 2\n',before['yaml']+'\ninvalid: invalid-default-check\n', '#'+('x'*262144)):
            with self.assertRaises(urllib.error.HTTPError):self.save(bad)
            self.assertEqual(custom.read_bytes(),old);self.assertEqual((self.fx.base/'mihomo/.box-runtime.yaml').read_bytes(),runtime)
        with self.assertRaises(urllib.error.HTTPError):self.save(before['yaml'],before['revision'])
        (self.fx.base/'fail-prepare').touch()
        with self.assertRaises(urllib.error.HTTPError):self.save(before['yaml']+'# valid candidate\n')
        self.assertEqual(custom.read_bytes(),old);self.assertEqual((self.fx.base/'mihomo/.box-runtime.yaml').read_bytes(),runtime)
        with self.assertRaises(urllib.error.HTTPError):self.fx.call('defaults-restore',{'revision':self.read()['revision']})
        self.assertEqual(custom.read_bytes(),old)

    def test_alias_template_large_roundtrip_and_factory_upgrade_preserves_private(self):
        before=self.read();base=self.parsed(before['yaml']);base.pop('sniffer',None)
        source=self.fx.base/'alias-input.yaml'
        source.write_text('defaults: &sniff\n  enable: false\nsniffer:\n  <<: *sniff\n')
        rest=self.fx.base/'base-input.json';rest.write_text(json.dumps(base))
        env={**os.environ,'MFR_REST':str(rest)}
        text=subprocess.check_output([YQ,'. * load(strenv(MFR_REST))',str(source)],env=env,text=True)
        text += '# Large editor roundtrip\n'+('# comment: '+'x'*100+'\n')*1100
        after=self.save(text);self.assertEqual(after['yaml'],text)
        self.assertFalse(self.runtime()['sniffer']['enable'])
        factory=self.fx.base/'templates/default.yaml';factory.write_text(factory.read_text()+'# upgraded factory\n')
        self.assertEqual(self.read()['yaml'],text)
        self.assertEqual(self.read()['revision'],after['revision'])
