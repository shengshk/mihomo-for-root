"""Capture and DNS choices must survive saves, subscriptions and UID selection."""
import json
import shutil
import subprocess
import unittest
import urllib.error
from pathlib import Path
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq/BusyBox')
class OverridesTest(unittest.TestCase):
    def setUp(self):
        self.fx = ManagerFixture()
        self.fx.call('status')

    def tearDown(self):
        self.fx.close()

    def save(self, **options):
        values = dict(routing_mode='rule', tun_mode='follow', dns_mode='follow',
                      ipv6_mode='follow', dns_hijack_mode='on', adguardhome_enabled=False,
                      wifi_pause_enabled=False, wifi_pause_ssids=[], append_network_dns=False,
                      app_mode='exclude', include_apps=[], exclude_apps=['com.example.installed'])
        values.update(options)
        return self.fx.call('settings-save', values)

    def default_filters(self):
        return json.loads(subprocess.check_output([YQ,'-o=json','.dns."fake-ip-filter"',str(self.fx.base/'templates/default.yaml')]))

    def runtime(self):
        return json.loads(subprocess.check_output([YQ, '-o=json', '.', str(self.fx.base/'mihomo/.box-runtime.yaml')]))

    def test_tun_dns_follow_and_fixed_ranges_without_source_changes(self):
        source = self.fx.base/'mihomo/config.yaml'
        source.write_text('tun:\n  enable: false\ndns:\n  enhanced-mode: redir-host\n  fake-ip-range: 198.19.0.1/16\n')
        before = source.read_bytes()
        self.save()
        self.assertFalse(self.runtime()['tun']['enable'])
        self.assertEqual(self.runtime()['dns']['enhanced-mode'], 'redir-host')
        self.save(tun_mode='on', dns_mode='fake-ip')
        runtime = self.runtime()
        self.assertTrue(runtime['tun']['enable'])
        self.assertEqual(runtime['dns']['fake-ip-range'], '198.19.0.1/16')
        self.assertEqual(runtime['dns']['fake-ip-range6'], '2001:2::1/64')
        source.write_text('tun:\n  enable: true\ndns:\n  enhanced-mode: fake-ip\n  fake-ip-range6: fd12:3456::1/64\n')
        self.save(tun_mode='off', dns_mode='redir-host')
        self.assertFalse(self.runtime()['tun']['enable'])
        self.assertEqual(self.runtime()['dns']['enhanced-mode'], 'redir-host')
        self.save(dns_mode='fake-ip', ipv6_mode='off')
        self.assertEqual(self.runtime()['dns']['fake-ip-range'], '198.18.0.1/16')
        self.assertEqual(self.runtime()['dns']['fake-ip-range6'], 'fd12:3456::1/64')
        self.assertFalse(self.runtime()['dns']['ipv6'])
        source.write_bytes(before)
        self.save(tun_mode='off', dns_mode='fake-ip')
        self.assertEqual(source.read_bytes(), before)
        cmd=f'. "{self.fx.base}/settings.ini"; mfr_tun_resolve "{self.fx.base}/mihomo/.box-runtime.yaml"; echo "$network_mode"'
        self.assertEqual(subprocess.check_output(['bash','-c',cmd],env=self.fx.env,text=True).strip(),'tproxy')
        self.save(tun_mode='on')
        self.assertEqual(subprocess.check_output(['bash','-c',cmd],env=self.fx.env,text=True).strip(),'tun')

    def test_legacy_save_preserves_choices_and_invalid_values_fail(self):
        self.save(tun_mode='off', dns_mode='redir-host')
        prefs=self.fx.base/'manage/preferences.json'
        values=json.loads(prefs.read_text())
        del values['tun_mode'];del values['dns_mode']
        self.fx.call('settings-save', values)
        self.assertEqual(json.loads(prefs.read_text())['tun_mode'], 'off')
        self.assertEqual(json.loads(prefs.read_text())['dns_mode'], 'redir-host')
        before=prefs.read_bytes()
        for value in ({'tun_mode':'invalid'}, {'dns_mode':'invalid'}):
            with self.assertRaises(urllib.error.HTTPError):self.save(**value)
            self.assertEqual(prefs.read_bytes(),before)
        state=self.fx.call('status')
        self.assertEqual(state['summary'],'已停止 · 规则 · TProxy · Redir-Host · IPv6 开 · 系统 DNS')

    def test_shared_summary_uses_observed_agh_and_effective_config(self):
        self.save(tun_mode='on', dns_mode='fake-ip', ipv6_mode='off')
        agh=self.fx.base/'run/observed-agh.json'
        for upstream,label in [('mihomo','AGH'),('system','AGH'),('unknown','AGH')]:
            agh.write_text(json.dumps(dict(running=True,upstream=upstream)))
            cmd=f'. "{self.fx.base}/settings.ini"; . "$scripts_dir/status.utils"; adguardhome_enabled=true; mfr_status_line "{self.fx.base}/mihomo/.box-runtime.yaml" paused global "{agh}"'
            value=subprocess.check_output(['bash','-c',cmd],text=True,env=self.fx.env).strip()
            self.assertEqual(value,'已暂停 · 全局 · TUN · Fake-IP · IPv6 关 · '+label)

    def test_cn_filter_respects_modes_and_explicit_rules(self):
        source=self.fx.base/'mihomo/config.yaml'
        cases=[
            ({}, self.default_filters()+['geosite:cn']),
            ({'fake-ip-filter':['*.example']}, ['*.example','geosite:cn']),
            ({'fake-ip-filter':['geosite:cn','*.example']}, ['geosite:cn','*.example']),
            ({'fake-ip-filter-mode':'rule','fake-ip-filter':['MATCH,fake-ip']}, ['GEOSITE,cn,real-ip','MATCH,fake-ip']),
            ({'fake-ip-filter-mode':'rule','fake-ip-filter':['GEOSITE,cn,fake-ip','MATCH,real-ip']}, ['GEOSITE,cn,fake-ip','MATCH,real-ip']),
            ({'fake-ip-filter-mode':'whitelist','fake-ip-filter':['geosite:gfw']}, ['geosite:gfw']),
            ({'enhanced-mode':'redir-host','fake-ip-filter':['*.example']}, ['*.example']),
        ]
        for dns,expected in cases:
            with self.subTest(dns=dns):
                source.write_text(json.dumps({'dns':dns}))
                before=source.read_bytes()
                self.save()
                subprocess.run(['bash',str(self.fx.base/'scripts/box.service'),'prepare'],env=self.fx.env,check=True,capture_output=True)
                self.assertEqual(self.runtime()['dns']['fake-ip-filter'],expected)
                self.assertEqual(source.read_bytes(),before)

    def test_expanded_template_respects_user_lists_false_and_empty_ranges(self):
        import ipaddress
        source=self.fx.base/'mihomo/config.yaml'
        def expand(value):
            source.write_text(json.dumps(value));before=source.read_bytes()
            subprocess.run(['bash',str(self.fx.base/'scripts/box.service'),'prepare'],env=self.fx.env,check=True,capture_output=True)
            self.assertEqual(source.read_bytes(),before)
            return self.runtime()
        default=expand({'proxies':[{'name':'node','type':'direct'}]})
        self.assertTrue(default['sniffer']['enable'])
        self.assertTrue(default['unified-delay']);self.assertTrue(default['tcp-concurrent'])
        self.assertEqual(default['geo-update-interval'],72)
        self.assertEqual(default['geodata-loader'],'memconservative')
        self.assertEqual(default['proxy-groups'][0]['proxies'],['DIRECT','node'])
        ranges=[ipaddress.ip_network(default['dns'][key],strict=False) for key in ('fake-ip-range','fake-ip-range6')]
        for block in default['tun']['route-exclude-address']:
            excluded=ipaddress.ip_network(block,strict=False)
            self.assertFalse(any(excluded.version==net.version and excluded.overlaps(net) for net in ranges))
        self.assertIn(ipaddress.ip_interface(default['tun']['inet6-address'][0]).ip,ranges[1])
        for exclusions in ([],['10.0.0.0/8','fc00::/7']):
            custom=expand({'tun':{'route-exclude-address':exclusions,'inet6-address':[]},
                'sniffer':{'enable':False},'ipv6':False,'unified-delay':False,
                'dns':{'fake-ip-range6':'','fake-ip-filter':[]}})
            self.assertEqual(custom['tun']['route-exclude-address'],exclusions)
            self.assertEqual(custom['tun']['inet6-address'],[])
            self.assertEqual(custom['dns']['fake-ip-range6'],'')
            self.assertEqual(custom['dns']['fake-ip-filter'],['geosite:cn']) # Agreed CN exception.
            self.assertFalse(custom['sniffer']['enable']);self.assertFalse(custom['ipv6'])
            self.assertFalse(custom['unified-delay'])
