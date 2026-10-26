"""Runtime YAML boundary, capture state, and event retry regressions."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
YQ = os.environ.get('MFR_TEST_YQ') or shutil.which('yq')


def functions(path, names):
    source = path.read_text()
    return '\n'.join(re.search(r'^'+name+r'\(\) \{.*?^\}', source, re.M|re.S).group() for name in names)


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class RuntimeLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-runtime-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base/'bin').mkdir();(self.base/'bin/yq').symlink_to(YQ)
        self.prefix = f'''box_dir={self.base}; bin_dir=$box_dir/bin; box_run_state=$box_dir
manage_dir=$box_dir; preferences_file=$box_dir/preferences.json; mfr_dns_port=15353
log() {{ :; }}
. {ROOT}/box/scripts/config.utils
. {ROOT}/box/scripts/network.utils
'''
        self.config = {'mode':'rule','dns':{'enable':True,'enhanced-mode':'fake-ip',
            'fake-ip-range':'28.0.0.1/8','fake-ip-range6':'2001:2::1/64','listen':'127.0.0.1:15353'},
            'tun':{'enable':True,'device':'Meta','stack':'system','strict-route':False,'auto-redirect':False}}

    def run_shell(self, code):
        return subprocess.run(['bash','-c',self.prefix+code],text=True,capture_output=True,timeout=6)

    def parse(self, config):
        p=self.base/'config.yaml';p.write_text(config if isinstance(config,str) else json.dumps(config))
        return self.run_shell(f'''mfr_config_read {p} || exit $?
printf '%s|%s|%s|%s|%s|%s|%s' "$mihomo_mode" "$mihomo_enhanced_mode" "$fake_ip_range" "$fake_ip6_range" "$mihomo_dns_port" "$tun_device" "$stack"
''')

    def test_block_flow_and_aliases_have_identical_typed_values(self):
        flow=json.dumps(self.config)
        block=subprocess.check_output([YQ,'-P','.'],input=flow,text=True)
        alias='defaults: &dns '+json.dumps(self.config['dns'])+'\ndns: *dns\ntun: '+json.dumps(self.config['tun'])+'\nmode: rule\n'
        results=[self.parse(text) for text in [flow,block,alias]]
        for r in results:self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual({r.stdout for r in results},{'rule|fake-ip|28.0.0.1/8|2001:2::1/64|15353|Meta|system'})

    def test_invalid_rule_addresses_types_and_ports_are_rejected(self):
        for field,value in [('fake-ip-range','{enable:'),('fake-ip-range','example.com/8'),
                            ('fake-ip-range','300.1.1.1/24'),('fake-ip-range','10.0.0.1/33'),
                            ('fake-ip-range6','2001:::1/64'),('fake-ip-range6','2001:2::1/129'),
                            ('fake-ip-range6',[]),('listen','127.0.0.1:99999')]:
            with self.subTest(field=field,value=value):
                config=json.loads(json.dumps(self.config));config['dns'][field]=value
                self.assertNotEqual(self.parse(config).returncode,0)
        config=json.loads(json.dumps(self.config));config['dns']['fake-ip-range6']=''
        self.assertEqual(self.parse(config).returncode,0)
        for value,family in [('::/0',6),('::ffff:192.0.2.1/128',6),('ffff:0:1:2:3:4:5:6/64',6),('0.0.0.0/0',4)]:
            self.assertEqual(self.run_shell(f'mfr_valid_cidr {value} {family}').returncode,0,value)

    def test_prepare_updates_fields_without_text_layout_assumptions(self):
        p=self.base/'config.yaml';p.write_text(json.dumps(self.config))
        (self.base/'uids').write_text('10001\n10002\n')
        funcs=functions(ROOT/'box/scripts/box.service',['tun_should_manage_core_config','prepare_mihomo'])
        result=self.run_shell(f'''{funcs}
mihomo_config={p}; uid_list={self.base}/uids; network_mode=tun; bypass_cn_ip=false
proxy_mode=blacklist;tproxy_port=9898;redir_port=9797
prepare_mihomo
''')
        self.assertEqual(result.returncode,0,result.stderr)
        value=json.loads(subprocess.check_output([YQ,'-o=json','.',str(p)],text=True))
        self.assertEqual(value['tun']['exclude-uid'],[10001,10002])
        self.assertEqual(value['tun']['include-uid'],[])
        self.assertEqual(value['tun']['stack'],'system')
        self.assertFalse(value['tun']['strict-route']);self.assertFalse(value['tun']['auto-redirect'])
        self.assertEqual(value['dns']['fake-ip-range'],'28.0.0.1/8')
        self.assertEqual(value['tproxy-port'],9898)

    def rules_prefix(self):
        return f'''
. {ROOT}/box/scripts/rules.utils
iptables-save() {{ cat "$box_dir/firewall"; }}
ip6tables-save() {{ :; }}
ip() {{ cat "$box_dir/routes"; }}
current_boot_id() {{ echo boot; }}
runtime_clear() {{ :; }}
cleanup_cn_ipset_if_needed() {{ :; }}
cleanup_iptables_for_mode() {{ echo "$1" >> "$box_dir/operations"; [ "$1" != all ] || : > "$box_dir/firewall"; }}
'''

    def test_clean_capture_skips_cleanup_and_keeps_agh_chains(self):
        (self.base/'firewall').write_text(':MFR_AGH_DNS - [0:0]\n-A OUTPUT -j MFR_AGH_DNS\n')
        (self.base/'routes').write_text('')
        r=self.run_shell(self.rules_prefix()+'mfr_rules_disable all')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertFalse((self.base/'operations').exists())
        self.assertEqual((self.base/'rules.state').read_text().strip(),'boot|clean')

    def test_remaining_legacy_rules_trigger_recovery_after_targeted_cleanup(self):
        (self.base/'firewall').write_text(':BOX_LOCAL - [0:0]\n')
        (self.base/'routes').write_text('')
        r=self.run_shell(self.rules_prefix()+'mfr_rules_disable tun')
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual((self.base/'operations').read_text().splitlines(),['tun','all'])
        self.assertEqual((self.base/'rules.state').read_text().strip(),'boot|clean')
        (self.base/'routes').write_text('default dev Meta table 2025\n')
        self.assertNotEqual(self.run_shell(self.rules_prefix()+'mfr_rules_absent').returncode,0)

    def test_start_gate_prioritizes_manual_stop_and_current_wifi(self):
        (self.base/'preferences.json').write_text(json.dumps({'wifi_pause_enabled':True,'wifi_pause_ssids':['Home']}))
        (self.base/'service-intent').write_text('running\n')
        probe='''mfr_current_ssid() { cat "$box_dir/wifi"; }
mfr_start_gate
'''
        (self.base/'wifi').write_text('Other\n')
        self.assertEqual(self.run_shell(probe).returncode,0)
        (self.base/'wifi').write_text('Home\n')
        self.assertEqual(self.run_shell(probe).returncode,77)
        self.assertEqual((self.base/'wifi-paused').read_text().strip(),'Home')
        self.assertEqual(self.run_shell('mfr_current_ssid() { return 1; }; mfr_start_gate').returncode,75)
        (self.base/'service-intent').write_text('stopped\n')
        self.assertEqual(self.run_shell('mfr_current_ssid() { exit 9; }; mfr_start_gate').returncode,77)

    def test_network_state_lag_and_lock_busy_retry_without_waiting_sixty_seconds(self):
        source=(ROOT/'box/scripts/box.policy').read_text()
        watch=source.split('  watch)\n',1)[1].split('  reconcile)\n',1)[0].rsplit(';;',1)[0]
        funcs=functions(ROOT/'box/scripts/box.policy',['policy_pending','policy_check'])
        (self.base/'scripts').mkdir();(self.base/'scripts/network.events').write_text('')
        (self.base/'settings').write_text('')
        self.base.joinpath('scripts/box.adg').write_text('#!/bin/sh\nexit 0\n');self.base.joinpath('scripts/box.adg').chmod(0o700)
        (self.base/'service-intent').write_text('running\n');(self.base/'wifi-paused').write_text('Home\n')
        code=f'''scripts_dir=$box_dir/scripts;policy_pid=$box_dir/pid;intent_file=$box_dir/service-intent
paused_file=$box_dir/wifi-paused;system_packages_file=$box_dir/none
alive() {{ return 1; }};live() {{ return 1; }};release() {{ :; }};adg_health_needed() {{ return 1; }}
mfr_events_open() {{ :; }};mfr_events_ensure() {{ :; }};mfr_events_close() {{ :; }}
mfr_uptime() {{ cat "$box_dir/clock"; }};mfr_network_interval() {{ echo 60; }}
sleep() {{ echo $(($(cat "$box_dir/clock")+$1)) > "$box_dir/clock"; }}
mfr_events_wait() {{ sleep "$1"; [ "$(cat "$box_dir/clock")" -lt 30 ] || exit 9; return 1; }}
mfr_wifi_matches() {{ [ "$1" = Home ]; }}
mfr_current_ssid() {{ if [ "$scenario" = stale ] && [ "$(cat "$box_dir/clock")" -lt 3 ]; then echo Home; else echo ''; fi; }}
acquire() {{ local n=$(cat "$box_dir/acquires");echo $((n+1)) > "$box_dir/acquires";[ "$scenario" != busy ] || [ "$n" != 0 ]; }}
reconcile() {{ cat "$box_dir/clock" > "$box_dir/started";rmdir "$box_dir/module"; }}
dumpsys() {{ :; }};box_dns_parse_network() {{ echo network; }}
{funcs}
'''
        watch=watch.replace('. /data/adb/box/settings.ini',f'. {self.base}/settings').replace('/data/adb/modules/box_for_root',str(self.base/'module'))
        for scenario in ['stale','busy']:
            (self.base/'module').mkdir();(self.base/'clock').write_text('0\n');(self.base/'acquires').write_text('0\n')
            r=self.run_shell(code+'\nscenario='+scenario+'\n'+watch)
            self.assertIn(r.returncode,[0,1],r.stderr)
            self.assertLessEqual(int((self.base/'started').read_text()),10)



    def test_start_is_idempotent_and_cancellation_never_applies_capture(self):
        scripts=self.base/'scripts';scripts.mkdir()
        helper=scripts/'box.iptables';helper.write_text('#!/bin/sh\necho "$1" >> "'+str(self.base)+'/operations"\n');helper.chmod(0o700)
        funcs=functions(ROOT/'box/scripts/box.service',['start_box'])
        code=funcs+'\nscripts_dir=$box_dir/scripts\nadg_core_alive() { [ "$scenario" = live ]; }\nbox_permission() { :; }; box_check_bin() { :; }\nbox_run_bin() { [ "$scenario" != cancel ] || return 77; }\nstop_box() { echo stopped >> "$box_dir/operations"; }\nmfr_start_gate() { :; }; set_description() { :; }\n'
        for scenario,expected in [('live',[]),('normal',['disable','renew']),('cancel',['disable','stopped'])]:
            with self.subTest(scenario=scenario):
                (self.base/'operations').unlink(missing_ok=True)
                r=self.run_shell(code+'\nscenario='+scenario+'; start_box')
                self.assertEqual(r.returncode,77 if scenario=='cancel' else 0,r.stderr)
                p=self.base/'operations'
                self.assertEqual(p.read_text().splitlines() if p.exists() else [],expected)

if __name__=='__main__':unittest.main()
