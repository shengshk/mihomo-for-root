import subprocess
import unittest
import shutil
from pathlib import Path
from test_manager import ManagerFixture, YQ

ROOT = Path(__file__).resolve().parents[1]
UTILS = ROOT / 'box/scripts/dns.utils'

def parse(text):
    result = subprocess.run(
        ['bash', '-c', '. "$1"; box_dns_parse_network', 'test', str(UTILS)],
        input=text, text=True, capture_output=True, check=True,
    )
    return result.stdout.strip()

class DefaultNetworkTest(unittest.TestCase):
    def test_wifi_does_not_collect_cellular_dns(self):
        self.assertEqual(parse('''Active default network: 103
NetworkAgentInfo{network{100} LinkProperties: {InterfaceName: rmnet_data0 DnsAddresses: [ /9.9.9.9 ]}}
NetworkAgentInfo{network{103} LinkProperties: {InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1,/fe80::1 ]}}
'''), '103|wlan0|10.0.0.1')

    def test_cellular_default_ignores_still_connected_wifi(self):
        self.assertEqual(parse('''Active default network: 100
NetworkAgentInfo{network{100} LinkProperties: {InterfaceName: rmnet_data0 DnsAddresses: [ /9.9.9.9,/149.112.112.112 ]}}
NetworkAgentInfo{network{103} LinkProperties: {InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1 ]}}
'''), '100|rmnet_data0|9.9.9.9 149.112.112.112')

    def test_same_dns_still_tracks_different_network(self):
        a=parse('Active default network: 101\nNetworkAgentInfo{network{101} InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1 ]}\n')
        b=parse('Active default network: 102\nNetworkAgentInfo{network{102} InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1 ]}\n')
        self.assertNotEqual(a, b)

    def test_invalid_loopback_and_duplicate_servers_are_filtered(self):
        self.assertEqual(parse('''Active default network: 3
NetworkAgentInfo{network{3} InterfaceName: wlan0 DnsAddresses: [ /127.0.0.1,/0.0.0.0,/999.1.1.1,/224.0.0.1,/10.0.0.1,/10.0.0.1 ]}
'''), '3|wlan0|10.0.0.1')

    def test_no_default_network_or_only_ipv6_has_safe_fallback(self):
        self.assertEqual(parse('Active default network: none\n'), 'none||')
        self.assertEqual(parse('Active default network: 5\nNetworkAgentInfo{network{5} InterfaceName: wlan0 DnsAddresses: [ /fe80::1 ]}\n'), '5|wlan0|')

    def test_tun_dns_is_not_used_as_upstream(self):
        self.assertEqual(parse('Active default network: 8\nNetworkAgentInfo{network{8} InterfaceName: tun0 DnsAddresses: [ /28.0.0.1 ]}\n'), 'none||')

    def test_historical_log_does_not_override_current_agent(self):
        self.assertEqual(parse('''Active default network: 103
NetworkAgentInfo{network{103} InterfaceName: wlan0 DnsAddresses: [ /10.0.0.1 ]}
2026/10/24 old NetworkAgentInfo{network{103} InterfaceName: wlan0 DnsAddresses: [ /1.1.1.1 ]}
'''), '103|wlan0|10.0.0.1')

@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class DnsRefreshTest(unittest.TestCase):
    def setUp(self):
        self.fx = ManagerFixture()
        self.addCleanup(self.fx.close)
        source = (ROOT/'box/scripts/box.dns').read_text().replace('/data/adb/box', str(self.fx.base)).replace('/system/bin/sh', '/bin/bash')
        self.fx.write('scripts/box.dns', source)
        with (self.fx.base/'settings.ini').open('a') as file:
            file.write('\nbin_name=mihomo\n')
        self.fx.write('bin/pidof', '#!/bin/sh\necho 123\n')
        self.fx.write('scripts/box.service', f'''#!/bin/bash
. "{self.fx.base}/settings.ini"
. "$scripts_dir/dns.utils"
box_dns_paths
echo "$1" >> "$box_dir/dns-operations"
box_dns_snapshot > "$box_dns_state"
''')

    def refresh(self):
        return subprocess.run(['bash', str(self.fx.base/'scripts/box.dns'), 'refresh'],
                              env=self.fx.env, text=True, capture_output=True)

    def test_refresh_applies_change_once_and_releases_operation_lock(self):
        result = self.refresh()
        self.assertEqual(result.returncode, 0, result.stderr)
        state = self.fx.base/'run/state/network-dns.state'
        self.assertEqual(state.read_text().strip(), 'enabled|1|wlan0|10.0.0.1')
        self.assertFalse((self.fx.base/'manage/operation.lock').exists())
        self.assertEqual(self.refresh().returncode, 0)
        self.assertEqual((self.fx.base/'dns-operations').read_text(), 'reload\n')

    def test_busy_operation_does_not_reload_or_remove_another_lock(self):
        lock = self.fx.base/'manage/operation.lock'
        lock.mkdir()
        (lock/'pid').write_text('occupied\n')
        self.assertEqual(self.refresh().returncode, 75)
        self.assertEqual((lock/'pid').read_text(), 'occupied\n')
        self.assertFalse((self.fx.base/'dns-operations').exists())


if __name__ == '__main__':
    unittest.main()
