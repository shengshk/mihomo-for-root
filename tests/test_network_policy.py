import subprocess
import unittest
from pathlib import Path

UTILS = Path(__file__).resolve().parents[1] / "box/scripts/network.utils"

class WifiPolicyTest(unittest.TestCase):
    def decision(self, wanted="running", disabled=False, live=False, paused=False, matches=False, explicit=False):
        values = [wanted] + [str(v).lower() for v in [disabled, live, paused, matches, explicit]]
        return subprocess.check_output(["bash", "-c", '. "$1"; shift; mfr_policy_decision "$@"', "test", str(UTILS), *values], text=True).strip()

    def test_connection_and_disconnect(self):
        self.assertEqual(self.decision(live=True, matches=True), "pause")
        self.assertEqual(self.decision(paused=True, matches=True), "pause")
        self.assertEqual(self.decision(paused=True), "start")

    def test_manual_stop_wins(self):
        self.assertEqual(self.decision(wanted="stopped", paused=True), "idle")
        self.assertEqual(self.decision(wanted="stopped", live=True, matches=True), "stop")

    def test_module_disable_wins(self):
        self.assertEqual(self.decision(disabled=True, paused=True, explicit=True), "idle")
        self.assertEqual(self.decision(disabled=True, live=True), "stop")

    def test_unexpected_core_exit_not_restarted(self):
        self.assertEqual(self.decision(), "idle")
        self.assertEqual(self.decision(matches=True), "idle")
        self.assertEqual(self.decision(explicit=True), "start")
        self.assertEqual(self.decision(explicit=True, matches=True), "pause")

    def test_wifi_names_and_stale_info(self):
        def parse(text):
            return subprocess.check_output(["bash", "-c", '. "$1"; busybox() { "$@"; }; mfr_wifi_parse', "test", str(UTILS)], input=text, text=True).rstrip("\n")
        name = 'Home \"Quoted\", 中文'
        report = f'Wifi is connected to "{name}"\nWifiInfo: SSID: "{name}", Supplicant state: COMPLETED, IsPrimary: 1\n'
        self.assertEqual(parse(report), name)
        self.assertEqual(parse('Wifi is disabled\nWifiInfo: SSID: "old", Supplicant state: COMPLETED\n'), "")
