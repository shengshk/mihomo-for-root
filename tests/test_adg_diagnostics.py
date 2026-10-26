"""API diagnostics retain failures without retaining DNS/API payloads."""
import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('busybox'), 'requires BusyBox')
class AdgDiagnosticTest(unittest.TestCase):
    def test_api_error_code_output_and_private_diagnostics(self):
        with tempfile.TemporaryDirectory(prefix='mfr-adg-errors-') as tmp:
            base=Path(tmp)
            curl=base/'curl'
            curl.write_text('#!/bin/sh\nprintf "response-secret"\nprintf "curl: (28) timeout" >&2\nexit "${FAKE_EXIT:-28}"\n')
            curl.chmod(0o700)
            script=f'''box_run={shlex.quote(tmp)}
bin_dir="$box_run"
. {shlex.quote(str(ROOT/'box/scripts/adg.utils'))}
adg_api POST 'dns_config?private-query' --data 'private-body'
'''
            proc=subprocess.run(['bash','-c',script],capture_output=True,text=True)
            self.assertEqual(proc.returncode,28)
            self.assertEqual(proc.stdout,'response-secret')
            log=base/'adguardhome-events.log'
            content=log.read_text()
            self.assertIn('api POST dns_config exit=28 curl: (28) timeout',content)
            for secret in ('private-query','private-body','response-secret'):
                self.assertNotIn(secret,content)
            self.assertEqual(log.stat().st_mode & 0o777,0o600)
            self.assertEqual(list(base.glob('.adg-api.*')),[])
            result=subprocess.run(['bash','-c',script],env={**os.environ,'FAKE_EXIT':'0'},capture_output=True,text=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(log.read_text(),content)
            log.write_text('x'*70000)
            subprocess.run(['bash','-c',script],capture_output=True)
            self.assertLess(log.stat().st_size,65536)
            self.assertIn('exit=28',log.read_text())

if __name__ == '__main__':
    unittest.main()
