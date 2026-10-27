"""Exercise the real exec boundary using temporary cgroup files, never host groups."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class DaemonTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='mfr-daemon-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        for name in ('box.daemon','daemon.utils'):
            shutil.copyfile(ROOT/'box/scripts'/name,self.base/name)
        self.groups = [self.base/'unified', self.base/'legacy']
        for group in self.groups:
            group.mkdir();(group/'cgroup.procs').touch()
        busybox = self.base/'busybox'
        busybox.write_text('#!/bin/sh\nprintf "%s\\n" "'+str(self.groups[0])+'" "'+str(self.groups[1])+'"\n')
        busybox.chmod(0o700)
        self.env = {**os.environ,'PATH':str(self.base)+':'+os.environ['PATH']}

    def launch(self):
        return subprocess.run(['bash',str(self.base/'box.daemon'),'sh','-c','echo "started $$"'],env=self.env,text=True,capture_output=True)

    def test_exec_keeps_pid_and_moves_every_controller(self):
        result = self.launch()
        self.assertEqual(result.returncode,0,result.stderr)
        pid = result.stdout.strip().split()[1]
        self.assertEqual([p.joinpath('cgroup.procs').read_text().strip() for p in self.groups],[pid,pid])

    def test_failed_detach_does_not_start_command(self):
        (self.groups[1]/'cgroup.procs').unlink()
        result = self.launch()
        self.assertNotEqual(result.returncode,0)
        self.assertNotIn('started',result.stdout)
        self.assertIn('无法将后台服务移出应用进程组',result.stderr)

if __name__ == '__main__':
    unittest.main()
