"""Package-to-UID mapping keeps shared, missing and multiuser names intact."""
import re
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('busybox'), 'requires BusyBox')
class PackageUidTest(unittest.TestCase):
    def mapping(self, entries, packages, gids=(), mode='blacklist'):
        source=(ROOT/'box/scripts/box.service').read_text()
        function=re.search(r'^find_packages_uid\(\) \{.*?^\}',source,re.M|re.S).group()
        with tempfile.TemporaryDirectory(prefix='mfr-uids-') as tmp:
            base=Path(tmp)
            (base/'packages').write_text(packages)
            script=f'''box_run_state={shlex.quote(tmp)}
system_packages_file="$box_run_state/packages"
uid_list="$box_run_state/uid.list"
proxy_mode={shlex.quote(mode)}
packages_list=({' '.join(map(shlex.quote,entries))})
gid_list=({' '.join(map(shlex.quote,gids))})
log() {{ :; }}
{function}
find_packages_uid
'''
            (base/'run.sh').write_text(script)
            subprocess.run(['bash',str(base/'run.sh')],check=True,capture_output=True,text=True,timeout=5)
            return (base/'uid.list').read_text().splitlines()

    def test_missing_shared_multiuser_and_gids(self):
        self.assertEqual(self.mapping(
            ['com.a','com.shared','com.missing','10:com.a','bad:com.b',':com.a','0:','com.b'],
            'com.a 10001 more fields\ncom.shared 10001\ncom.b 10002\n',
            gids=['3005','10001']), ['3005','10001','10002','1010001'])

    def test_empty_map_and_empty_list(self):
        self.assertEqual(self.mapping(['com.a'],'',gids=['3005']),['3005'])
        self.assertEqual(self.mapping([],'com.a 10001\n'),[])
        self.assertEqual(self.mapping(['com.a'],'com.a 10001\n',mode='core'),[])

    def test_large_persistent_list(self):
        entries=[f'com.example.app{i}' for i in range(20000)]
        self.assertEqual(self.mapping(entries,'com.example.app19999 10444\n'),['10444'])

if __name__ == '__main__':
    unittest.main()
