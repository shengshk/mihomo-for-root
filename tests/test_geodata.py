"""Offline Geo seeding preserves existing databases and core-recognized aliases."""
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which('busybox'), 'requires BusyBox')
class GeoDataSeedTest(unittest.TestCase):
    def test_seed_missing_preserve_existing_aliases_and_repeat(self):
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=base/'source';dest=base/'destination'
            source.mkdir();dest.mkdir()
            files=['GeoIP.dat','GeoSite.dat','Country.mmdb','ASN.mmdb']
            for name in files:(source/name).write_bytes(('builtin-'+name).encode())
            (dest/'geosite.DAT').write_bytes(b'user-geosite')
            (dest/'geoip.metadb').write_bytes(b'user-country')
            (dest/'ASN.mmdb').touch()
            command=f'. "{ROOT}/box/scripts/geodata.utils"; mfr_seed_geodata "$1" "$2"'
            def seed():subprocess.run(['bash','-c',command,'seed',str(source),str(dest)],check=True)
            seed()
            self.assertEqual((dest/'geosite.DAT').read_bytes(),b'user-geosite')
            self.assertFalse((dest/'GeoSite.dat').exists())
            self.assertEqual((dest/'geoip.metadb').read_bytes(),b'user-country')
            self.assertFalse((dest/'Country.mmdb').exists())
            self.assertEqual((dest/'GeoIP.dat').read_bytes(),b'builtin-GeoIP.dat')
            self.assertEqual((dest/'ASN.mmdb').read_bytes(),b'builtin-ASN.mmdb')
            (dest/'GeoIP.dat').write_bytes(b'updated-user-geoip')
            seed()
            self.assertEqual((dest/'GeoIP.dat').read_bytes(),b'updated-user-geoip')
            self.assertFalse(list(dest.glob('*.next')))
