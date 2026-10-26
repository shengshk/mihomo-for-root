"""Read-only, bounded and redacted logs through the actual HTTP bridge."""
import os
import shutil
import unittest
import urllib.error
from test_manager import ManagerFixture, YQ


@unittest.skipUnless(YQ and shutil.which('busybox'), 'requires host yq and BusyBox')
class LogApiTest(unittest.TestCase):
    def setUp(self):
        self.fx=ManagerFixture();self.fx.call('status')
    def tearDown(self):self.fx.close()

    def test_tail_bound_redaction_and_json_text(self):
        path=self.fx.base/'run/mihomo.log'
        lines=[f'entry {i}' for i in range(150)]
        lines+=['fetch https://example.invalid/private?credential=HIDDEN','Authorization: Basic PRIVATE','secret: PRIVATE','<script>alert(1)</script>']
        path.write_text('\n'.join(lines)+'\n')
        result=self.fx.call('logs',{'type':'mihomo'})
        self.assertEqual(result['type'],'mihomo')
        self.assertEqual(len(result['text'].splitlines()),100)
        self.assertNotIn('entry 1\n',result['text'])
        self.assertNotIn('example.invalid',result['text'])
        self.assertNotIn('HIDDEN',result['text'])
        self.assertNotIn('PRIVATE',result['text'])
        self.assertIn('[链接已隐藏]',result['text'])
        self.assertIn('<script>alert(1)</script>',result['text']) # JSON text, rendered as textContent.
        path.write_text(('x'*6000+'\n')*120)
        bounded=self.fx.call('logs',{'type':'mihomo'})['text']
        self.assertLessEqual(len(bounded.encode()),32768)
        self.assertLessEqual(len(bounded.splitlines()),100)

    def test_fixed_sources_missing_logs_and_operation_lock(self):
        files=[self.fx.base/f for f in ['manage/preferences.json','manage/profiles.json','mihomo/config.yaml']]
        before=[p.read_bytes() for p in files]
        lock=self.fx.base/'manage/operation.lock';lock.mkdir();(lock/'pid').write_text(str(os.getpid()))
        self.assertEqual(self.fx.call('logs',{'type':'module'})['text'],'')
        (self.fx.base/'run/runs.log').write_text('module event\n')
        (self.fx.base/'run/adguardhome.log').write_text('daemon event\n')
        (self.fx.base/'run/adguardhome-events.log').write_text('API failed\n')
        self.assertEqual(self.fx.call('logs')['text'],'module event')
        agh=self.fx.call('logs',{'type':'agh'})['text']
        self.assertIn('daemon event',agh);self.assertIn('API failed',agh)
        self.assertEqual(before,[p.read_bytes() for p in files])
        self.assertTrue(lock.exists())
        for kind in ['../../manage/preferences.json','/proc/self/environ','unknown']:
            with self.assertRaises(urllib.error.HTTPError):self.fx.call('logs',{'type':kind})
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.fx.call('logs',{'type':'module'},{'Origin':'https://other.invalid'})
        self.assertEqual(error.exception.code,403)

if __name__=='__main__':unittest.main()
