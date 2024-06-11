import contextlib
import random
import unittest
from io import StringIO
from pathlib import Path
from unittest import skip

import bogrod
from bogrod import Bogrod
from bogrod.tests import BASE_PATH


class BogrodTests(unittest.TestCase):
    # TODO add more tests
    def test_main(self):
        f = StringIO()
        with contextlib.redirect_stdout(f):
            bogrod.main(['jupyter'])
        output = f.getvalue()
        self.assertIn('bogrod', output)

    def test_contrib_base(self):
        from bogrod.contrib import aggregators
        self.assertIn('dummy', aggregators)

    @skip('functionality currently not working properly')
    def test_from_file(self):
        notes_file = BASE_PATH / 'releasenotes/notes/rc1-99e6a29d3335a383.yaml'
        notes_file_update = BASE_PATH / 'releasenotes/notes/rc1-99e6a29d3335a383-update.yaml'
        sbom = Bogrod.from_sbom(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.json')
        sbom.read_notes(notes_file)
        # check previous release with known security issue present
        security_notes = sbom.notes['security']
        self.assertNotIn('CVE-2022-29999 high fixed', security_notes)
        # update notes with current issues
        # -- expected previous issue to be resolved
        # -- expected more issues added
        sbom.update_notes()
        self.assertIn('CVE-2022-29999 high fixed', security_notes)
        self.assertIn('CVE-2021-27478 high open', security_notes)
        sbom.write_notes(notes_file_update)
        buffer = StringIO()
        sbom.report(stream=buffer)
        self.assertTrue(buffer.getvalue().startswith('id'))
        self.assertTrue(buffer.getvalue().__contains__('CVE-2021-27478'))

    def test_cli(self):
        base_path = Path(bogrod.__file__).parent.parent
        with self.assertRaises(SystemExit):
            bogrod.main(argv='--version'.split(' '))
        bogrod.main(argv=f'{base_path}/releasenotes/sbom/jupyter-base-notebook.cdx.json'.split(' '))

    def test_filter_issues(self):
        bogrod = Bogrod.from_sbom(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.cdx.json')
        # -- no issues expected
        data = bogrod._generate_report_data(issues=True)
        self.assertEqual(len(data), 0)
        # -- disregard issues
        data = bogrod._generate_report_data(issues=False)
        self.assertEqual(len(data), len(bogrod.data['vulnerabilities']))
        # -- simulate an issue
        for vuln in random.sample(bogrod.data['vulnerabilities'], 5):
            vuln_id = vuln['id']
            vex = bogrod.vex.setdefault(vuln_id, {})
            vex_report = vex.setdefault('report', {})
            vex_report['issues'] = [
                {
                    'id': 'CVE-2022-29999',
                    'description': 'this is a test issue'
                }
            ]
        data = bogrod._generate_report_data(issues=True)
        # -- expect at least 5 issues
        # -- we can have more than 5 issues because bogrod.data maintains a list of all issues (in SBOM),
        #    while bogrod.vex maintains a list of CVEs (i.e. the same CVE can be referenced in SBOM multiple times)
        self.assertTrue(len(data) >= 5)
        # -- get 'no issues'
        data = bogrod._generate_report_data(issues=False)
        self.assertTrue(len(data) < len(bogrod.data['vulnerabilities']))
        # -- get 'all issues'
        data = bogrod._generate_report_data(issues=None)
        self.assertEqual(len(data), len(bogrod.data['vulnerabilities']))
        data = bogrod._generate_report_data(issues='*')
        self.assertEqual(len(data), len(bogrod.data['vulnerabilities']))


if __name__ == '__main__':
    unittest.main()
