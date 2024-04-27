import contextlib
import unittest
from io import StringIO
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

if __name__ == '__main__':
    unittest.main()
