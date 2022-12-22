import unittest
from io import StringIO
from pathlib import Path

import bogrod

from bogrod import Bogrod

BASE_PATH = Path(bogrod.__file__).parent.parent


class BogrodTests(unittest.TestCase):
    def test_from_file(self):
        sbom = Bogrod.from_sbom(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.json')
        sbom.read_notes(BASE_PATH / 'releasenotes/notes/rc1-a86b72ab67c7c21e.yaml')
        # check previous release with known security issue present
        security_notes = sbom.notes['security']
        self.assertNotIn('CVE-2022-29999 high fixed', security_notes)
        # update notes with current issues
        # -- expected previous issue to be resolved
        # -- expected more issues added
        sbom.update_notes()
        self.assertIn('CVE-2022-29999 high fixed', security_notes)
        self.assertIn('CVE-2021-27478 high open', security_notes)
        sbom.write_notes(BASE_PATH / 'releasenotes/notes/rc1-a86b72ab67c7c21e-updated.yaml')
        buffer = StringIO()
        sbom.report(stream=buffer)
        self.assertTrue(buffer.getvalue().startswith('id'))
        self.assertTrue(buffer.getvalue().__contains__('CVE-2021-27478'))


if __name__ == '__main__':
    unittest.main()
