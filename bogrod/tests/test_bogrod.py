import unittest
from pathlib import Path

import bogrod

from bogrod import Bogrod

BASE_PATH = Path(bogrod.__file__).parent.parent


class BogroTests(unittest.TestCase):
    def test_from_file(self):
        sbom = Bogrod.from_sbom(BASE_PATH / 'reports/jupyter-base-notebook.json')
        print(sbom.vulnerabilities())


if __name__ == '__main__':
    unittest.main()
