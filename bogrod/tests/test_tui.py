from unittest import IsolatedAsyncioTestCase

from bogrod import Bogrod
from bogrod.tests import BASE_PATH


class BogrodTuiTests(IsolatedAsyncioTestCase):
    # guide: https://textual.textualize.io/guide/testing/

    async def test_tui_setup(self):
        # basic testing of the TUI
        from bogrod.tui.app import BogrodApp
        bogrod = Bogrod.from_sbom(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.cdx.json')
        bogrod.read_vex(BASE_PATH / 'releasenotes/sbom/vex.yaml')
        bogrod.read_grype(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.grype.json')
        bogrod.app = BogrodApp(bogrod=bogrod)
        async with bogrod.app.run_test() as pilot:
            self.assertIsNotNone(pilot)
            await pilot.press('enter')
            await pilot.press('q')
