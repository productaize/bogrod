from unittest import IsolatedAsyncioTestCase

from bogrod import Bogrod
from bogrod.tests import BASE_PATH
from bogrod.tui import VulnearabilityEditor
from bogrod.tui.vulnlist import VulnerabilityList
from bogrod.tui.widgets.modals import SearchModal


class BogrodTuiTests(IsolatedAsyncioTestCase):
    # guide: https://textual.textualize.io/guide/testing/
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from bogrod.tui.app import BogrodApp
        bogrod = Bogrod.from_sbom(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.cdx.json')
        bogrod.read_vex(BASE_PATH / 'releasenotes/sbom/vex.yaml')
        bogrod.read_grype(BASE_PATH / 'releasenotes/sbom/jupyter-base-notebook.grype.json')
        bogrod.app = BogrodApp(bogrod=bogrod)
        self.bogrod = bogrod

    async def test_tui_setup(self):
        # basic testing of the TUI
        bogrod = self.bogrod
        async with bogrod.app.run_test() as pilot:
            self.assertIsNotNone(pilot)
            await pilot.press('enter')
            await pilot.press('q')

    async def test_tui_filter(self):
        # test filtering by various criteria
        bogrod = self.bogrod
        async with bogrod.app.run_test() as pilot:
            await self._test_filter(pilot, 'affects:python', 'affects', 'python')
            await self._test_filter(pilot, 'state:in_triage', 'state', 'in_triage')
            await self._test_filter(pilot, 'source:nvd', 'source', 'nvd')

    async def test_tui_multi_select(self):
        # test selecting multiple vulnerabilities
        bogrod = self.bogrod
        async with bogrod.app.run_test() as pilot:
            self.assertIsInstance(pilot.app.screen, VulnerabilityList)
            await pilot.press('space', 'down', 'space')
            table = pilot.app.screen.vuln_table
            self.assertEqual(len(table.selected_rows), 2)
            # quick reset of selected rows
            await pilot.press('ctrl+@')  # ctrl+space
            self.assertEqual(len(table.selected_rows), 0)
            # quick selection of all rows
            await pilot.press('ctrl+@')  # ctrl+space
            self.assertEqual(len(table.selected_rows), len(pilot.app.screen.data))

    async def test_tui_multi_edit(self):
        # test editing multiple vulnerabilities
        bogrod = self.bogrod
        async with bogrod.app.run_test() as pilot:
            # select two vulnerabilities
            self.assertIsInstance(pilot.app.screen, VulnerabilityList)
            await pilot.press('space', 'down', 'space')
            table = pilot.app.screen.vuln_table
            self.assertEqual(len(table.selected_rows), 2)
            # edit selected vulnerabilities
            await pilot.press('enter')
            await pilot.pause()
            self.assertIsInstance(pilot.app.screen, VulnearabilityEditor)
            # set a comment
            # -- tab, tab, tab to 'detail' textarea
            await pilot.press('tab', 'tab', 'tab')
            await pilot.press(*'this is a test')
            await pilot.press('ctrl+s')
            # check comment is saved for both vulnerabilities
            await pilot.pause()
            self.assertIsInstance(pilot.app.screen, VulnerabilityList)
            vex = self.bogrod.vex
            for vuln in pilot.app.screen.data[:2]:
                self.assertEqual(vex[vuln['id']]['detail'].strip(), 'this is a test')

    async def _test_filter(self, pilot, criteria, key, value):
        # runs a sequence of user interactions to filter the vulnerability list
        # 1. enter search modal by pressing /
        # 2. enter search criteria, using format field:value
        # 3. check filters and active data, ensuring data is filtered
        # 4. reset filters by pressing / and enter (empty search)
        # -- get base data
        data = pilot.app.screen.data
        count = len(data)
        # -- enter search modal
        self.assertIsInstance(pilot.app.screen, VulnerabilityList)
        await pilot.press('/')
        self.assertIsInstance(pilot.app.screen, SearchModal)
        # -- search for python vulnerabilities
        await pilot.press(*criteria, 'enter')
        self.assertIsInstance(pilot.app.screen, VulnerabilityList)
        # -- check current filters and data are filtered
        filters = pilot.app.screen.filters
        data = pilot.app.screen.data
        print(filters)
        self.assertEqual(filters[key], value)
        self.assertTrue(all(value in vuln[key] for vuln in data))
        # -- reset filters
        await pilot.press('/', "enter")
        data = pilot.app.screen.data
        self.assertIsInstance(pilot.app.screen, VulnerabilityList)
        self.assertEqual(len(data), count)
