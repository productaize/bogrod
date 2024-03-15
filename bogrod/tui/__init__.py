import logging
import sys

from textual.app import App, ComposeResult, RenderResult
from textual.logging import TextualHandler
from textual.message import Message
from textual.widget import Widget
from textual.widgets import Static, Header, Footer, SelectionList, OptionList, DataTable

logging.basicConfig(
    level="NOTSET",
    handlers=[TextualHandler()],
)


class VulnerabilitySelected(Message):
    def __init__(self, value: str):
        super().__init__()
        self.value = value


class VulnerabilitiesList(Widget):
    CSS_PATH = "styles.tcss"

    def compose(self) -> ComposeResult:
        self.border_title = 'severity'
        self.log(f'{self.parent.app.bogrod}')
        yield OptionList(*[
            "critical", "high", "medium", "low"
        ])
        self.log("Composed")

    def on_option_list_option_highlighted(self, event) -> None:
        self.log(f"****Highlighted {event}")
        self.post_message(VulnerabilitySelected(event))


class VulnerabilityView(Widget):
    def compose(self) -> ComposeResult:
        from datetime import datetime as dt
        yield Static(f"Vulnerability View {dt.now()}", id='vulnerability-text')

    def update(self):
        from datetime import datetime as dt
        self.query_one('#vulnerability-text').update(f"Vulnerability View {dt.now()}")


ROWS = [
    ("lane", "swimmer", "country", "time"),
    (4, "Joseph Schooling", "Singapore", 50.39),
    (2, "Michael Phelps", "United States", 51.14),
    (5, "Chad le Clos", "South Africa", 51.14),
    (6, "László Cseh", "Hungary", 51.14),
    (3, "Li Zhuhao", "China", 51.26),
    (8, "Mehdy Metella", "France", 51.58),
    (7, "Tom Shields", "United States", 51.73),
    (1, "Aleksandr Sadovnikov", "Russia", 51.84),
    (10, "Darren Burns", "Scotland", 51.84),
]


class BogrodApp(App):
    CSS_PATH = "styles.tcss"
    _on_mount_cb = []

    def __init__(self, *args, bogrod=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bogrod = bogrod
        self.data = self.bogrod._generate_report_data()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        # yield VulnerabilitiesList(classes="box", id='filter-severity')
        for flt in self.make_filters():
            yield flt
        # yield VulnerabilityView(classes="box", id="vulnerability-view")
        yield self.make_vuln_view()
        yield Static("Three", classes="box")
        yield Footer()

    def make_filters(self):
        # severity
        severity = OptionList(*[
            "critical", "high", "medium", "low"
        ], name='severity', classes="box", id='filter-severity')
        severity.border_title = 'severity'
        return severity,

    def make_vuln_view(self):
        table = self.vuln_table = DataTable(classes="box", id="vulnerability-view")
        table.cursor_type = 'row'

        def on_mount(initial=False):
            data = self.data
            table.clear()
            table.add_columns(*data[0].keys()) if initial else None
            table.add_rows(list(row.values()) for row in data)

        def reload(event):
            on_mount()
            table.refresh()

        table.reload = reload

        self._on_mount_cb.append(on_mount)
        return table

    def filter_data(self, severity=None):
        self.data = self.bogrod._generate_report_data(severities=[severity])

    def show_details(self, vuln):
        self.log(f'details {vuln}')

    def on_mount(self) -> None:
        self.title = 'bogrod'
        for cb in self._on_mount_cb:
            cb(initial=True)

    def on_key(self, key) -> None:
        if key.key == 'enter':
            self.show_details(self.data[self.vuln_table.cursor_row])

    def on_option_list_option_highlighted(self, event):
        if event.option_list.id == 'filter-severity':
            self.log(f"****Selected {event.option.prompt}")
            self.filter_data(severity=event.option.prompt)
            self.vuln_table.reload(event)


from bogrod import main

args = '-s all -W releasenotes/sbom/jupyter-base-notebook.cdx.json'.split(' ')
bogrod = main(args)
app = bogrod.app
