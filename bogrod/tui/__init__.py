import logging
import sys
from contextlib import contextmanager
from io import StringIO
from textwrap import dedent, wrap

import yaml
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.logging import TextualHandler
from textual.screen import Screen
from textual.widgets import Header, Footer, OptionList, DataTable, Label, SelectionList, TextArea

logging.basicConfig(
    level="NOTSET",
    handlers=[TextualHandler()],
)

MD = """
* *abstract* asfaöfdafd
* *foobar* afdafdaf 
"""


class RadioSelectionList(SelectionList):
    """
    A selection list that only allows one item to be selected at a time
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def on_selection_list_selection_toggled(self, event):
        toggled = event.selection_index
        active = toggled in event.selection_list.selected
        self.deselect_all()
        self.select(toggled) if active else None


class VulnearabilityEditor(Screen):
    CSS_PATH = "editor.tcss"

    def __init__(self, *args, vex_data=None, vuln_details=None, vex_schema=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.vex_schema = vex_schema
        self.vuln_details = vuln_details
        self.vex_data = vex_data

    def compose(self) -> ComposeResult:
        # yield Static("one", classes="box")
        yield TextArea(self.vuln_details, id='view-details', classes="box", read_only=True)
        vex_raw = StringIO()
        yaml.dump(self.vex_data, vex_raw)
        vex_raw.seek(0)
        yield TextArea(vex_raw.read(), id='view-vexdata', classes="box", read_only=True)
        states = [(v, i, False) for i, v in enumerate(self.vex_schema['state'])]
        responses = [(v, i, False) for i, v in enumerate(self.vex_schema['response'])]
        justifications = [(v, i, False) for i, v in enumerate(self.vex_schema['justification'], )]
        with Horizontal(classes="box"):
            yield Label("state")
            yield RadioSelectionList(
                *states,
                id='select-state',
            )
            yield Label("response")
            yield SelectionList[int](
                *responses,
                id='select-response'
            )
            yield Label("justification")
            yield RadioSelectionList(
                *justifications,
                id='select-justification',
            )
            yield Label("detail")
            yield TextArea(self.vex_data['detail'], id='text-detail')

    def on_mount(self) -> None:
        self.log(f'vex data {self.vex_data} {self.vex_schema}')

        def select_single_option(id, key):
            option = tryOr(lambda: self.vex_schema[key].index(self.vex_data[key]), None)
            if isinstance(option, int):
                self.query_one(id).select(option)

        def select_multiple_options(id, key):
            options = tryOr(lambda: self.vex_data[key], [])
            for option in options:
                idx = tryOr(lambda: self.vex_schema[key].index(option), None)
                if isinstance(idx, int):
                    self.query_one(id).select(idx)

        select_single_option('#select-state', 'state')
        select_single_option('#select-justification', 'justification')
        select_multiple_options('#select-response', 'response')

    def on_key(self, event) -> None:
        self.log(f"key {event.key}")
        if event.key == 'ctrl+s':
            self.dismiss(self.data())

    def on_selection_list_select(self, event):
        self.log(f"selection {event}")

    def data(self):
        state = self.query_one('#select-state').selected
        state = self.vex_schema['state'][state[0]] if len(state) else ''
        justification = self.query_one('#select-justification').selected
        justification = self.vex_schema['justification'][justification[0]] if justification else ''
        responses = self.query_one('#select-response').selected
        responses = [self.vex_schema['response'][r] for r in responses]
        detail = self.query_one('#text-detail').text
        _data = {
            "state": state,
            "response": responses,
            "detail": detail,
            "justification": justification,
        }
        self.log(f"****data {_data}")
        return _data


class BogrodApp(App):
    CSS_PATH = "styles.tcss"
    _on_mount_cb = []

    def __init__(self, *args, bogrod=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bogrod = bogrod
        self.report_columns = 'id,name,severity,state,vector,url'.split(',')
        self.data = self.bogrod._generate_report_data(columns=self.report_columns)
        self.all_data = self.bogrod.vulnerabilities(as_dict=True)
        self.filters = {
            'severity': 'critical',
            'vector': None,
            'state': None,
        }

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        # yield VulnerabilitiesList(classes="box", id='filter-severity')
        severity, vectors, states = self.make_filters()
        yield severity
        # yield VulnerabilityView(classes="box", id="vulnerability-view")
        yield self.make_vuln_view()
        yield vectors
        yield states
        yield Footer()

    def make_filters(self):
        # severity
        severity = OptionList(*[
            "*", "critical", "high", "medium", "low"
        ], name='severity', classes="box", id='filter-severity')
        severity.border_title = 'severity'
        # vectors
        vector_options = ['*'] + list(sorted(self.bogrod._vectors()))
        vectors = OptionList(*vector_options,
                             name='vectors', classes="box", id='filter-vectors')
        vectors.border_title = 'vectors'
        # state
        state_options = ['*'] + list(sorted(self.bogrod._states()))
        states = OptionList(*state_options,
                            name='states', classes="box", id='filter-states')
        return severity, vectors, states

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

    def filter_data(self, **kwargs):
        kwargs = kwargs or self.filters

        def setfilter(k):
            fv = kwargs.get(k, self.filters.get(k))
            return [fv] if (fv and fv != '*') else None

        report_filters = {
            'severities': setfilter('severity'),
            'vectors': setfilter('vector'),
            'columns': self.report_columns,
            'states': setfilter('state'),
        }
        self.log(f'filter_data {report_filters}')
        self.data = self.bogrod._generate_report_data(**report_filters)

    def edit_vulnerability(self, vuln_id):
        all_vuln = self.bogrod.vulnerabilities(as_dict=True, severities='*')
        vuln = all_vuln[vuln_id]
        vex = self.bogrod.vex
        vex_schema = {
            k.lower(): [v for v in v.get('enum', ['<text>']) if v]
            for k, v in self.bogrod._get_vex_schema()['definitions'].items()
            if k.lower() in ['state', 'justification', 'response', 'detail']
        }
        matches = self.bogrod.grype_matches()
        vuln_details = dedent("""
                # id: {id} 
                # severity: {severity}
                # vector: {vector} 
                # component: {component} 
                # artifact: {artifact}
                # fix: {fix}      
                # urls:   {url}
                # description: 
                #      {description}
                # locations: 
                #      {location}
                """).strip().format(id=vuln_id,
                                    severity=self.bogrod._vuln_severity(vuln),
                                    vector=self.bogrod._vuln_vector(vuln),
                                    description='\n# '.join(
                                        wrap(vuln.get('description', 'unknown'), subsequent_indent=' ' * 5)),
                                    component=tryOr(lambda: vex[vuln_id]['related']['component'], 'n/a'),
                                    artifact=tryOr(lambda: (matches[vuln_id]['artifact'].get('name', '?') + '-' +
                                                            matches[vuln_id]['artifact'].get('version', '?')), 'n/a'),
                                    url=tryOr(lambda: vuln['source']['url'], 'unknown'),
                                    fix=tryOr(lambda: ';'.join(matches[vuln_id]['vulnerability']['fix']['versions']) +
                                                      '(' + matches[vuln_id]['vulnerability']['fix']['state'] + ')',
                                              '?'),
                                    location='\n#      '.join([v.get('path')
                                                               for v in
                                                               tryOr(lambda: matches[vuln_id]['artifact']['locations'],
                                                                     [{'path': '<no grype json file>'}])]),
                                    )
        editor = VulnearabilityEditor(vex_data=vex[vuln_id],
                                      vuln_details=vuln_details,
                                      vex_schema=vex_schema,
                                      classes="editor")

        def on_dismiss(data):
            self.bogrod.vex[vuln['id']].update(data)

        self.push_screen(editor, on_dismiss)

    def xedit_vulnerability(self, vuln):
        self.log(f'details {vuln}')
        matches = self.bogrod.grype_matches()
        all_vuln = self.bogrod.vulnerabilities(as_dict=True, severities='*')
        vex_schema = yaml.dump({
            k.lower(): '|'.join(v if v else '[]' for v in v.get('enum', ['<text>']))
            for k, v in self.bogrod._get_vex_schema()['definitions'].items()
            if k.lower() in ['state', 'justification', 'response', 'detail']
        }).splitlines()
        # see https://github.com/Textualize/textual/discussions/165
        with self.suspend():
            self.bogrod._work_vulnerability(vuln['id'], matches, all_vuln, vex_schema)

    def on_mount(self) -> None:
        self.title = 'bogrod'
        for cb in self._on_mount_cb:
            cb(initial=True)

    def on_key(self, key) -> None:
        if key.key == 'enter':
            self.edit_vulnerability(self.data[self.vuln_table.cursor_row]['id'])

    def on_option_list_option_highlighted(self, event):
        if event.option_list.id == 'filter-severity':
            self.log(f"****severity {event.option.prompt}")
            self.filters['severity'] = event.option.prompt
        elif event.option_list.id == 'filter-vectors':
            self.log(f"****vectors {event.option.prompt}")
            self.filters['vector'] = event.option.prompt
        elif event.option_list.id == 'filter-states':
            self.log(f"****states {event.option.prompt}")
            self.filters['state'] = event.option.prompt
        self.filter_data()
        self.vuln_table.reload(event)

    @contextmanager
    def suspend(self):
        self._driver.stop_application_mode()
        yield
        self._driver.start_application_mode()
        self.refresh()


from bogrod import main, tryOr

if sys.argv[0] == '-c':
    args = '-s all -W releasenotes/sbom/jupyter-base-notebook.cdx.json'.split(' ')
    bogrod = main(args)
    app = bogrod.app
