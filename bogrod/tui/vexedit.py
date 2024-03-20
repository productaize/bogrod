from io import StringIO

import yaml
from textual.app import ComposeResult
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widgets import Header, TextArea, Label, SelectionList, OptionList, Footer

from bogrod import tryOr
from bogrod.tui.widgets.modals import InputModal
from bogrod.tui.widgets.radioslist import RadioSelectionList


class VulnearabilityEditor(Screen):
    CSS_PATH = "editor.tcss"

    def __init__(self, *args, vex_data=None, vuln_details=None, vex_schema=None,
                 templates=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.vex_schema = vex_schema
        self.vuln_details = vuln_details
        self.vex_data = vex_data
        self.vex_templates = templates

    def compose(self) -> ComposeResult:
        # yield Static("one", classes="box")
        yield Header()
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
        yield OptionList(classes="box templates", id='select-template')
        yield Footer()

    def on_mount(self) -> None:
        self.log(f'vex data {self.vex_data} {self.vex_schema}')

        def select_single_option(id, key):
            option = tryOr(lambda: self.vex_schema[key].index(self.vex_data[key]), None)
            control = self.query_one(id)
            control.deselect_all()
            if isinstance(option, int):
                self.query_one(id).select(option)

        def select_multiple_options(id, key):
            options = tryOr(lambda: self.vex_data[key], [])
            control = self.query_one(id)
            control.deselect_all()
            for option in options:
                idx = tryOr(lambda: self.vex_schema[key].index(option), None)
                if isinstance(idx, int):
                    self.query_one(id).select(idx)

        select_single_option('#select-state', 'state')
        select_single_option('#select-justification', 'justification')
        select_multiple_options('#select-response', 'response')
        self.query_one('#text-detail').text = self.vex_data['detail']

        templates = [k for k, v in self.vex_templates.items()
                     if (v.get('match') in ('all', self.vuln_details)
                         or k in self.vuln_details)]
        self.log('****tempaltes', templates)
        self.query_one('#select-template').clear_options()
        self.query_one('#select-template').add_options(templates)

    def on_key(self, event) -> None:
        self.log(f"key {event.key}")
        if event.key == 'enter':
            event.prevent_default()
        if event.key == 'ctrl+s':
            data = self.data()
            self.dismiss(data)
        if event.key == 'ctrl+t':
            data = self.data()

            def on_dismiss(key):
                self.vex_templates = self.app.bogrod.add_as_template(key, data)
                self.on_mount()

            self.app.push_screen(InputModal(), on_dismiss)

        if event.key == 'space' and self.app.focused.id == 'select-template':
            option_list = self.app.focused
            template = option_list.get_option_at_index(option_list.highlighted).prompt
            self.vex_data = dict(self.vex_templates[template])
            self.on_mount()

    def on_selection_list_select(self, event):
        self.log(f"selection {event}")

    def on_option_list_option_selected(self, event):
        if event.option_list.id == 'select-component':
            self.log(f"component {event.option.prompt}")
            self.vex_data = self.vex_templates[event.option.prompt]
            self.on_mount()

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
