import webbrowser
from io import StringIO

import yaml
from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal
from textual.screen import Screen
from textual.widget import Widget
from textual.widgets import Header, TextArea, SelectionList, OptionList, Footer

from bogrod.tui.widgets.modals import InputModal, HelpableMixin
from bogrod.tui.widgets.radioslist import RadioSelectionList
from bogrod.util import tryOr


class VulnearabilityEditor(HelpableMixin, Screen):
    CSS_PATH = "editor.tcss"

    BINDINGS = [
        Binding(key="ctrl+s", action='save', description="save"),
        Binding(key="enter", action='ignore', show=False),
        Binding(key='ctrl+t', action='save_template', description='save as template'),
        Binding(key='v,V', action='browse_url', description='browse CVE-related web page', show=True),
        Binding(key='t,T', action='select_template', description='get template'),
        Binding(key="?", action='help', description="help", priority=True, show=True),
    ]

    def __init__(self, *args, vex_data=None, vuln_data=None, vuln_details=None, vex_schema=None,
                 templates=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.vex_schema = vex_schema
        self.vuln_details = vuln_details
        self.vuln_data = vuln_data
        self.vex_data = vex_data
        self.vex_templates = templates

    def compose(self) -> ComposeResult:
        # yield Static("one", classes="box")
        yield Header()
        details = TextArea(self.vuln_details, id='view-details', classes="box", read_only=True)
        details.border_title = 'details'
        yield details
        vex_raw = StringIO()
        yaml.dump(self.vex_data, vex_raw)
        vex_raw.seek(0)
        vexdata = TextArea(vex_raw.read(), id='view-vexdata', classes="box")
        vexdata.border_title = 'vexdata'
        yield vexdata
        with Horizontal():
            states, responses, justifications, detail = self.make_vex_responses()
            yield states
            yield responses
            yield justifications
            yield detail
        templates = OptionList(classes="box templates", id='select-template')
        templates.border_title = 'templates'
        yield templates
        yield Footer()

    def make_vex_responses(self):
        states = [(v, i, False) for i, v in enumerate(self.vex_schema['state'])]
        responses = [(v, i, False) for i, v in enumerate(self.vex_schema['response'])]
        justifications = [(v, i, False) for i, v in enumerate(self.vex_schema['justification'], )]

        states = RadioSelectionList(
            *states,
            id='select-state', classes="box",
        )
        states.border_title = 'state'
        responses = SelectionList[int](
            *responses,
            id='select-response', classes="box",
        )
        responses.border_title = 'response'
        justifications = RadioSelectionList(
            *justifications,
            id='select-justification', classes="box",
        )
        justifications.border_title = 'justification'
        detail = TextArea(self.vex_data['detail'], id='text-detail', classes="box")
        detail.border_title = 'detail'
        return states, responses, justifications, detail

    @property
    def focus_chain(self) -> list[Widget]:
        try:
            return [
                self.query_one('#select-state'),
                self.query_one('#select-response'),
                self.query_one('#select-justification'),
                self.query_one('#text-detail'),
                self.query_one('#select-template'),
                self.query_one('#view-vexdata'),
            ]
        except Exception as e:
            pass
        return []

    def on_mount(self) -> None:
        self.log(f'vex data {self.vex_data} {self.vex_schema}')
        self.get_widget_by_id('select-state').focus()

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
        self.log('****templates', templates)
        self.query_one('#select-template').clear_options()
        self.query_one('#select-template').add_options(templates)
        # calling focus here causes the state to be deselected/wrong
        # self.query_one('#select-state').focus()

    def action_save(self):
        data = self.data()
        self.dismiss(data)

    def action_save_template(self):
        data = self.data()

        def on_dismiss(key):
            self.vex_templates = self.app.bogrod.add_as_template(key, data)
            self.on_mount()

        self.app.push_screen(InputModal(border_title='template name'), on_dismiss)

    def action_select_template(self):
        options = self.query_one('#select-template')
        options.highlighted = 0 if options.highlighted is None else options.highlighted
        options.focus()

    def action_browse_url(self):
        url = self.vuln_data.get('url')
        webbrowser.open(url) if url else None

    def on_key(self, event) -> None:
        self.log(f"key {event.key}")
        if event.key == 'enter':
            event.prevent_default()
        if event.key == 'space' and self.focused.id == 'select-template':
            option_list = self.focused
            template = option_list.get_option_at_index(option_list.highlighted).prompt
            self.vex_data = dict(self.vex_templates[template])
            self.on_mount()
            self.action_select_template()

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

    @property
    def help_bindings(self):
        return [b for b in self.BINDINGS if b.key != 'enter']

    @property
    def help_text(self):
        return """
        * **Purpose** 
          
          Use this page to edit your vulnerability analysis. For every vulnerability, 
          you should define the state, response, justification and provide additional details.
        
        * **Templates**
        
          Your analysis is automatically stored as a component template. Apply any 
          template by pressing T and selecting the template from the list, then press
          space. Store any response as a template by pressing Ctrl+T. 
          
        * **Bulk updates**
        
          If you have selected multiple vulnerabilities before entering this page,
          update all the selected vulnerabilities by pressing Ctrl+S.
        """
