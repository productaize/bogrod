from textwrap import wrap, dedent

import yaml
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header, DataTable, Footer, OptionList

from bogrod import tryOr
from bogrod.tui import VulnearabilityEditor
from bogrod.tui.widgets.modals import SearchModal


class VulnerabilityList(Screen):
    BINDINGS = [
        Binding(key="enter", action='edit_vulnerability', description="edit", priority=True, show=True),
        Binding(key="q", action='quit', description="quit", priority=True, show=True),
        Binding(key="?", action='command_palette', description="help", priority=True, show=True),
        Binding(key="l", action='focus_table', description="select", show=True),
        Binding(key='f', action='focus_filter', description='filter', show=True),
        Binding(key='/', action='search', description='search', show=True)
    ]

    def __init__(self, *args, bogrod=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bogrod = bogrod
        self.report_columns = 'id,name,severity,state,vector,url'.split(',')
        self.all_data = self.bogrod.vulnerabilities(as_dict=True, severities='*')
        self.data = None
        self.filters = {
            'severity': '*',
            'vector': None,
            'state': None,
            'issues': None,
        }
        self.bogrod.severities = '*'
        self.filter_data()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        # yield VulnerabilitiesList(classes="box", id='filter-severity')
        severity, vectors, states, components, issues = self.make_filters()
        yield severity
        # yield VulnerabilityView(classes="box", id="vulnerability-view")
        yield DataTable(classes="box", id="vulnerability-view")
        yield vectors
        yield states
        yield components
        yield issues
        yield Footer()

    def make_filters(self):
        # severity
        severities = "*", "critical", "high", "medium", "low"
        severity = OptionList(*severities,
                              name='severity', classes="box", id='filter-severity')
        severity.border_title = 'severity'
        severity.highlighted = severities.index(self.filters.get('severity') or 0)
        # vectors
        vector_options = ['*'] + list(sorted(self.bogrod._vectors()))
        vectors = OptionList(*vector_options,
                             name='vectors', classes="box", id='filter-vectors')
        vectors.border_title = 'vector'
        # state
        state_options = ['*'] + list(sorted(self.bogrod._states()))
        states = OptionList(*state_options,
                            name='states', classes="box", id='filter-states')
        states.border_title = 'state'
        # components/artifacts
        components = ['*'] + list(sorted(self.bogrod._components()))
        components = OptionList(*components,
                                name='components', classes="box", id='filter-components')
        components.border_title = 'component'
        # has issues
        issues = ['*', 'issues', 'no issues']
        issues = OptionList(*issues,
                            name='issues', classes="box", id='filter-issues')
        issues.border_title = 'issues'
        return severity, vectors, states, components, issues

    def make_vuln_view(self):
        table: DataTable
        initial = not hasattr(self, 'vuln_table')
        table = self.vuln_table = self.query_one('#vulnerability-view')
        table.cursor_type = 'row'
        self.filter_data()
        data = self.data
        cur = table.cursor_row
        table.clear()
        table.add_columns(*data[0].keys()) if initial else None
        table.add_rows(list(row.values()) for row in data)
        table.refresh()
        table.move_cursor(row=cur)
        return table

    @property
    def focus_chain(self):
        try:
            return [
                self.query_one('#filter-severity'),
                self.query_one('#filter-vectors'),
                self.query_one('#filter-states'),
                self.query_one('#filter-components'),
                self.query_one('#filter-issues'),
                self.query_one('#vulnerability-view'),
            ]
        except Exception as e:
            pass
        return []

    def filter_data(self, **kwargs):
        kwargs = kwargs or self.filters

        def setfilter(k):
            fv = kwargs.get(k, self.filters.get(k))
            return [fv] if (fv and fv != '*') else None

        report_filters = {
            'ids': setfilter('id'),
            'severities': setfilter('severity'),
            'vectors': setfilter('vector'),
            'columns': self.report_columns,
            'states': setfilter('state'),
            'components': setfilter('component'),
            'issues': (False if kwargs.get('issues') == 'no issues'
                       else True if kwargs.get('issues') == 'issues' else None),
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
        details_data = dict(
            id=vuln_id,
            severity=self.bogrod._vuln_severity(vuln),
            vector=self.bogrod._vuln_vector(vuln),
            description='\n# '.join(
                wrap(vuln.get('description', 'unknown'), subsequent_indent=' ' * 5)),
            component=tryOr(lambda: vuln['affects'][0]['ref'], 'n/a'),
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
                """).strip().format(**details_data)
        editor = VulnearabilityEditor(vex_data=vex[vuln_id],
                                      vuln_details=vuln_details,
                                      vex_schema=vex_schema,
                                      templates=self.bogrod.templates(),
                                      classes="editor")

        def on_dismiss(data):
            self.bogrod.vex[vuln['id']].update(data)
            self.bogrod.add_as_template(details_data['artifact'], data, match='artifact')
            self.bogrod.add_as_template(details_data['component'], data, match='component')
            self.on_mount()

        self.app.push_screen(editor, on_dismiss)

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
        with self.app.suspend():
            self.bogrod._work_vulnerability(vuln['id'], matches, all_vuln, vex_schema)

    def on_mount(self) -> None:
        self.title = 'bogrod'
        self.query_one('#vulnerability-view').focus()
        self.filter_data(**self.filters)
        self.make_vuln_view()

    def action_edit_vulnerability(self) -> None:
        self.edit_vulnerability(self.data[self.vuln_table.cursor_row]['id'])

    def action_focus_table(self) -> None:
        self.query_one('#vulnerability-view').focus()

    def action_focus_filter(self) -> None:
        self.query_one('#filter-severity').focus()

    def action_search(self) -> None:
        def on_dismiss(filter):
            self.filters['id'] = filter.strip()
            self.on_mount()

        self.app.push_screen(SearchModal(), on_dismiss)

    def xon_key(self, key) -> None:
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
        elif event.option_list.id == 'filter-components':
            self.log(f"****components {event.option.prompt}")
            self.filters['component'] = event.option.prompt
        elif event.option_list.id == 'filter-issues':
            self.log(f"****issues {event.option.prompt}")
            self.filters['issues'] = event.option.prompt
        else:
            return
        self.make_vuln_view()

