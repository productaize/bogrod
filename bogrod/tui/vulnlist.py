import webbrowser
from collections import Counter
from textwrap import wrap, dedent

import yaml
from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header, Footer, OptionList, Markdown

from bogrod.tui import VulnearabilityEditor
from bogrod.tui.widgets.modals import SearchModal, HelpableMixin
from bogrod.tui.widgets.multitable import MultiSelectDataTable
from bogrod.util import tryOr


class VulnerabilityList(HelpableMixin, Screen):
    BINDINGS = [
        Binding(key="enter", action='edit_vulnerability', description="edit", priority=True, show=True),
        Binding(key="q", action='quit', description="quit", priority=True, show=True),
        Binding(key="?", action='help', description="help", priority=True, show=True),
        Binding(key="l,L", action='focus_table', description="go to list of vulnerabilities", show=True),
        Binding(key='f,F', action='focus_filter', description='go to filters', show=True),
        Binding(key='v,V', action='browse_url', description='browse CVE-related web page', show=True),
        Binding(key='/', action='search', description='search by different criteria', show=True),
    ]

    def __init__(self, *args, bogrod=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.bogrod = bogrod
        self.sub_title = self.bogrod.sbom_path
        self.report_columns = 'id,source,severity,state,vector,affects,url,issues'.split(',')
        self.all_data = self.bogrod.vulnerabilities(as_dict=True, severities='*')
        self.data = None
        self.filters = {
            'severity': '*',
            'vector': None,
            'state': None,
            'issues': None,
            'affects': None,
            'components': None,
            'source': None,
        }
        self.bogrod.severities = '*'
        self.filter_data()

    def compose(self) -> ComposeResult:
        yield Header()
        # yield VulnerabilitiesList(classes="box", id='filter-severity')
        severity, vectors, states, components, issues, scores = self.make_filters()
        yield severity
        yield Markdown("* summary\n * top", classes='box', id="vulnerability-summary")
        yield vectors
        yield states
        yield MultiSelectDataTable(classes="box", id="vulnerability-view")
        yield components
        yield issues
        yield scores
        yield Footer()

    def make_filters(self):
        # severity
        severities = "*", "critical", "high", "medium", "low"
        severity = OptionList(*severities,
                              name='severity', classes="box", id='filter-severity')
        severity.border_title = 'severity'
        severity.highlighted = severities.index(self.filters.get('severity') or '*')
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
        # scores
        scores = ['*'] + list(f'>{s}' for s in range(11))
        scores = OptionList(*scores,
                            name='scores', classes="box", id='filter-scores')
        scores.border_title = 'scores'
        return severity, vectors, states, components, issues, scores

    def reset_filters(self):
        """ reset all filters, no filters applied """
        # reset filters
        for k in self.filters:
            self.filters[k] = None
        # reset options
        for k in ['severity', 'vectors', 'states', 'components', 'issues', 'scores']:
            options: OptionList = self.query_one(f'#filter-{k}')
            options.highlighted = 0
            options.scroll_to_highlight(top=True)
        # clear selected rows
        self.vuln_table.clear_selected_rows()

    def make_vuln_view(self):
        # issues list
        table: MultiSelectDataTable
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

    def update_vuln_summary(self):
        # summary
        summary: Markdown
        summary = self.query_one('#vulnerability-summary')
        summary.border_title = 'summary'
        # prepare summary markdown
        # -- we create a table with the top 5 of each category, plus a total row
        # calculate the top 5 of each category
        by_severity = Counter([v['severity'] for v in self.data])
        by_component = Counter([v['affects'] for v in self.data])
        by_state = Counter([v['state'].split('*')[0] for v in self.data])
        by_issues = Counter([bool(v['issues']) for v in self.data])
        by_vector = Counter()
        for v in self.data:
            # vectors are in the format AV:N/AV:
            v = v['vector']
            by_vector.update(vv for vv in v.split('/') if vv.startswith('AV'))
        # -- top severity
        st = [k for k in ['critical', 'high', 'medium', 'low']]
        sv = [by_severity.get(k, 0) for k in ['critical', 'high', 'medium', 'low']]
        # -- state
        xt = ['issues'] + [k for k, _ in by_state.most_common(5)] + [''] * 5
        xv = [by_issues.get(True, False)] + [by_state.get(k) for k, v in by_state.most_common(5)] + [''] * 5
        # -- top component
        ct = [(k or '').split('/')[-1].split('@')[0] for k, _ in by_component.most_common(5)] + [''] * 5
        cv = [by_component.get(k) for k, v in by_component.most_common(5)] + [''] * 5
        # -- top vectors
        vt = [k for k, _ in by_vector.most_common(5)] + [''] * 5
        vv = [by_vector.get(k, '') for k in vt] + [''] * 5
        # create a table
        markdown = (
            '| By Priority | # | State | # | Component | # | Vector    | # |\n'
            '|-------------|--:|-------|--:|-----------|--:|-----------|--:|\n'
        )
        # -- add each data row
        for i in range(4):
            markdown += f"| {st[i]} | {sv[i]:>4} | {xt[i]} | {xv[i]:>4} | {ct[i]} | {cv[i]:>4} | {vt[i]} | {vv[i]:>4} |\n"
        # -- add the total row
        markdown += f"| ----- |  |  |  |  |  |  |  |\n"
        markdown += f"| Total | {len(self.data)} |  |  |  |  |  |  |\n"
        self.log(f'summary updated {markdown}')
        summary.update(dedent(markdown))

    @property
    def focus_chain(self):
        # order of focus traversal by the TAB key
        try:
            return [
                self.query_one('#filter-severity'),
                self.query_one('#filter-vectors'),
                self.query_one('#filter-states'),
                self.query_one('#filter-components'),
                self.query_one('#filter-issues'),
                self.query_one('#filter-scores'),
                self.query_one('#vulnerability-view'),
            ]
        except Exception as e:
            pass
        return []

    def filter_data(self, **kwargs):
        kwargs = kwargs or self.filters

        def setfilter(k):
            fv = kwargs.get(k) or self.filters.get(k)
            fv = [fv] if (fv and fv != '*') else None
            return fv

        report_filters = {
            'ids': setfilter('id'),
            'severities': setfilter('severity'),
            'vectors': setfilter('vector'),
            'columns': self.report_columns,
            'states': setfilter('state'),
            'affects': setfilter('affects'),
            'components': setfilter('component'),
            'scores': setfilter('score'),
            'names': setfilter('source'),
            'issues': (False if kwargs.get('issues') == 'no issues'
                       else True if kwargs.get('issues') == 'issues' else None),
        }
        self.log(f'filter_data {self.filters=} => {report_filters=}')
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
        vex_data = vex.setdefault(vuln_id, {})
        matches = self.bogrod.grype_matches()
        details_data = dict(
            id=vuln_id,
            severity=self.bogrod._vuln_severity(vuln),
            score=self.bogrod._vuln_score(vuln),
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
                # score: {score}
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
        editor = VulnearabilityEditor(vex_data=vex_data,
                                      vuln_data=details_data,
                                      vuln_details=vuln_details,
                                      vex_schema=vex_schema,
                                      templates=self.bogrod.templates(),
                                      classes="editor")

        def on_dismiss(data):
            # update current vulnerability
            self.bogrod.vex[vuln['id']].update(data)
            self.bogrod.add_as_template(details_data['artifact'], data, match='artifact')
            self.bogrod.add_as_template(details_data['component'], data, match='component')
            # update all cells selected for bulk update
            for row_index in self.vuln_table.selected_rows:
                vuln_id = self.data[row_index]['id']
                self.bogrod.vex.setdefault(vuln_id, {})
                vex[vuln_id].update(data)
            # refresh
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
        self.make_vuln_view()
        self.update_vuln_summary()
        self.query_one('#vulnerability-view').focus()

    def action_edit_vulnerability(self) -> None:
        self.edit_vulnerability(self.data[self.vuln_table.cursor_row]['id'])

    def action_focus_table(self) -> None:
        self.query_one('#vulnerability-view').focus()

    def action_focus_filter(self) -> None:
        self.query_one('#filter-severity').focus()

    def action_browse_url(self):
        vuln_id = self.data[self.vuln_table.cursor_row]['id']
        url = [v['url'] for v in self.data if v['id'] == vuln_id][0]
        webbrowser.open(url)

    def action_search(self) -> None:
        def on_dismiss(filter):
            if filter == '.cancel':
                return
            elif not filter:
                self.reset_filters()
            elif ':' in filter:
                k, v = filter.split(':', 1)
                if k not in self.filters:
                    # select the first key that matches the prefix
                    # -- default to 'id'
                    k = ([kk for kk in self.filters if kk.startswith(k)] + ['id'])[0]
                self.filters[k] = v.strip()
                self.log(self.filters)
            else:
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
        elif event.option_list.id == 'filter-scores':
            self.log(f"****scores {event.option.prompt}")
            lowest_score = int(event.option.prompt.replace('>', '')) if event.option.prompt != '*' else None
            self.filters['score'] = lowest_score
        else:
            return
        if not self.app._batch_count:
            # prevent update on initial compose and layout refresh
            self.make_vuln_view()
            self.update_vuln_summary()

    @property
    def related_screens(self):
        return self, self.vuln_table

    @property
    def help_text(self):
        return """
        * **Purpose** 

          This page lists all the vulnerabilities found in the SBOM. Filter the list using 
          the criteria boxes on the left, focus by pressing F. To search for a specific 
          vulnerability, press / and type the id or any other criteria (see below).

        * **Searching**

          Press / to search by different criteria, e.g. `id:1234`, `severity:high` or 
          'affects:python'. The list is updated once you press Enter. To reset all filters,
          press / and then Enter. 

        * **Summary statistics**

          The statistics are updated as you filter the list. The top 5 of each category are shown.
        """
