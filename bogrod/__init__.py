import argparse
import json
import jsonschema
import os
import subprocess
import yaml
from jsonschema.exceptions import ValidationError
from pathlib import Path
from tabulate import tabulate
from tempfile import NamedTemporaryFile
from textwrap import dedent, wrap

from bogrod.util import dict_merge, tabulate_data, tryOr


class Bogrod:
    """ Bogrod - utility to SBOM and VEX information

    Bogrod combines SBOM, VEX and release notes processing into a single tool.

    Usage:

        # read SBOM, vex records, notes specification
        bogrod = Bogrod.from_sbom('/path/to/sbom.json')
        bogrod.read_vex('/path/to/vex.yaml')
        bogrod.read_notes('/path/to/notes.yaml')

        # update notes from vex records
        bogrod.update_notes()
        bogrod.notes()

        # update 'analysis' section of sbom using vex records
        bogrod.update_vex()
        bogrod.write_vex()

        # vex.yaml
        <vulnerability-id>:
            detail: <text>
            response:
                - <response code>
            state: <state code>
            justification: <justification code>

        # notes.yaml
        ...
        security:
        - "<vulnerability id> <severity> <status>"
    """

    def __init__(self, data, notes=None, vex=None, grype=None):
        self.data = data
        self.notes = notes
        self.notes_path = None
        self.sbom_path = None
        self.severities = 'critical,high'.split(',')
        self.severities_order = 'critical,high,medium,low,none,unknown'.split(',')
        self.vex = vex or {}
        self.grype = grype or {}
        self.report_columns = 'id,name,severity,state,affects,url'.split(',')

    def vulnerabilities(self, as_dict=False, severities=None):
        vuln = self.data.get('vulnerabilities', [])
        severity_rank = lambda v: self.severities_order.index(self._vuln_severity(v))
        severity_rank_d = lambda d: severity_rank(d[1])
        severities = severities or self.severities
        if as_dict:
            vuln = {v['id']: v for v in vuln if self._vuln_severity(v) in severities}
            return dict(sorted(vuln.items(), key=severity_rank_d))
        return sorted(vuln, key=severity_rank)

    def _vuln_severity(self, v):
        return ([s.get('severity') for s in v['ratings'] if s.get('severity')] + ['unknown'])[0]

    def read_notes(self, path):
        with open(path, 'r') as fin:
            self.notes = yaml.safe_load(fin)
        self.notes_path = path

    def update_notes(self, severities=None):
        assert self.notes, "no release notes found. to add notes, use reno new"
        severities = severities or self.severities
        notes = self.security_notes()
        security = self.notes['security']
        sbom_vuln_ids = {}
        # for every vulnerability, add security item to release note
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            severity = self._vuln_severity(vuln)
            if vuln_id not in notes and severity in severities:
                security.append(f'{vuln_id} {severity} unknown')
            sbom_vuln_ids[vuln_id] = severity
        # update state from vex or due to missing
        # -- for vuln in release notes but not in sbom: fixed
        # -- for vuln in vex
        for i, vuln in enumerate(list(security)):
            vuln_id, severity, *state = vuln.split(' ')
            state, *comment = state
            comment = ' '.join(comment)
            if '-' not in vuln_id:
                # ignore entries other than valid vuln ids
                continue
            if vuln_id in self.vex:
                state = self.vex[vuln_id].get('state', state) or 'unknown'
                comment = self.vex[vuln_id].get('detail') or ''
            if vuln_id not in sbom_vuln_ids and not comment.startswith('fixed'):
                state = 'fixed'
                self.vex.setdefault(vuln_id, {})
                self.vex[vuln_id]['state'] = state
            security[i] = f'{vuln_id} {severity} {state} {comment}'

    def write_notes(self, path=None):
        assert self.notes, "no notes founds. use reno new to add"
        path = path or self.notes_path
        with open(path, 'w') as fout:
            print("Writing release notes: ", path)
            yaml.safe_dump(self.notes, fout, default_style='|')

    def write_vex(self, path, properties=None):
        # https://blog.adolus.com/a-deeper-dive-into-vex-documents
        assert self.vex, "no vex information found, call bogrod.update_vex() first"
        path = Path(path)
        if path.exists():
            # update sbom or write vex information as such
            if path.suffix == '.json':
                with open(path, 'r') as fin:
                    data = json.load(fin)
                    if data.get('bomFormat', '').lower() == 'cyclonedx':
                        all_vulns = {v['id']: v for v in data['vulnerabilities']}
                        for k, v in self.vex.items():
                            if k not in all_vulns:
                                continue
                            vuln = all_vulns[k]
                            vuln.setdefault('analysis', {})
                            vuln['analysis'].update(v)
                    else:
                        data = self.vex
                    if properties:
                        # FIXME this duplicates self.merge_properties
                        dict_merge(data, properties)
                with open(path, 'w') as fout:
                    print("Writing vex: ", path)
                    json.dump(data, fout, indent=2)
            elif path.suffix == '.yaml':
                data = self.vex
                with open(path, 'w') as fout:
                    print("Writing vex: ", path)
                    yaml.safe_dump(data, fout)
        else:
            with open(path, 'w') as fout:
                print("Writing vex: ", path)
                if path.suffix == '.json':
                    json.dump(self.vex, fout, indent=2)
                elif path.suffix == '.yaml':
                    yaml.safe_dump(self.vex, fout)

    def security_notes(self):
        notes = {}
        # build dict of notes id => comment
        if self.notes:
            for vuln in self.notes['security']:
                vuln_id, severity, *comment = vuln.split(' ')
                state, *comment = comment
                notes[vuln_id] = {
                    'comment': ' '.join(comment),
                    'state': state,
                    'severity': severity,
                }
        return notes

    def read_grype(self, path):
        with open(path, 'r') as fin:
            print("Reading grype: ", path)
            self.grype = json.load(fin)
        return self.grype

    def read_vex(self, path):
        try:
            with open(path, 'r') as fin:
                print("Reading vex: ", path)
                self.vex = yaml.safe_load(fin)
        except:
            print(f"WARNING: could not read --vex-file {path}. Specify -x to create from sbom")
            self.vex = {}

    def update_vex(self):
        # https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json
        notes = self.security_notes()
        self.vex = all_vex = self.vex
        self.vex = self.notes.get('security-vex', {}) if self.vex is None and self.notes else self.vex
        ensure_list = lambda v: v if isinstance(v, list) else v.split(',')
        ensure_no_empty = lambda l: [e for e in l if e]
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            vex = all_vex.get(vuln_id, {})
            note = notes[vuln_id] if vuln_id in notes else {}
            analysis = vuln.setdefault('analysis', {})
            analysis['state'] = vex.get('state') or note.get('state') or analysis.get('state', 'in_triage')
            analysis['detail'] = vex.get('detail', note.get('comment', ''))
            analysis['response'] = ensure_no_empty(ensure_list(vex.get('response') or []))
            analysis['justification'] = vex.get('justification')
            if not analysis['justification']:
                # sbom-1.4 requires a valid value, or element not present
                del analysis['justification']
            all_vex.setdefault(vuln_id, {})
            all_vex[vuln_id].update(analysis)
            related = vex.setdefault('related', {})
            related['component'] = self.data.get('metadata', {}).get('component', {}).get('name')
            # remove vex information that is not supported by the standard
            if 'related' in vuln['analysis']:
                del vuln['analysis']['related']
            if 'resources' in vuln['analysis']:
                del vuln['analysis']['resources']
        self.validate()
        return self.vex

    def _generate_report_data(self, severities=None, columns=None):
        notes = self.security_notes()
        data = []
        severities = severities or self.severities
        columns = columns or self.report_columns
        # build list of dict of each vulnerability
        for vuln in self.vulnerabilities():
            severity = self._vuln_severity(vuln)
            if severity not in severities:
                continue
            description = vuln.get('description', ' ')
            short = description[0:min(len(description), 40)]
            vex = notes.get(vuln['id']) or self.vex.get(vuln['id']) or {}
            record = {
                'id': vuln['id'],
                'name': vuln['source']['name'],
                'severity': severity,
                'state': vex.get('state'),
                'justification': vex.get('justification'),
                'comment': vex.get('detail') or notes.get(vuln['id'], {}).get('comment'),
                'affects': vuln['affects'][0]['ref'].split('?')[0],
                'description': description,
                'short': short,
                'url': vuln['source'].get('url'),
            }
            record = {k: v for k, v in record.items() if k in columns}
            data.append(record)
        severity_rank = lambda v: self.severities.index(v['severity'])
        data = sorted(data, key=severity_rank)
        return data

    def report(self, format='table', stream=None, severities=None, columns=None, summary=False):
        data = self._generate_report_data(severities=severities, columns=columns)
        if summary:
            print("\nbogrod SBOM Summary Report\n")
            data, headers = tabulate_data(data, 'severity', ['state'])
        else:
            print("\nbogrod SBOM Report\n")
            headers = "keys"
        if format == 'table':
            print(tabulate(data, headers=headers), file=stream)
        elif format == 'json':
            print(json.dumps(data), file=stream)
        elif format == 'yaml':
            print(yaml.safe_dump(data), file=stream)
        else:
            for rec in data:
                print("{id:20} {severity:8} {note}".format(**rec))

    def _get_sbom_schema(self):
        schema_path = Path(__file__).parent / 'resources/bom-1.4.schema.json'
        with open(schema_path) as fin:
            schema = json.load(fin)
        return schema

    def _get_vex_schema(self):
        schema_path = Path(__file__).parent / 'resources/vex-1.0.schema.json'
        with open(schema_path) as fin:
            schema = json.load(fin)
        return schema

    def validate(self):
        schema = self._get_sbom_schema()
        try:
            jsonschema.validate(self.data, schema)
        except ValidationError as ex:
            print(f"ValidationError: {ex.message} {ex.absolute_path}")

    @classmethod
    def from_sbom(cls, sbom_path, notes_path=None):
        print("Reading sbom: ", sbom_path)
        with open(sbom_path, 'r') as fin:
            data = json.load(fin)
        bogrod = Bogrod(data)
        if notes_path is None:
            sbom_name = Path(sbom_path).name.replace('.json', '')
            candidates = list(Path('releasenotes/notes').glob(f'{sbom_name}*.yaml'))
            notes_path = candidates[0] if candidates else None
        else:
            notes_path = Path(notes_path)
        if notes_path and notes_path.exists():
            bogrod.read_notes(notes_path)
        return bogrod

    def merge_properties(self, prop_path, data=None):
        with open(prop_path) as fin:
            prop_data = yaml.safe_load(fin)
        data = data or self.data
        dict_merge(data, prop_data)
        return prop_data

    def grype_matches(self):
        """ return dict of grype matches by vulnerability id """
        matches = {}
        for match in self.grype.get('matches', []):
            vuln = match['vulnerability']
            vuln_id = vuln['id']
            matches[vuln_id] = match
        return matches

    def work(self, severities=None, issues=None, status=None, since=None):
        all_vuln = self.vulnerabilities(as_dict=True, severities=severities)
        matches = self.grype_matches()
        vex_schema = yaml.dump({
            k.lower(): '|'.join(v if v else '[]' for v in v.get('enum', ['<text>']))
            for k, v in self._get_vex_schema()['definitions'].items()
            if k.lower() in ['state', 'justification', 'response', 'detail']
        }).splitlines()
        clear = lambda: os.system("cls" if os.name == "nt" else "clear")
        in_triage = lambda: [i for i, v in enumerate(data) if v['state'] == 'in_triage']
        idx = None
        while True:
            data = self._generate_report_data(severities=severities)
            # get the first in_triage vulnerability
            if idx is None:
                idx = tryOr(lambda: in_triage()[0], 0)
            # get user's choice
            clear()
            print(tabulate(data, headers='keys', showindex=True))
            user_idx = input(f"Enter index to edit or q to exit: [{idx}] ")
            user_idx = user_idx or idx
            if user_idx == 'q':
                clear()
                break
            # process user's choice
            try:
                idx = int(user_idx)
                vuln_id = data[idx]['id']
            except Exception as e:
                print("input is invalid, try again.")
                continue
            self._work_vulnerability(vuln_id, matches, all_vuln, vex_schema)
            # move to next in_triage vulnerability
            idx = tryOr(lambda: [i for i in in_triage() if i > idx][0],
                        tryOr(lambda: in_triage()[0], 0))

    def _work_vulnerability(self, vuln_id, matches, all_vuln, vex_schema):
        vex = self.vex
        vuln = all_vuln[vuln_id]
        text = dedent("""
        # id: {id} 
        # severity: {severity} 
        # component: {component} 
        # artifact: {artifact}
        # fix: {fix}      
        # urls:   {url}
        # description: 
        #      {description}
        # locations: 
        #      {location}
        # fill in the following fields:
        # {vex_schema}
        {vex_yml}
        """).strip().format(id=vuln_id,
                            severity=self._vuln_severity(vuln),
                            description='\n# '.join(
                                wrap(vuln.get('description', 'unknown'), subsequent_indent=' ' * 5)),
                            component=tryOr(lambda: vex[vuln_id]['related']['component'], 'n/a'),
                            artifact=tryOr(lambda: (matches[vuln_id]['artifact'].get('name', '?') + '-' +
                                                    matches[vuln_id]['artifact'].get('version', '?')), 'n/a'),
                            url=tryOr(lambda: vuln['source']['url'], 'unknown'),
                            fix=tryOr(lambda: ';'.join(matches[vuln_id]['vulnerability']['fix']['versions']) +
                                              '(' + matches[vuln_id]['vulnerability']['fix']['state'] + ')', '?'),
                            location='\n#      '.join([v.get('path')
                                                       for v in tryOr(lambda: matches[vuln_id]['artifact']['locations'],
                                                                      [{'path': '<no grype json file>'}])]),
                            vex_yml=yaml.dump(vex[vuln_id]),
                            vex_schema='\n# '.join(
                                ''.join(wrap(l, initial_indent=' ' * 5,
                                             subsequent_indent=' ' * 5, break_long_words=False)) for l in vex_schema),
                            )
        with NamedTemporaryFile(mode='w', delete=False) as fout:
            fout.write(text)
        editor = os.environ.get('EDITOR', 'nano')
        while True:
            subprocess.run([editor, fout.name])
            try:
                with open(fout.name) as fin:
                    self.vex[vuln_id] = yaml.safe_load(fin)
            except Exception as e:
                print(f"invalid yaml, try again. {e}")
                input("press enter to continue...")
                continue
            else:
                os.unlink(fout.name)
                break


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('sbom',
                        help='/path/to/cyclonedx-sbom.json')
    parser.add_argument('-n', '--notes',
                        help='/path/to/notes.yaml')
    parser.add_argument('-o', '--output', default='table',
                        help='output format [table,json,yaml,raw]')
    parser.add_argument('-S', '--summary', action='store_true',
                        help='summarize report')
    parser.add_argument('-s', '--severities', default='critical,high',
                        help='list of serverities in critical,high,medium,low')
    parser.add_argument('-x', '--update-vex', action='store_true',
                        help='update vex information in sbom')
    parser.add_argument('--vex-file',
                        help='/path/to/vex.yaml')
    parser.add_argument('-p', '--sbom-properties',
                        help='Merge sbom with information in /path/to/properties.yaml')
    parser.add_argument('-m', '--merge-vex', action='store_true', default=True,
                        help='Merge vex data back to sbom')
    parser.add_argument('-w', '--write-notes',
                        action='store_true',
                        help='update notes according to sbom (add new, mark fixed)')
    parser.add_argument('-W', '--work',
                        action='store_true',
                        help='work each vulnerability')
    parser.add_argument('-g', '--grype',
                        help='/path/to/grype.json')
    args = parser.parse_args()
    bogrod = Bogrod.from_sbom(args.sbom)

    def write_vex_merge(vex_file):
        bogrod.write_vex(vex_file)
        if args.merge_vex:
            prop_data = None
            if args.sbom_properties:
                prop_data = bogrod.merge_properties(args.sbom_properties)
            bogrod.write_vex(args.sbom, properties=prop_data)

    if not args.grype:
        grype_file = Path(args.sbom).parent / (Path(args.sbom).stem + '-grype.json')
        if grype_file.exists():
            print("Found grype file: ", grype_file)
            args.grype = grype_file
    if args.severities:
        bogrod.severities = args.severities.split(',')
    if args.vex_file:
        bogrod.read_vex(args.vex_file)
    if args.notes:
        bogrod.read_notes(args.notes)
        bogrod.update_notes()
    if args.write_notes:
        bogrod.write_notes(args.notes)
    if args.grype:
        bogrod.read_grype(args.grype)
    if args.update_vex:
        vex_file = args.vex_file or args.sbom
        bogrod.update_vex()
        write_vex_merge(vex_file)
    if args.work:
        vex_file = args.vex_file or args.sbom
        bogrod.work()
        write_vex_merge(vex_file)
    bogrod.report(format=args.output, summary=args.summary)


if __name__ == '__main__':
    main()
