import argparse
import json
import jsonschema
import yaml
from jsonschema.exceptions import ValidationError
from pathlib import Path
from tabulate import tabulate


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
    def __init__(self, data, notes=None, vex=None):
        self.data = data
        self.notes = notes
        self.notes_path = None
        self.severities = 'critical,high'.split(',')
        self.vex = vex or {}
        self.report_columns = 'id,name,severity,state,affects,url'.split(',')

    def vulnerabilities(self, as_dict=False):
        vuln = self.data.get('vulnerabilities', [])
        if as_dict:
            vuln = { v['id']: v for v in vuln }
        return vuln

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
            severity = vuln['ratings'][0]['severity']
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
            yaml.safe_dump(self.notes, fout, default_style='|')

    def write_vex(self, path):
        # https://blog.adolus.com/a-deeper-dive-into-vex-documents
        assert self.vex, "no vex information found, call bogrod.update_vex() first"
        path = Path(path)
        if path.exists():
            # update sbom or write vex information as such
            if path.suffix == '.json':
                with open(path, 'r') as fin:
                    data = json.load(fin)
                    if data.get('bomFormat').lower() == 'cyclonedx':
                        all_vulns = {v['id']: v for v in data['vulnerabilities']}
                        for k, v in self.vex.items():
                            if k not in all_vulns:
                                continue
                            vuln = all_vulns[k]
                            vuln.setdefault('analysis', {})
                            vuln['analysis'].update(v)
                    else:
                        data = self.vex
                with open(path, 'w') as fout:
                    json.dump(data, fout, indent=2)
            elif path.suffix == '.yaml':
                data = self.vex
                with open(path, 'w') as fout:
                    yaml.safe_dump(data, fout)
        else:
            with open(path, 'w') as fout:
                json.dump(self.vex, fout, indent=2)

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

    def read_vex(self, path):
        with open(path, 'r') as fin:
            self.vex = yaml.safe_load(fin)

    def update_vex(self):
        # https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json
        notes = self.security_notes()
        self.vex = all_vex = self.vex or self.notes.get('security-vex', {})
        ensure_list = lambda v: v if isinstance(v, list) else v.split(',')
        ensure_no_empty = lambda l: [e for e in l if e]
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            vex = all_vex.get(vuln_id, {})
            note = notes[vuln_id] if vuln_id in notes else {}
            analysis = vuln['analysis']
            analysis['state'] = vex.get('state') or note.get('state') or analysis['state']
            analysis['detail'] = vex.get('detail', note.get('comment', ''))
            analysis['response'] = ensure_no_empty(ensure_list(vex.get('response') or []))
            analysis['justification'] = vex.get('justification')
            if not analysis['justification']:
                # sbom-1.4 requires a valid value, or element not present
                del analysis['justification']
            all_vex.setdefault(vuln_id, {})
            all_vex[vuln_id].update(analysis)
        self.validate()
        return self.vex

    def report(self, format='table', stream=None, severities=None, columns=None):
        notes = self.security_notes()
        data = []
        severities = severities or self.severities
        columns = columns or self.report_columns
        # build list of dict of each vulnerability
        for vuln in self.vulnerabilities():
            severity = vuln['ratings'][0]['severity']
            if severity not in severities:
                continue
            description = vuln.get('description', ' ')
            short = description[0:min(len(description), 40)]
            record = {
                'id': vuln['id'],
                'name': vuln['source']['name'],
                'severity': severity,
                'state': notes.get(vuln['id'], {}).get('state'),
                'comment': notes.get(vuln['id'], {}).get('comment'),
                'affects': vuln['affects'][0]['ref'].split('?')[0],
                'description': description,
                'short': short,
                'url': vuln['source'].get('url'),
            }
            record = {k: v for k, v in record.items() if k in columns}
            data.append(record)
        severity_rank = lambda v: self.severities.index(v['severity'])
        data = sorted(data, key=severity_rank)
        if format == 'table':
            print(tabulate(data, headers="keys"), file=stream)
        elif format == 'json':
            print(json.dumps(data), file=stream)
        elif format == 'yaml':
            print(yaml.safe_dump(data), file=stream)
        else:
            for rec in data:
                print("{id:20} {severity:8} {note}".format(**rec))

    def validate(self):
        schema_path = Path(__file__).parent / 'resources/bom-1.4.schema.json'
        with open(schema_path) as fin:
            schema = json.load(fin)
            try:
                jsonschema.validate(self.data, schema)
            except ValidationError as ex:
                print(f"ValidationError: {ex.message} {ex.absolute_path}")

    @classmethod
    def from_sbom(cls, sbom_path, notes_path=None):
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('sbom',
                        help='/path/to/cyclonedx-sbom.json')
    parser.add_argument('-n', '--notes',
                        help='/path/to/notes.yaml')
    parser.add_argument('-o', '--output', default='table',
                        help='output format [table,json,yaml,raw]')
    parser.add_argument('-s', '--severities', default='critical,high',
                        help='list of serverities in critical,high,medium,low')
    parser.add_argument('-x', '--update-vex', action='store_true',
                        help='update vex information in sbom')
    parser.add_argument('--vex-file',
                        help='/path/to/vex.yaml')
    parser.add_argument('-m', '--merge-vex', action='store_true', default=True,
                        help='Merge vex data back to sbom')
    parser.add_argument('-w', '--write-notes',
                        action='store_true',
                        help='update notes according to sbom (add new, mark fixed)')
    args = parser.parse_args()
    bogrod = Bogrod.from_sbom(args.sbom)
    if args.severities:
        bogrod.severities = args.severities.split(',')
    if args.vex_file:
        bogrod.read_vex(args.vex_file)
    if args.notes:
        bogrod.read_notes(args.notes)
        bogrod.update_notes()
    if args.write_notes:
        bogrod.write_notes(args.notes)
    if args.update_vex:
        vex_file = args.vex_file or args.sbom
        bogrod.update_vex()
        bogrod.write_vex(vex_file)
        if args.merge_vex:
            bogrod.write_vex(args.sbom)
    bogrod.report(format=args.output)


if __name__ == '__main__':
    main()
