import argparse
import json
from pathlib import Path

import yaml
from tabulate import tabulate


class Bogrod:
    def __init__(self, data, notes=None):
        self.data = data
        self.notes = notes
        self.notes_path = None
        self.severities = ['critical', 'high']

    def vulnerabilities(self):
        return self.data.get('vulnerabilities', [])

    def read_notes(self, path):
        with open(path, 'r') as fin:
            self.notes = yaml.safe_load(fin)
        self.notes_path = path

    def update_notes(self, severities=None):
        assert self.notes, "no notes founds. use reno new to add"
        severities = severities or self.severities
        notes = self.security_notes()
        security = self.notes['security']
        sbom_vuln_ids = {}
        # for every vulnerability, add security item to release note
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            severity = vuln['ratings'][0]['severity']
            if vuln_id not in notes and severity in severities:
                security.append(f'{vuln_id} {severity} open')
            sbom_vuln_ids[vuln_id] = severity
        # set fixed status for security items in release notes but not in sbom
        for i, vuln in enumerate(list(security)):
            vuln_id, severity, *_ = vuln.split(' ')
            if not '-' in vuln_id:
                # ignore entries other than valid vuln ids
                continue
            if vuln_id not in sbom_vuln_ids:
                security[i] = f'{vuln_id} {severity} fixed'

    def write_notes(self, path=None):
        assert self.notes, "no notes founds. use reno new to add"
        path = path or self.notes_path
        with open(path, 'w') as fout:
            yaml.safe_dump(self.notes, fout, default_style='|')

    def security_notes(self):
        notes = {}
        # build dict of notes id => comment
        if self.notes:
            for vuln in self.notes['security']:
                vuln_id, severity, *comment = vuln.split(' ')
                notes[vuln_id] = ' '.join(comment)
        return notes

    def report(self, format='table', stream=None, severities=None):
        notes = self.security_notes()
        data = []
        severities = severities or self.severities
        # build list of dict of each vulnerability
        for vuln in self.vulnerabilities():
            severity = vuln['ratings'][0]['severity']
            if severity not in severities:
                continue
            record = {
                'id': vuln['id'],
                'name': vuln['source']['name'],
                'severity': severity,
                'note': notes.get(vuln['id']),
            }
            data.append(record)
        if format == 'table':
            print(tabulate(data, headers="keys"), file=stream)
        elif format == 'json':
            print(json.dumps(data), file=stream)
        elif format == 'yaml':
            print(yaml.safe_dump(data), file=stream)
        else:
            for rec in data:
                print("{id:20} {severity:8} {note}".format(**rec))

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
    parser.add_argument('-w', '--write-notes',
                        action='store_true',
                        help='update notes according to sbom (add new, mark fixed)')
    args = parser.parse_args()
    bogrod = Bogrod.from_sbom(args.sbom)
    if args.notes:
        bogrod.read_notes(args.notes)
        bogrod.update_notes()
    if args.write_notes:
        bogrod.write_notes(args.notes)
    bogrod.report(format=args.output)

if __name__ == '__main__':
    main()



