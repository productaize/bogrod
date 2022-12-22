import json
from pathlib import Path

import yaml


class Bogrod:
    def __init__(self, data, notes=None):
        self.data = data
        self.notes = notes

    def vulnerabilities(self):
        return self.data.get('vulnerabilities', [])

    def read_notes(self, path):
        with open(path, 'r') as fin:
            self.notes = yaml.load(fin)

    def update_notes(self):
        assert self.notes, "no notes founds. use reno new to add"
        security = self.notes['security']
        sbom_vuln_ids = {}
        # for every vulnerability, add security item to release note
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            severity = vuln['ratings'][0]['severity']
            if vuln_id not in security:
                security.append(f'{vuln_id} {severity} open')
            sbom_vuln_ids[vuln_id] = severity
        # set fixed status for security items in release notes but not in sbom
        for i, vuln in enumerate(list(security)):
            vuln_id = vuln.split(' ', 1)[0]
            if vuln_id not in sbom_vuln_ids:
                severity = sbom_vuln_ids[vuln_id]
                security[i] = f'{vuln_id} {severity} fixed'

    @classmethod
    def from_sbom(cls, sbom_path, notes_path=None):
        with open(sbom_path, 'r') as fin:
            data = json.load(fin)
        bogrod = Bogrod(data)
        if notes_path is None:
            sbom_name = Path(sbom_path).name.replace('.json', '')
            notes_path = Path('releasenotes/notes').glob(f'{sbom_name}*.yaml')
        else:
            notes_path = Path(notes_path)
        if notes_path.exists():
            bogrod.read_notes(notes_path)
        return
