import json
from pathlib import Path


class Bogrod:
    def __init__(self, data, notes=None):
        self.data = data
        self.notes = notes

    def vulnerabilities(self):
        return self.data.get('vulnerabilities', {})

    def read_notes(self, path):
        with open(path, 'r') as fin:
            self.notes = json.load(fin)

    @classmethod
    def from_sbom(cls, sbom_path, notes_path=None):
        notes_path = notes_path or Path(Path(sbom_path).name.replace('.json', '.notes.json'))
        with open(sbom_path, 'r') as fin:
            data = json.load(fin)
        bogrod = Bogrod(data)
        if notes_path.exists():
            bogrod.read_notes(notes_path)
        return
