import argparse
import json
import os
import re
import subprocess
import sys
from configparser import ConfigParser
from copy import deepcopy
from pathlib import Path
from tempfile import NamedTemporaryFile
from textwrap import dedent, wrap
from uuid import uuid4

import jsonschema
import keyring
import yaml
from jsonschema.exceptions import ValidationError
from tabulate import tabulate

from bogrod import contrib
from bogrod.sbom import CycloneDXSBOM
from bogrod.util import dict_merge, tabulate_data, tryOr, SafeNoAliasDumper


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
            related:
                - component: component-name
            history:
                - <new|resolved|unchanged>: component-name

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
        self.severities = 'critical,high,medium,low,none,unknown'.split(',')
        self.severities_order = 'critical,high,medium,low,none,unknown'.split(',')
        self.vex = vex or {}
        self.grype = grype or {}
        self.report_columns = 'id,name,severity,state,vector'.split(',')
        self.diff_data = {}

    def vulnerabilities(self, as_dict=False, severities=None, ordered=False):
        vuln = self.data.get('vulnerabilities', [])
        severity_rank = lambda v: self.severities_order.index(self._vuln_severity(v))
        severity_rank_d = lambda d: severity_rank(d[1])
        severities = severities or self.severities
        if as_dict:
            vuln = {v['id']: v for v in vuln
                    if (self._vuln_severity(v) in severities)
                    or (severities in ('*', 'all'))}
            return dict(sorted(vuln.items(), key=severity_rank_d))
        return vuln if not ordered else sorted(vuln, key=severity_rank)

    def _vectors(self, severities=None):
        severities = severities or self.severities
        flatten = lambda l: [x for xs in l for x in xs if x]
        return set(flatten([self._vuln_vector(v).split('/') for v in self.vulnerabilities(severities=severities)]))

    def _states(self):
        return set([v.get('state', 'unknown') for k, v in self.vex.items() if k != 'templates'])

    def _components(self, severities=None):
        return set(vv['ref'].split('/')[-1].split('@')[0] for v in self.vulnerabilities(severities=severities) for vv in
                   v.get('affects', []))

    def _vuln_severity(self, v):
        return ([s.get('severity') for s in v['ratings'] if s.get('severity')] + ['unknown'])[0]

    def _vuln_vector(self, v):
        matches = self.grype_matches()
        vector = tryOr(lambda: v['ratings'][0]['vector'], '')
        vector = vector or tryOr(lambda: matches[v['id']]['cvss'][0]['vector'], '')
        vector = vector or tryOr(lambda: matches[v['id']]['relatedVulnerabilities'][0]['cvss'][0]['vector'], '')
        return vector

    def add_as_template(self, key, data, match='all'):
        # todo move to vex class
        templates = self.vex.setdefault('templates', {})
        entry = templates.setdefault(key, {})
        entry.update(data)
        entry['match'] = match
        return templates

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
                if self.data.get('bomFormat', '').lower() == 'cyclonedx':
                    data = self.data
                    self.validate(data)
                    self.fix_metadata()
                else:
                    data = self.vex
                if properties:
                    # FIXME this duplicates self.merge_properties
                    dict_merge(data, properties)
                with open(path, 'w') as fout:
                    print("Writing vex to sbom: ", path)
                    json.dump(data, fout, indent=2)
            elif path.suffix == '.yaml':
                data = self.vex
                with open(path, 'w') as fout:
                    print("Writing vex to yaml: ", path)
                    yaml.dump_all([data], fout, Dumper=SafeNoAliasDumper)
        else:
            with open(path, 'w') as fout:
                print("Writing vex to json: ", path)
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
        for k, v in self.vex.items():
            if k == 'templates':
                continue
            if 'state' not in v:
                v['state'] = 'in_triage'
        return self.vex

    def templates(self):
        return self.vex.get('templates', {})

    def read_vex_issues(self, path):
        if not Path(path).exists():
            return
        with open(path, 'r') as fin:
            print("Reading vex issues: ", path)
            vex_issues = self.vex_issues = yaml.safe_load(fin)
            if 'report' not in vex_issues:
                status = vex_issues.get('status')
                sbomId = vex_issues.get('id')
                print(f"WARNING: vex issues report does not contain 'report' key. Id: {sbomId} Status: {status}")
            else:
                report_vulns = vex_issues['report']['vulnerabilities']
                sbom_vulns = self.vulnerabilities(as_dict=True, severities='*')
                related = self.grype_related()
                for vuln in report_vulns:
                    # process each vulnerability in the vex issues report
                    vuln_id = vuln['id']
                    new_issues = vuln.get('issues', [])
                    reportedSeverity = vuln['highestSeverity']
                    vex = self.vex.setdefault(vuln_id, {})
                    report = vex.setdefault('report', {})
                    report.update({
                        'issues': new_issues,
                        'severity': reportedSeverity
                    })
                    # check that the sbom has a matching vulnerability
                    if vuln_id not in sbom_vulns:
                        if vuln_id in related:
                            # append the reported vulnerability to the sbom
                            # -- take the first related vulnerability as the origin
                            related_vuln_id = related[vuln_id]['origins'][0]
                            self.add_vulnerability_from(vuln_id, related_vuln_id)
                        else:
                            self.add_vulnerability(vuln_id, name=None, description=None, severity=reportedSeverity, url=None)
            return vex_issues

    def add_vulnerability(self, vuln_id, name, description, severity, url):
        vuln = {
            'id': vuln_id,
            'bom-ref': uuid4().urn,
            'description': description or '(unknown, reported from bogrod)',
            'source': {
                'name': name or '(unknown, reported from bogrod)',
                'url': url or f'https://nvd.nist.gov/vuln/detail/{vuln_id}',
            },
            'ratings': [
                {
                    'vector': '',
                    'severity': severity,
                }
            ],
            'affects': [
            ],
            'advisories': [
            ],
            'analysis': {
                'state': 'in_triage',
                'detail': '',
                'response': [],
            },
        }
        self.data['vulnerabilities'].append(vuln)
        return vuln

    def add_vulnerability_from(self, vuln_id, origin_vuln_id, sbom_vulns=None):
        # -- copy the origin vulnerability and update the id
        sbom_vulns = sbom_vulns or self.vulnerabilities(as_dict=True, severities='*')
        origin_vuln: dict = sbom_vulns[origin_vuln_id]
        new_vuln = deepcopy(origin_vuln)
        new_vuln['id'] = vuln_id
        new_vuln['bom-ref'] = uuid4().urn
        references = new_vuln.setdefault('references', [])
        references.append({
            'id': origin_vuln_id,
            'source': dict(origin_vuln['source'])
        }) if origin_vuln_id not in [r['id'] for r in references] else None
        # reset analysis
        # TODO it's the same vuln, why reset?
        # new_vuln["analysis"] = {
        #     "state": "in_triage",
        #     "detail": "",
        #     "response": []
        # }
        # -- add the new vulnerability to the sbom
        self.data['vulnerabilities'].append(new_vuln)
        # -- add the new vex entry
        related_vex = self.vex.setdefault(origin_vuln_id, {})
        new_vex = self.vex.setdefault(vuln_id, deepcopy(related_vex))
        byref = {
            'byref': origin_vuln_id,
        }
        new_vex_related = new_vex.setdefault('related', [])
        new_vex_related.append(byref) if byref not in new_vex_related else None
        # -- reference the new vuln in vex
        related_info = {'reportas': vuln_id}
        new_vex_related.append(related_info) if related_info not in new_vex_related else None
        return new_vex

    def fix_metadata(self):
        # fix metadata.component from container image tag
        # -- check if we have a name like repo.domain/image:tag
        # -- if yes, parse into proper .name=image .version=tag
        #    and add original component data to the metadata .components list
        #    https://cyclonedx.org/docs/1.4/json/#metadata_component_components
        #    this seems the most appropriate location in order to keep the original
        meta = self.data['metadata']
        comp = meta['component']
        raw_comp = deepcopy(comp)
        fixed = False
        if comp['type'] == 'container':
            # use image last-level/basename, not full repo path
            # -- eg. repo.company.com/app/nginx:latest => .name=app/nginx:latest
            #        nginx:latest => .name=nginx:latest
            if '/' in comp['name']:
                comp['name'] = '/'.join(comp['name'].split('/')[-2:])
                fixed = True
            # use image tag as the version
            # -- e.g. app/nginx:latest => .name=app/nginx, .version=latest
            # -- rationale: by default syft/grype use name=image tag, version=image id/sha
            #               so we'd get .name=app/nginx:latest .version=sha256:...
            if ':' in comp['name']:
                comp['name'], comp['version'] = comp['name'].split(':')
                fixed = True
            if fixed:
                # check if we have previously fixed this
                compnts = comp.setdefault('components', [])
                bom_refs = {v.get('bom-ref') for v in compnts}
                top_level = raw_comp['bom-ref'].split('sbom:')[-1]
                if top_level not in bom_refs:
                    compnts.append(raw_comp)
                comp['bom-ref'] = f'sbom:{top_level}'

    def update_vex(self):
        # https://github.com/CycloneDX/bom-examples/blob/master/VEX/vex.json
        notes = self.security_notes()
        self.vex = all_vex = self.vex
        self.vex = self.vex if self.vex is not None and not self.notes else self.notes.get('security-vex', {})
        ensure_list = lambda v: v if isinstance(v, list) else v.split(',')
        ensure_no_empty = lambda l: [e for e in l if e]
        component = {'component': self.data.get('metadata', {}).get('component', {}).get('name')}
        for vuln in self.vulnerabilities():
            vuln_id = vuln['id']
            vex = all_vex.setdefault(vuln_id, {})
            note = notes[vuln_id] if vuln_id in notes else {}
            analysis = vuln.setdefault('analysis', {})
            analysis['state'] = vex.get('state') or note.get('state') or analysis.get('state', 'in_triage')
            analysis['detail'] = vex.get('detail', note.get('comment', ''))
            analysis['response'] = ensure_no_empty(ensure_list(vex.get('response') or []))
            analysis['justification'] = vex.get('justification')
            # -- adjust for sbom-1.4 compliance
            if not analysis['justification']:
                # sbom-1.4 requires a valid value, or element not present
                del analysis['justification']
            # -- remove sbom vex information that is not supported by the standard
            if 'related' in vuln['analysis']:
                del vuln['analysis']['related']
            if 'resources' in vuln['analysis']:
                del vuln['analysis']['resources']
            # track vex related info to vulnerability's sbom component
            vex.update(analysis)
            # -- component
            related = vex.setdefault('related', [])
            if related is None:
                vex['related'] = related = []
            if isinstance(related, dict):
                related = vex['related'] = [{k: v} for k, v in related.items()]
                vex['related'] = related
            if component not in related:
                related.append(dict(component))
        # -- record history of changes in vex
        for vuln_id, vex in all_vex.items():
            if vuln_id == 'templates':
                continue
            history = vex.setdefault('history', [])
            diff = self.diff_data.get(vuln_id) or 'added'
            diff_in = component['component']
            change = {diff: diff_in}
            if change not in history:
                history.append(change)

        self.validate()
        return self.vex

    def _generate_report_data(self, severities=None, columns=None, vectors=None, states=None, components=None,
                              issues=None, ids=None):
        notes = self.security_notes()
        data = []
        severities = severities or self.severities
        columns = columns or self.report_columns
        diff = self.diff_data
        # build list of dict of each vulnerability
        for vuln in self.vulnerabilities():
            severity = self._vuln_severity(vuln)
            vector = self._vuln_vector(vuln)
            if '*' not in severities and severity not in severities:
                continue
            if vector and vectors:
                pattern = '|'.join(v.strip() for v in vectors if v)
                if re.search(pattern, vector) is None:
                    continue
            if states and vuln['analysis']['state'] not in states:
                continue
            if components:
                pattern = '|'.join(c.strip() for c in components if c)
                affects = ';'.join(v['ref'] for v in vuln.get('affects', []))
                if re.search(pattern, affects) is None:
                    continue
            if ids and not any(k in vuln['id'] for k in ids):
                continue
            description = vuln.get('description', ' ')
            short = description[0:min(len(description), 40)]
            vex = notes.get(vuln['id']) or self.vex.get(vuln['id']) or {}
            issues_ind = '*' if vex.get('report', {}).get('issues') else ''
            if issues != '*' and issues and not issues_ind:
                continue
            record = {
                'id': vuln['id'],
                'name': vuln['source']['name'],
                'severity': severity,
                'state': vex.get('state', '') + issues_ind,
                'justification': vex.get('justification'),
                'comment': vex.get('detail') or notes.get(vuln['id'], {}).get('comment'),
                'affects': tryOr(lambda: vuln['affects'][0]['ref'].split('?')[0], None),
                'description': description,
                'short': short,
                'url': vuln['source'].get('url'),
                'change': diff.get(vuln['id']),
                'vector': self._vuln_vector(vuln),
            }
            record = {k: record[k] for k in columns}
            data.append(record)
        severity_rank = lambda v: self.severities_order.index(v['severity'])
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
        # TODO get the actual schema
        schema_path = Path(__file__).parent / 'resources/bom-1.5.schema.json'
        with open(schema_path) as fin:
            schema = json.load(fin)
        return schema

    def _get_vex_schema(self):
        schema_path = Path(__file__).parent / 'resources/vex-1.0.schema.json'
        with open(schema_path) as fin:
            schema = json.load(fin)
        return schema

    def validate(self, data=None):
        print("Validating sbom...")
        schema = self._get_sbom_schema()
        data = data or self.data
        try:
            jsonschema.validate(data, schema)
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

    def grype_related(self):
        related = {}
        for match in self.grype.get('matches', []):
            vuln_id = match['vulnerability']['id']
            for related_vuln in match.get('relatedVulnerabilities', []):
                related_id = related_vuln['id']
                entry = related.setdefault(related_id, {})
                entry['vulnerability'] = related_vuln
                origins = entry.setdefault('origins', [])
                origins.append(vuln_id) if vuln_id not in origins else None
        return related

    def work(self, severities=None, issues=None, status=None, since=None):
        all_vuln = self.vulnerabilities(as_dict=True, severities=severities)
        matches = self.grype_matches()
        vex_schema = yaml.dump({
            k.lower(): '|'.join(v if v else '[]' for v in v.get('enum', ['<text>']))
            for k, v in self._get_vex_schema()['definitions'].items()
            if k.lower() in ['state', 'justification', 'response', 'detail']
        }).splitlines()
        clear = lambda: os.system("cls" if os.name == "nt" else "clear")
        in_triage = lambda data: [i for i, v in enumerate(data) if v['state'].startswith('in_triage')]
        idx = None
        while True:
            data = self._generate_report_data(severities=severities)
            # get the first in_triage vulnerability
            if idx is None:
                idx = tryOr(lambda: in_triage(data)[0], 0)
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
            idx = tryOr(lambda: [i for i in in_triage(data) if i > idx][0],
                        tryOr(lambda: in_triage(data)[0], 0))

    def _work_vulnerability(self, vuln_id, matches, all_vuln, vex_schema):
        vex = self.vex
        vuln = all_vuln[vuln_id]
        text = dedent("""
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
        # fill in the following fields:
        # {vex_schema}
        {vex_yml}
        """).strip().format(id=vuln_id,
                            severity=self._vuln_severity(vuln),
                            vector=self._vuln_vector(vuln),
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
                with open(fout.name, 'a') as fin:
                    fin.write(f"# ERROR: {e}".replace('\n', ' '))
                continue
            else:
                os.unlink(fout.name)
                break

    def diff(self, other_sbomfile):
        current = CycloneDXSBOM(self.data)
        other = CycloneDXSBOM.from_file(other_sbomfile)
        self.diff_data = current.diff(other)

    def report_diff(self, stream=None):
        data = []
        vuln = self.vulnerabilities(as_dict=True)
        for vuln_id, diff_data in self.diff_data.items():
            data.append({
                'vuln_id': vuln_id,
                'change': diff_data['delta'],
                'description': diff_data['vuln']['affects'][0]
            })
        headers = 'keys'
        print(tabulate(data, headers=headers), file=stream)


def main(argv=None):
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
                        help='update vex information from sbom vulnerabilities')
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
    parser.add_argument('--tui',
                        action='store_true',
                        help='use tui')
    parser.add_argument('-g', '--grype',
                        help='use grype SBOM to match vulnerabilities at /path/to/grype.json')
    parser.add_argument('--diff',
                        help='/path/to/cyclonedx-sbom.json')
    parser.add_argument('--vex-issues',
                        help='/path/to/vex-issues.yaml')
    parser.add_argument('--upload',
                        help='specify target aggregator to upload sbom and get issues report')
    parser.add_argument('--upload-tentative', action='store_true',
                        help='if specified upload sbom as tentative')
    args = parser.parse_args(argv)

    def write_vex_merge(vex_file):
        bogrod.write_vex(vex_file)
        if args.merge_vex:
            prop_data = None
            if args.sbom_properties:
                prop_data = bogrod.merge_properties(args.sbom_properties)
            bogrod.write_vex(args.sbom, properties=prop_data)

    # load .bogrod ini file
    if Path('.bogrod').exists():
        config = ConfigParser()
        config.read('.bogrod')

        def update_args(section):
            args.vex = config[section].get('vex', args.vex_file)
            args.grype = config[section].get('grype', args.grype)
            args.sbom_properties = config[section].get('sbom_properties', args.sbom_properties)
            args.update_vex = config[section].getboolean('update_vex', args.update_vex)
            args.merge_vex = config[section].getboolean('merge_vex', args.merge_vex)
            args.write_notes = config[section].getboolean('write_notes', args.write_notes)
            args.work = config[section].getboolean('work', args.work)
            args.output = config[section].get('output', args.output)
            args.severities = config[section].get('severities', args.severities)
            args.summary = config[section].getboolean('summary', args.summary)
            args.notes = config[section].get('notes', args.notes)
            args.vex_file = config[section].get('vex_file', args.vex_file)
            args.vex_issues = config[section].get('vex_issues', args.vex_issues)
            if not Path(args.sbom).exists():
                args.sbom = config[section].get('sbom', args.sbom)
            args.upload = config[section].get('upload', args.upload)
            if args.upload and ':' in args.upload:
                args.upload, args.projectpath = args.upload.split(':')
            args.projectpath = config[section].get('projectpath') or getattr(args, 'projectpath', None)

        update_args('global') if 'global' in config.sections() else None
        if 'aggregators' in config.sections():
            args.aggregators = config['aggregators']
        if args.sbom in config.sections():
            update_args(args.sbom)
        elif not Path(args.sbom).exists():
            print(f"{args.sbom} does not exist and not found in .bogrod file. Available: {','.join(config.sections())}")
            exit(1)

    # find default files
    # -- grype
    if not args.grype:
        grype_file = Path(args.sbom).parent / (Path(args.sbom).stem.replace('.cdx', '') + '.grype.json')
        if grype_file.exists():
            print("Found grype file: ", grype_file)
            args.grype = grype_file
    # -- vex
    if not args.vex_file:
        vex_file1 = Path(args.sbom).parent / (Path(args.sbom).stem.replace('.cdx', '') + '.vex.yaml')
        vex_file2 = Path(args.sbom).parent / 'vex.yaml'
        if vex_file1.exists():
            print("Found vex file: ", vex_file1)
            args.vex_file = vex_file1
            args.update_vex = True
            args.merge_vex = True
        elif vex_file2.exists():
            print("Found vex file: ", vex_file2)
            args.vex_file = vex_file2
            args.update_vex = True
            args.merge_vex = True
        else:
            print("Assuming vex file: ", vex_file2)
            args.vex_file = vex_file2
            args.update_vex = True
            args.merge_vex = True
    # -- vex issues report from aggregator (e.g. essentx)
    if not args.vex_issues:
        vex_issues_file = Path(args.sbom).parent / (Path(args.sbom).stem.replace('.cdx', '') + '.vexiss.yaml')
        args.vex_issues = vex_issues_file
        if vex_issues_file.exists():
            print("Found vex issues: ", vex_issues_file)
    # -- properties
    if not args.sbom_properties:
        prop_file = Path(args.sbom).parent / 'sbom-metadata.yaml'
        if prop_file.exists():
            print("Found sbom properties file: ", prop_file)
            args.sbom_properties = prop_file
    # -- release notes
    if not args.notes:
        notes_file = Path(args.sbom).parent.parent / 'notes' / (Path(args.sbom).stem + '.yaml')
        if notes_file.exists():
            print("Found release notes: ", notes_file)
            args.notes = notes_file

    # process
    bogrod = Bogrod.from_sbom(args.sbom)
    if args.severities:
        if args.severities == 'all':
            args.severities = 'critical,high,medium,low,none,unknown'
        bogrod.severities = args.severities.split(',')
    if args.notes:
        bogrod.read_notes(args.notes)
        bogrod.update_notes()
    if args.write_notes:
        bogrod.write_notes(args.notes)
    if args.grype:
        bogrod.read_grype(args.grype)
    if args.diff:
        bogrod.diff(args.diff)
        if not args.work:
            bogrod.report_diff()
            exit(0)
    if args.vex_file:
        bogrod.read_vex(args.vex_file)
    if args.vex_issues:
        bogrod.read_vex_issues(args.vex_issues)
    if args.update_vex:
        vex_file = args.vex_file or args.sbom
        bogrod.update_vex()
        write_vex_merge(vex_file)
    if args.upload:
        AggregatorClass = contrib.aggregators[args.upload]
        params = {}
        params_key = args.upload + '.'
        for k, v in args.aggregators.items():
            pk = k.replace(params_key, '')
            if not k.startswith(params_key):
                continue
            if v.startswith('keyring:'):
                params[pk] = keyring.get_password(*v.replace('keyring:', '').split(':'))
            else:
                params[pk] = v
        print(f'Uploading vex to {args.upload}')
        aggregator = AggregatorClass(**params)
        sbomID, report = aggregator.submit(args.projectpath, args.sbom, tentative=args.upload_tentative)
        with open(args.vex_issues, 'w') as fout:
            yaml.safe_dump(report, fout)
        aggregator.summary(sbomID, report)
        exit(0)
    if args.work:
        vex_file = args.vex_file or args.sbom
        if sys.argv[0] == '-c' or args.tui:
            from bogrod.tui.app import BogrodApp
            bogrod.app = BogrodApp(bogrod=bogrod)
            bogrod.app.run() if args.tui else None
        else:
            bogrod.work()
        write_vex_merge(vex_file)
    else:
        bogrod.report(format=args.output, summary=args.summary)
    return bogrod


if __name__ == '__main__':
    bogrod = main(sys.argv)
