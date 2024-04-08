import json
from collections import Counter

import requests
from bogrod.contrib.aggregator import SBOMAggregator


class EssentxElementaris(SBOMAggregator):
    def __init__(self, url, token):
        self.url = url
        self.token = token

    def auth(self, r):
        r.headers['authorization'] = f'{self.token}'
        r.headers['content-type'] = 'application/json'
        return r

    def upload_sbom(self, projectpath, sbompath, tentative=False):
        with open(sbompath, 'r') as fin:
            data = json.load(fin)
        if tentative:
            url = f'{self.url}/sbom/temporary-report'
        else:
            url = f'{self.url}/sbom?projectPath={projectpath}'
        resp = requests.post(url,
                             json=data,
                             auth=self.auth)
        data = resp.json()
        self.raise_for_status(resp, data, extra={'projectpath': projectpath, 'sbompath': sbompath})
        return data.get('sbomID')

    def get_report(self, sbomID):
        resp = requests.get(f'{self.url}/sbom/reports/{sbomID}',
                            auth=self.auth)
        data = resp.json()
        self.raise_for_status(resp, data, extra={'sbomID': sbomID})
        return data

    def summary(self, sbomID, report=None):
        data = report or self.get_report(sbomID)
        sbomId = data.get('id')
        status = data.get('status')
        if 'report' not in data:
            print(f'ERROR: SBOM ID: {sbomId} Status: {status}')
            return
        trustLevel = data['report']['trustLevelScore']
        vulns = data['report']['vulnerabilities']
        counter = Counter()
        for v in vulns:
            counter.update({v['highestSeverity']: 1, 'id': 1, 'issues': len(v['issues'])})
        print(f'SBOM ID: {sbomID} Status: {status} Trust Level: {trustLevel}')
        print('issues: ', counter)

    def raise_for_status(self, resp, data=None, extra=None):
        data = data or resp.json()
        extra = extra or ''
        if 'error' in data or 'code' in data or resp.status_code > 400:
            message = data['message']
            text = f'{resp.status_code=} {message=} {extra=}'
            raise Exception(text)
        return data

