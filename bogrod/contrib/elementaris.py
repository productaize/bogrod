import json
from collections import Counter

import requests
from bogrod.contrib.aggregator import SBOMAggregator


class EssentxElementaris(SBOMAggregator):
    """ An aggregator for the Essentx Elementaris SBOM service

    Usage:
        in the .bogrod config file:

        [aggregator]
        elementaris.url=https://<company>.elementaris.essentx.com/api/v1/
        elementaris.token=<API>
        elementaris.report_timeout=<seconds>
        elementaris.report_interval=<seconds>

    Args:
        url (str): the base URL for the Elementaris service
        token (str): the API token for the Elementaris service. The token
          can be specified as "[keyring:]<user>:<token>". If "keyring:"
          is specified, <user> and <service> are used to retrieve the actual
          token as keyring.get_password(servicename=user, username=token).

    Notes:
        The Elementaris service requires an API token for authentication.
        The token is passed in the `authorization` header of the request.
        The service expects the SBOM data to be in CycloneDX JSON format.
        The url for the service is typically `https://<company>.elementaris.essentx.com/api/v1/`

    See Also:
        - https://github.com/essentxag/elementaris-docu
        - https://github.com/essentxag/elementaris-docu/releases/tag/v1.2.0
    """

    def __init__(self, *args, url=None, token=None, **kwargs):
        super().__init__(*args, **kwargs)
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
