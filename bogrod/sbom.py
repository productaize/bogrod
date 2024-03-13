import json

from bogrod import settings


class GrypeSBOM:
    """Grype SBOM

    This class is used to read the Grype SBOM file and return the data
    """

    def __init__(self, data):
        self.data = data

    @classmethod
    def from_file(cls, path):
        with open(path, 'r') as fin:
            print("Reading grype: ", path)
            data = json.load(fin)
        return GrypeSBOM(data)


class CycloneDXSBOM:
    """CycloneDX SBOM

    Purpose of this class is to read the CycloneDX SBOM file and return the data
    """

    def __init__(self, data):
        self.data = data

    def vulnerabilities(self, as_dict=False, severities=None, ordered=False):
        """return vulnerabilities

        Args:
            as_dict (bool): return a dict of vulnerabilities
            severities (list): return vulnerabilities with severity in the list
            ordered (bool): return vulnerabilities ordered by severity

        How it works:
        - if as_dict is True, return a dict of vulnerabilities
        - if severities is None, return all vulnerabilities
        - if severities is a list, return vulnerabilities with severity in the list
        - if ordered is True, return vulnerabilities ordered by severity
        """
        vuln = self.data.get('vulnerabilities', [])
        severity_rank = lambda v: settings.severities_order.index(self._vuln_severity(v))
        severity_rank_d = lambda d: severity_rank(d[1])
        severities = severities or settings.severities
        if as_dict:
            vuln = {v['id']: v for v in vuln if self._vuln_severity(v) in severities}
            return dict(sorted(vuln.items(), key=severity_rank_d))
        return vuln if not ordered else sorted(vuln, key=severity_rank)

    def _vuln_severity(self, v):
        return ([s.get('severity') for s in v['ratings'] if s.get('severity')] + ['unknown'])[0]

    def diff(self, other):
        """return diff between two SBOMs

        Compares two SBOMs and returns a dict of vulnerabilities that are
        added, removed or unchanged. The analysis is with respect to the
        vulnerabilities in the current SBOM (self).

        Args:
            other (CycloneDXSBOM): the other SBOM to compare to

        Returns:
            dict: a dict of vulnerabilities that are unchanged, new or resolved
        """
        diff = {}
        ours_vuln = self.vulnerabilities(as_dict=True)
        theirs_vuln = other.vulnerabilities(as_dict=True)
        ours = set(ours_vuln)
        theirs = set(theirs_vuln)
        diff.update({
            vid: {
                'delta': 'unchanged',
                'vuln': ours_vuln[vid]
            }
         for vid in ours.intersection(theirs)})
        diff.update({
            vid: {
                'delta': 'new',
                'vuln': ours_vuln[vid]
            }
        for vid in ours.difference(theirs)})
        diff.update({
            vid: {
                'delta': 'resolved',
                'vuln': theirs_vuln[vid]
            }
        for vid in theirs.difference(ours)})
        return diff

    @classmethod
    def from_file(self, path):
        with open(path, 'r') as fin:
            print("Reading cyclonedx: ", path)
            self.cyclonedx = json.load(fin)
        return CycloneDXSBOM(self.cyclonedx)
