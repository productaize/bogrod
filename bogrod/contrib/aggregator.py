from time import sleep

from tqdm import tqdm


class SBOMAggregator:
    def upload_sbom(self, projectpath, sbompath, **kwargs):
        raise NotImplementedError

    def get_report(self, sbomID):
        raise NotImplementedError

    def submit(self, projectpath, sbompath, tentative=False, timeout=600):
        sbomID = self.upload_sbom(projectpath, sbompath, tentative=tentative)
        report = None
        for i in tqdm(range(max(timeout, 10)), delay=5):
            report = self.get_report(sbomID)
            if 'pending' not in report['status'].lower():
                break
            sleep(1)
        return sbomID, report
