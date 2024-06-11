from uuid import uuid4

from bogrod.contrib.aggregator import SBOMAggregator


class DummyAggregator(SBOMAggregator):
    """ A dummy aggregator that simulates the upload and report process

    This aggregator is useful for testing the SBOM upload and report process.
    It does not actually upload the SBOM data, but simulates the process.

    Args:
        delay (int): the time to wait before the report is marked as complete

    Usage:
        in the .bogrod config file:

        [aggregator]
        dummy.delay=2 # wait 2 seconds before marking the report as complete
    """

    def __init__(self, *args, delay=60, **kwargs):
        super().__init__(*args, **kwargs)
        self._reports = {}
        self._delay = int(delay)

    def upload_sbom(self, projectpath, sbompath, **kwargs):
        sid = uuid4().hex
        self._reports[sid] = {
            'eta': self._delay,
        }
        return sid

    def progress(self, sbomID):
        report = self._reports.get(sbomID)
        if report:
            report['eta'] = eta = report['eta'] - 1
            report['status'] = 'pending' if eta else 'complete'
            report['report'] = {}
        else:
            report = {
                'status': 'does-not-exist'
            }
        return report

    def get_report(self, sbomID):
        report = self.progress(sbomID)
        return report
