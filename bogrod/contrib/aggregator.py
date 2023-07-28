from uuid import uuid4

from yaspin import yaspin
from yaspin.spinners import Spinners

from bogrod.util import wait


class SBOMAggregator:
    """
    A base class for SBOM aggregators

    Args:
        report_timeout (int): the maximum time to wait for the report to complete in seconds
        report_interval (int): the time to wait between checking the report status in seconds
    """
    def __init__(self, *args, report_timeout=None, report_interval=None):
        self.report_timeout = int(report_timeout or 300)
        self.report_interval = int(report_interval or 10)

    def upload_sbom(self, projectpath, sbompath, **kwargs):
        raise NotImplementedError

    def get_report(self, sbomID):
        raise NotImplementedError

    def submit(self, projectpath, sbompath, tentative=False, timeout=None, interval=None):
        """

        Args:
            projectpath (str): the project path to associate with the SBOM (e.g. company/component)
            sbompath (str): the path to the SBOM file
            tentative (bool): whether to upload the SBOM as a tentative report
            timeout (int): the maximum time to wait for the report to complete
            interval (int): the time to wait between checking the report status
        """
        timeout = self.report_timeout
        interval = self.report_interval
        sbomID = self.upload_sbom(projectpath, sbompath, tentative=tentative)
        report = None
        with yaspin(Spinners.dots, color='green') as yp:
            yp.text = 'uploading'
            for i in range(timeout):
                report = self.get_report(sbomID)
                status = report.get('status', 'waiting')
                eta = report.get('eta', '(no eta)')
                if 'pending' not in status.lower():
                    break
                for progress in wait(interval):
                    yp.text = f'{status=} {eta=} [checking again in {progress} seconds]'
            else:
                yp.text = f"aborting, exceeded timeout of {timeout} seconds"
        return sbomID, report

    def summary(self, sbomID, report=None):
        report = report or self.get_report(sbomID)
        status = report.get('status')
        print(f'{sbomID=} {status=}')


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
        else:
            report = {
                'status': 'does-not-exist'
            }
        return report

    def get_report(self, sbomID):
        report = self.progress(sbomID)
        return report


