import logging

from bogrod.analysis.aicheck import LLMCheck, run_checks
from bogrod.analysis.prompts import deployment_description


def read_csv(filepath, *filters):
    """
    Read a CSV file and apply multiple filter functions in sequence.
    """
    import csv

    with open(filepath, 'r') as file:
        reader = csv.DictReader(file)
        data = list(reader)

    # Apply all filters
    for filter_func in filters:
        data = filter(filter_func, data)

    return list(data)


if __name__ == '__main__':
    logging.basicConfig(
        filename='aicheck_debug.log',
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    )
    logging.getLogger("openai").setLevel(logging.ERROR)
    logging.getLogger("httpx").setLevel(logging.ERROR)
    logging.getLogger("httpx2").setLevel(logging.ERROR)
    logging.getLogger("httpcore").setLevel(logging.ERROR)
    logging.getLogger("httpcore2").setLevel(logging.ERROR)

    vulns = read_csv('sbom-report.csv')
    checker = LLMCheck('http://neptun:11434/v1', 'qwen3-coder:30b')
    run_checks(
        checker,
        deployment_description,
        vulns,
    )
