import argparse
from configparser import ConfigParser
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path

import keyring
import yaml

from bogrod import contrib
from bogrod.controller import Bogrod
from bogrod.sbom import CycloneDXSBOM


def check_args(argv):
    # setup argument parser
    parser = argparse.ArgumentParser(prog='bogrod')
    # test for --version first
    with redirect_stderr(StringIO()) as _:
        try:
            parser.add_argument('--version', help='show version', action='store_true')
            args = parser.parse_args(argv)
        except:
            args = None
    # show version
    if args and args.version:
        with open(Path(__file__).parent / 'VERSION') as fin:
            version = fin.read()
        print(version)
        exit(0)
    # no --version argument, continue
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
    parser.add_argument('-F', '--fail-on-issues', action='store_true', dest='fail_on_issues',
                        help='if there are pending issues or unresolved vulnerabilities, exit with error')
    args = parser.parse_args(argv)
    return args


def main(argv=None):
    args = check_args(argv)

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
        from bogrod.tui.app import BogrodApp
        bogrod.app = BogrodApp(bogrod=bogrod)
        bogrod.app.run()
        write_vex_merge(vex_file)
    else:
        bogrod.report(format=args.output, summary=args.summary, fail_on_issues=args.fail_on_issues)
    return bogrod
