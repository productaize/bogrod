Bogrod
======

Automatically update release notes with vulnerabilities information (VEX)
from, and merge with, SBOM in cyclonedx format.

Format
------

The release notes format is simply a YAML file with a
security section:

    # notes.yaml
    # security:
    #  - <CVE#> severity status [comment]
    security:
    - CVE-2022-999999 high open will fix in next release 
    - CVE-2022-999989 high fixed will fix in next release

This is a superset of the release notes format used by reno, the
release notes tools.

Adding Vulnerability Exploit information (VEX)
-----------------------------------------------

Bogrod can extract vulnerability exploit information from 
the release notes or from a vex.yaml file (--vex-file)::

    # vex.yaml
    CVE-2022-999999:
        state: open
        response: will fix in next release     
        detail: affects only if debug flag is set
        justification: in normal operation this is not an issue

The vex.yaml file is used to update the "analysis" part of the 
CycloneDX sbom when the -x flag is specified. If --vex-file is
not specified the information from the security section in the
notes is used to set the analysis 'state' and 'response' fields.

Syntax
------

Run as a command line utility:

    $ bogrod -h
    usage: bogrod [-h] [-n NOTES] [-o OUTPUT] [-s SEVERITIES] [-x] [--vex-file VEX_FILE] [-m] [-w] sbom

    positional arguments:
      sbom                  /path/to/cyclonedx-sbom.json
    
    optional arguments:
      -h, --help            show this help message and exit
      -n NOTES, --notes NOTES
                            /path/to/notes.yaml
      -o OUTPUT, --output OUTPUT
                            output format [table,json,yaml,raw]
      -s SEVERITIES, --severities SEVERITIES
                            list of serverities in critical,high,medium,low
      -x, --vex             update vex information in sbom
      --vex-file VEX_FILE   /path/to/vex.yaml
      -m, --merge-vex       Merge vex data back to sbom
      -w, --write-notes     update notes according to sbom (add new, mark fixed)
   

Pipeline with grype and reno
----------------------------

1. reno => create release notes
2. grype => scan image and create sbom
3. bogrod => update release notes with vulns found in sbom
4. reno report => build release notes  

Tools
-----

* Syft https://github.com/anchore/syft
* Grype https://github.com/anchore/grype
* Trivy https://aquasecurity.github.io/trivy/
* SBOM diff https://github.com/CycloneDX/cyclonedx-cli 
* Reno https://docs.openstack.org/reno/latest/


Specification
-------------

* browser https://cyclonedx.org/docs/1.4/json/
* jsonschema https://github.com/CycloneDX/specification/releases
