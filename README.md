Bogrod
======

Automatically update release notes with vulnerabilities 
from an SBOM in cyclonedx format.

Format
------

The release notes format is simply a YAML file with a
security section:

    # security:
    #  - <CVE#> severity status + comment
    security:
    - CVE-2022-999999 high open 
    - CVE-2022-999989 high fixed

This is a subset of the release notes format used by reno, the
release notes tools.

Syntax
------

Run as a command line utility:

    $ bogrod -h
    usage: bogrod [-h] [-n NOTES] [-o OUTPUT] [-w] sbom
    
    positional arguments:
      sbom                  /path/to/cyclonedx-sbom.json
    
    optional arguments:
      -h, --help            show this help message and exit
      -n NOTES, --notes NOTES
                            /path/to/notes.yaml
      -o OUTPUT, --output OUTPUT
                            output format [table,json,yaml,raw]
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
