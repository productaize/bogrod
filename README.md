Bogrod
======

Automatically update release notes with vulnerabilities 
from an SBOM in cyclonedx format.

Format
------

The release notes format is simply a YAML file with a
security section::

    security:
    - CVE-2022-999999 high open 
    - CVE-2022-999989 fixed

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
