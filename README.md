<p align="center">
  <img alt="bogrod - SBOM as code" src="https://raw.githubusercontent.com/productaize/bogrod/master/resources/logotitle.png" style="visibility: visible; max-width: 100%;">
</p>

# bogrod — SBOM as Code

> Manage your Software Bill of Materials and VEX analysis the same way you manage source code.

[![PyPI version](https://img.shields.io/pypi/v/bogrod)](https://pypi.org/project/bogrod/)
[![License](https://img.shields.io/github/license/productaize/bogrod)](LICENSE)

## Why bogrod?

SBOMs are typically managed in UI tools like Dependency Track. While such tools provide a nice UI, they require
additional infrastructure and are far removed from the development process. The last thing a DevOps team needs is
another external tool to manage and integrate into existing CI/CD practices.

**Enter bogrod:**

- Enable your DevOps team to manage SBOMs where they originate: with the code
- Track SBOM and VEX analysis using established git practices
- Analyze vulnerabilities and update VEX records from the console, your favorite IDE or with bogrod's console TUI
- Easily reuse VEX analysis across multiple images

[![bogrod process](https://github.com/productaize/bogrod/raw/master/resources/process.png)](resources/process.png)

---

## Features

The bogrod CLI and console TUI supports you to:

- 🛡️ Analyse and update VEX analysis interactively, by component and severity
- 🚨 Report on vulnerabilities by severity in detailed or summary form
- 📦 Collect VEX information from multiple SBOMs in CycloneDX format
- 🔐 Create a git-managed database of vulnerabilities (YAML format)
- 📝 Update release notes with vulnerabilities found in SBOMs
- 🏷️ Update SBOM metadata from a common source

---

## Installation

```bash
pip install bogrod
```

To install from source (includes examples and tests):

```bash
git clone https://github.com/productaize/bogrod.git
pip install ./bogrod[dev]
```

---

## CLI Reference

Run as a command line utility:

    usage: bogrod [-h] [-n NOTES] [-o OUTPUT] [-S] [-s SEVERITIES] [-x] [--vex-file VEX_FILE] [-p SBOM_PROPERTIES] [-m] [-w] [-W] [-g GRYPE] sbom

    positional arguments:
      sbom                  name of sbom in .bogrod, or /path/to/cyclonedx-sbom.json
    
    optional arguments:
      -h, --help            show this help message and exit
      -n NOTES, --notes NOTES
                            /path/to/notes.yaml
      -o OUTPUT, --output OUTPUT
                            output format [table,json,yaml,raw]
      -S, --summary         summarize report
      -s SEVERITIES, --severities SEVERITIES
                            list of serverities in critical,high,medium,low
      -x, --update-vex      update vex information from sbom vulnerabilities
      --vex-file VEX_FILE   /path/to/vex.yaml
      -p SBOM_PROPERTIES, --sbom-properties SBOM_PROPERTIES
                            Merge sbom with information in /path/to/properties.yaml
      -m, --merge-vex       Merge vex data back to sbom
      -w, --write-notes     update notes according to sbom (add new, mark fixed)
      -W, --work            work each vulnerability
      -g GRYPE, --grype GRYPE

---

## File Naming Conventions

bogrod uses a consistent naming convention so it can automatically locate related files. Place all files in the same
directory:

```
releasenotes/sbom/<image-name>.cdx.json    # CycloneDX SBOM
releasenotes/sbom/<image-name>.grype.json  # Grype vulnerability report
releasenotes/sbom/<image-name>.syft.json   # Syft artifact report
releasenotes/sbom/vex.yaml                 # VEX analysis records
```

When you provide a `.cdx.json` path, bogrod automatically looks for the corresponding `.grype.json` and `.syft.json` in
the same directory. It does not require grype and syft reports, and will work with just a `.cdx.json` file.

---

## Example Workflow

Consider this scenario

*We have a docker image, jupter/base-notebook:ubuntu-20.04, for which we want to
analyze and keep track of vulnerabilities. Let's use syft to create the
SBOM and grype to find all vulnerabilities. Then we'll apply bogrod's interactive TUI to analyze
each vulnerabilitiy, record our analysis and update the SBOM with the respective
VEX analysis information.*

**1. Generate the SBOM with Syft**

```bash
syft jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.syft.json --output json
```

**2. Find vulnerabilities with Grype**

```bash
# Detailed Grype report (includes VEX context)
grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json \
  --output json=releasenotes/sbom/jupyter-base-notebook.grype.json

# CycloneDX-format report for bogrod
grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json \
  --output cyclonedx-json=releasenotes/sbom/jupyter-base-notebook.cdx.json
```

**3. Analyze and summarize the SBOM**

```bash
bogrod -S releasenotes/sbom/jupyter-base-notebook.cdx.json

bogrod SBOM Summary Report

severity          state
              in_triage
----------  -----------
critical              3
high                 73
Total                76
```

Next, let's see how we can interactively work with this SBOM to analyze each vulnerability and decide on our course of
action.

---

## Working with Vulnerabilities Interactively

Run `bogrod --work` to open an interactive terminal UI for working through each vulnerability:

```bash
bogrod --work releasenotes/sbom/jupyter-base-notebook.cdx.json
```

**Vulnerability list**

At startup bogrod parses the SBOM and provides a quick summary at the top of the screen.

- Press `Enter` to view the full details of a vulnerability
- Press `V` to open the CVE/NVD page directly in your browser
- Press `Ctrl-C` or `Q` to save and quit

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo1.png)](resources/demo1.png)

**View vulnerability and add your analysis**

The detail panel let's you view the details of the vulnerability and edit your course of action, according to the
Vulnerability Exploitability eXchange standard.

- Use `Tab` to switch between the various panels (`state`, `response`, `justification`, `detail`, `templates`,
  `vexdata`)
- Select a `state` according to your process and analysis
- Select a `response` according to the response you plan to take
- Select a `justification` according to your analaysis
- Enter a `detail` comment to explain your rationale
- Press `Ctrl-t` to save your response as a template for similar vulnerabilities (e.g. the same component, or a
  different image)
- Press `Ctrl-s` to save the VEX information and return to bogrod's main panel
- Select a `template` or press `t` to select a template (see below)

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo2.png)](resources/demo2.png)

**Filtering and search**

Filter the list of vulnerabilites by the various quick criteria on the left by selecting
one of the listed values.

- Press `F` and `Tab` to cycle through quick filter criteria on the left
- Press `/` to search using `<column>:<value>` syntax (e.g. `severity:critical`)

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo3.png)](resources/demo2.png)

**Bulk editing**

Edit multiple vulnerabilities at marking related entries using ctrl+space.

- Use `Ctrl+Space` to mark multiple related vulnerabilities
- Select any marked entry, enter your analysis, and press `Ctrl+S` — all marked entries will be updated with the same
  analysis

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo4.png)](resources/demo3.png)

**Opening CVE pages**

Assessing wheter a vulnerability is a concern for your software requires knowing what it is about. While this
information is easy
to find online, bogrod makes it fast and simple.

- From any entry (list or detail view), press `V` to open the CVE or NVD page in your browser — no copy-pasting required

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo5.png)](resources/demo4.png)

**Templates**

Using templates of your analysis can help in responding to the same vulnerability across different images that were
created from the same base image.

- While editing a vulnerability, press `Ctrl+T` to save the current analysis as a reusable template
- Press `T` to apply a template to the current entry
- bogrod automatically creates a template for each component analyzed, making it easy to apply consistent analysis to
  related vulnerabilities

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo6.png)](resources/demo5.png)

**Platform upload and dealing with issue reports**

Uploading to a vulnerability management platform such
as [elementaris by Essentx](https://github.com/essentxag/elementaris-docu) is straightforward:

```bash
bogrod --upload elementaris releasenotes/sbom/jupyter-base-notebook.cdx.json
```

The platform returns its own analysis, and any flagged vulnerabilities are marked with a `*` postfix on their state.

- Press `Enter` to view details including the platform's report in the `vexdata` part of the detail panel.

[![bogrod demo](https://github.com/productaize/bogrod/raw/master/resources/demo7.png)](resources/demo7.png)

---

## Working with Multiple Images

When multiple images share a base, their vulnerabilities overlap. Instead of repeating analysis, bogrod tracks the
origin of each vulnerability and lets you merge VEX records across images.

Create a `.bogrod` config file referencing each image's SBOM:

```ini
# .bogrod
[global]
update_vex = yes
merge_vex = yes

[jupyter]
sbom = releasenotes/sbom/jupyter-base-notebook.json

[jupyter-hub]
sbom = releasenotes/sbom/jupyter-hub-notebook.json
```

---

## Format of Vulnerability Exploitability eXchange (VEX)

bogrod stores VEX records in a plain YAML file, making them easy to read, edit, and track in git.

```yaml
# vex.yaml
CVE-2022-999999:
  state: open
  response: will fix in next release
  detail: affects only if debug flag is set
  justification: in normal operation this is not an issue
```

Use `--vex-file` to point bogrod at your VEX file and `--update-vex` to apply analysis back to the SBOM. You can also
record related information like component origin and duplicate CVEs:

```yaml
CVE-2022-999999:
  state: open
  response: will fix in next release
  detail: affects only if debug flag is set
  justification: in normal operation this is not an issue
  related:
    - component: jupyter/base-notebook:ubuntu-20.04
    - duplicates: CVE-2019-10773
```

### Using VEX Templates

Avoid re-entering the same analysis repeatedly by defining templates in your `vex.yaml`. Templates can match by
component, artifact, or all vulnerabilities:

```yaml
# vex.yaml
templates:
  pkg:generic/python@3.10.6?package-id=aadd06b57d8f4fc4:
    match: component
    state: in_triage
    response: [ ]
    justification: ''
    detail: 'this package is not used in production'

  python-3.10.6:
    match: artifact
    state: in_triage
    response: [ ]
    justification: ''
    detail: ''

  some template:
    match: all
    state: in_triage
    response: [ ]
    justification: ''
    detail: ''
```

Templates appear in the VEX detail screen and can be applied with a single keypress.

---

## SBOM Metadata

bogrod can enrich the SBOM's metadata section from an external YAML file:

```yaml
# sbom.metadata.yaml
# Full spec: https://cyclonedx.org/docs/1.4/json/#metadata
metadata:
  supplier:
    name: productaize
    url:
      - https://productaize.io
    contact:
      - name: Jane John
        email: founder@productaize.io
```

```bash
bogrod --sbom-properties sbom.metadata.yaml releasenotes/sbom/my-image.cdx.json
```

bogrod also normalizes container image metadata. Syft/Grype represent images like this:

```json
{
  "component": {
    "bom-ref": "c001e40278e035d7",
    "type": "container",
    "name": "jupyter/base-notebook:ubuntu-20.04",
    "version": "sha256:21fd9..."
  },
  ...
}
```

bogrod transforms this into a more useful structure, separating the image name from its tag and preserving the original
sha256 reference as a nested component. Any registry prefix (e.g. `ghcr.io/`) is also stripped:

```json
{
  "component": {
    "bom-ref": "sbom:c001e40278e035d7",
    "type": "container",
    "name": "jupyter/base-notebook",
    "version": "ubuntu-20.04",
    "components": [
      {
        "bom-ref": "c001e40278e035d7",
        "type": "container",
        "name": "jupyter/base-notebook:ubuntu-20.04",
        "version": "sha256:21fd9..."
      }
    ],
    ...
  }
```

---

## CI/CD Integration

bogrod fits naturally into automated pipelines. Use `--fail-on-issues` to fail the build if any vulnerabilities remain
unresolved:

```bash
# 1. Install syft and grype
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ${HOME}/.local/bin
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ${HOME}/.local/bin

# 2. Generate SBOM files
syft jupyter/base-notebook:ubuntu-20.04 \
  --output json=releasenotes/sbom/jupyter-base-notebook.syft.json
grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json \
  --output json=releasenotes/sbom/jupyter-base-notebook.grype.json
grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json \
  --output cyclonedx-json=releasenotes/sbom/jupyter-base-notebook.cdx.json

# 3. Run bogrod (fails if in_triage or exploitable vulnerabilities exist)
bogrod --fail-on-issues releasenotes/sbom/jupyter-base-notebook.cdx.json
```

---

## Ecosystem & Related Tools

| Tool                                                        | Purpose                                              |
|-------------------------------------------------------------|------------------------------------------------------|
| [Syft](https://github.com/anchore/syft)                     | Generate SBOMs from container images and filesystems |
| [Grype](https://github.com/anchore/grype)                   | Vulnerability scanner, produces CycloneDX output     |
| [Trivy](https://aquasecurity.github.io/trivy/)              | Alternative vulnerability scanner                    |
| [cyclonedx-cli](https://github.com/CycloneDX/cyclonedx-cli) | Diff SBOMs between releases                          |
| [mitrecve](https://mitrecve.readthedocs.io/en/latest/)      | Query the MITRE vulnerability database               |
| [nvdlib](https://nvdlib.com/en/latest/)                     | Query the NIST NVD vulnerability database            |

Usage of Syft and Grype:

- Syft can output a detailed json report with all artificats found inside and image.
  This json follows a Syft internal schema, and it can be used by Grype as input to
  create a CycloneDX SBOM.
- Bogrod can accept a Syft json report as input to have more information when working
  on resolving vulnerabilities.

**Specifications**

- CycloneDX JSON browser: https://cyclonedx.org/docs/1.6/json/
- CycloneDX JSON schema: https://github.com/CycloneDX/specification/releases

---

## Commercial Support

Commercial training and support for bogrod is available from [productaize](https://productaize.io). Contact:
info at productaize.io

---

## What's in a Name?

I was looking for the name of a trusted secret keeper of sorts. An early fan of Harry Potter's
I found some character from Gringotts Wizarding Bank would be a great fit.

> *Bogrod, a goblin, is one of the counter staff at Gringotts Wizarding Bank in Diagon Alley.*
> — Wikipedia

A trusted keeper of inventories and valuables. A fitting name for a tool that keeps careful track of what's inside your
software.

Credits: [Wikipedia](https://en.wikibooks.org/wiki/Muggles%27_Guide_to_Harry_Potter/Characters/Bogrod)
