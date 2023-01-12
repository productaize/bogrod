sbom:
	grype jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.json --output embedded-cyclonedx-vex-json

notes:
	reno new rc1 .
	reno report . --title FOO | pandoc -f rst > release-notes.html

report:
	bogrod releasenotes/sbom/jupyter-base-notebook.json  --notes releasenotes/notes/rc1-a86b72ab67c7c21e.yaml -w
	reno report . --title FOO | pandoc -f rst > release-notes.html
