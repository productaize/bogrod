sbom:
	grype jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.json --output embedded-cyclonedx-vex-json

notes:
	reno new rc1 .
	reno report . --title FOO | pandoc -f rst > release-notes.html

report:
	bogrod releasenotes/sbom/jupyter-base-notebook.json  --notes releasenotes/notes/rc1-99e6a29d3335a383.yaml -w
	reno report . --title FOO | pandoc -f rst > release-notes.html
