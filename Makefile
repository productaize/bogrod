sbom:
	grype jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.json --output embedded-cyclonedx-vex-json

notes:
	reno new rc1 .
	reno report . --title FOO | pandoc -f rst > release-notes.html

vex:
	bogrod releasenotes/sbom/jupyter-base-notebook.json --vex-file releasenotes/sbom/vex.yaml --update-vex --merge-vex

report:
	bogrod releasenotes/sbom/jupyter-base-notebook.json --vex-file releasenotes/sbom/vex.yaml --notes releasenotes/notes/rc1-99e6a29d3335a383.yaml -w
	reno report . --title FOO | pandoc -f rst > release-notes.html
