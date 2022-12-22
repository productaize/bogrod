sbom:
	grype jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.json --output embedded-cyclonedx-vex-json

notes:
	reno new rc1 .
