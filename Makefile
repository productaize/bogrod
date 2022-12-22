sbom:
	grype jupyter/base-notebook:ubuntu-20.04 --file reports/jupyter-base-notebook.json --output embedded-cyclonedx-vex-json
