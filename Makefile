.PHONY: dist image help

sbom:
	# sbom
	syft jupyter/base-notebook:ubuntu-20.04 --file releasenotes/sbom/jupyter-base-notebook.syft.json --output json
	# grype format, including match information
	grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json --file releasenotes/sbom/jupyter-base-notebook.grype.json --output json
	# cyclonedx format
	grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json --file releasenotes/sbom/jupyter-base-notebook.cdx.json --output embedded-cyclonedx-vex-json

notes:
	reno new rc1 .
	reno report . --title FOO | pandoc -f rst > release-notes.html

vex:
	bogrod releasenotes/sbom/jupyter-base-notebook.cdx.json --vex-file releasenotes/sbom/vex.yaml --update-vex --merge-vex --sbom-properties releasenotes/sbom/sbom-metadata.yaml

vexwork:
	bogrod -W releasenotes/sbom/jupyter-base-notebook.cdx.json --vex-file releasenotes/sbom/vex.yaml --update-vex --merge-vex --sbom-properties releasenotes/sbom/sbom-metadata.yaml

report:
	bogrod releasenotes/sbom/jupyter-base-notebook.json --vex-file releasenotes/sbom/vex.yaml --notes releasenotes/notes/rc1-99e6a29d3335a383.yaml -w
	reno report . --title FOO | pandoc -f rst > release-notes.html

dist:
	: "run setup.py sdist bdist_wheel"
	rm -rf ./dist/*
	rm -rf ./build/*
	# set DISTTAGS to specify eg --python-tag for bdist
	python setup.py sdist bdist_wheel ${DISTTAGS}
	twine check dist/*.whl

release: dist
	twine upload --skip-existing --repository pypi-productaize dist/*gz dist/*whl
