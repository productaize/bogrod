.PHONY: dist image help

sbom:
	# get image
	docker pull -q jupyter/base-notebook:ubuntu-20.04
	# sbom
	syft jupyter/base-notebook:ubuntu-20.04 --output json=releasenotes/sbom/jupyter-base-notebook.syft.json
	# grype format, including match information
	grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json --output json=releasenotes/sbom/jupyter-base-notebook.grype.json
	# cyclonedx format
	grype sbom:releasenotes/sbom/jupyter-base-notebook.syft.json --output cyclonedx-json=releasenotes/sbom/jupyter-base-notebook.cdx.json
	# check
	bogrod -F jupyter

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

bump-build:
	@bash -c "grep -qE '(-rc|-dev)' bogrod/VERSION && bump2version build || echo WARNING this is a final release, build not incremented"
	@cat bogrod/VERSION

bump-release:
	@bump2version release 2> /dev/null || bump2version patch
	@cat bogrod/VERSION

dist: bump-build
	: "run setup.py sdist bdist_wheel"
	rm -rf ./dist/*
	rm -rf ./build/*
	# set DISTTAGS to specify eg --python-tag for bdist
	pip install -U setuptools build
	python -m build
	twine check dist/*.whl

release: test dist
	bash -c "grep -qvE '(-rc|-dev)' bogrod/VERSION || (echo 'must be a final release. run make bump-release first'; exit 1)"
	bash -c 'git checkout -b release-`head -n1 bogrod/VERSION`'
	bash -c "git add .; git commit -m 'build release'; git push"
	twine upload --skip-existing --repository pypi-productaize dist/*gz dist/*whl
	bash -c "git tag `head -n1 bogrod/VERSION`; git push origin --tags"

release-test: dist
	# upload and install
	bash -c "grep -qE '(-rc)' bogrod/VERSION || (echo 'must be a release candidate (-rc). run make bump-release first'; exit 1)"
	bash -c 'git checkout -b build-`head -n1 bogrod/VERSION`'
	bash -c "git add .; git commit -m 'build release test'; git push"
	twine upload --repository testpypi-productaize dist/*gz dist/*whl
	pip install -U --pre -i https://test.pypi.org/simple/ --extra-index-url https://pypi.org/simple/ bogrod
	bogrod --version

install-sbom-tools:
	# install grype and syft
	curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b ${HOME}/.local/bin
	curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b ${HOME}/.local/bin
	pip install reno
	pip install -e .

test:
	tox
