from pathlib import Path

from setuptools import setup, find_packages, find_namespace_packages

README = open(Path(__file__).parent / 'README.md').read()
version = open(Path(__file__).parent / 'bogrod' / 'VERSION').read()

dev_deps = [
    'tox',
    'pytest',
    'build',
    'pytest-textual-snapshot',
]

setup(
    name='bogrod',
    version=version,
    packages=find_packages() + find_namespace_packages(),
    include_package_data=True,
    url='https://github.com/productaize/bogrod',
    license='MIT',
    author='Patrick Senti',
    author_email='patrick@productaize.io',
    description='Manage SBOM, VEX records and release notes in a single tool',
    long_description=README,
    long_description_content_type='text/markdown',
    install_requires=[
        'jsonschema<4',  # 4.x causes endless loop when validating with bom-1.5.schema.json
        'pyyaml',
        'tabulate',
        'attrdict',
        'textual',
        'textual-dev',  # for testing
        'requests',
        'yaspin',
        'keyring',
    ],
    entry_points={
        'console_scripts': [
            'bogrod=bogrod:main_cli',
            'bd=bogrod:main_cli'
        ]
    },
    extras_require={
        'dev': dev_deps,
    }
)
