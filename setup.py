from pathlib import Path

from setuptools import setup

README = open(Path(__file__).parent /'README.md').read()
version = open(Path(__file__).parent / 'bogrod' / 'VERSION').read()

setup(
    name='bogrod',
    version=version,
    packages=['bogrod', 'bogrod.tests'],
    url='https://github.com/productaize/bogrod',
    license='MIT',
    author='Patrick Senti',
    author_email='patrick@productaize.io',
    description='Manage SBOM, VEX records and release notes in a single tool',
    long_description=README,
    long_description_content_type='text/markdown',
    install_requires=[
        'jsonschema<4', # 4.x causes endless loop when validating with bom-1.5.schema.json
        'pyyaml',
        'tabulate',
        'attrdict',
        'textual',
        'textual-dev', # for testing
        'requests',
        'yaspin',
    ],
    entry_points = {
        'console_scripts': [
            'bogrod=bogrod:main'
        ]
    }
)
