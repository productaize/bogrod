from setuptools import setup

setup(
    name='bogrod',
    version='',
    packages=['bogrod', 'bogrod.tests'],
    url='',
    license='',
    author='patrick',
    author_email='',
    description='',
    install_requires=[
        'jsonschema',
    ],
    entry_points = {
        'console_scripts': [
            'bogrod=bogrod:main'
        ]
    }
)
