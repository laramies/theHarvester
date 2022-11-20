from setuptools import setup, find_packages
from theHarvester.lib.version import version

with open('README.md', 'r') as fh:
    long_description: str = fh.read()

setup(
    name='theHarvester',
    version=version(),
    author="Christian Martorella",
    author_email="cmartorella@edge-security.com",
    description="theHarvester is a very simple, yet effective tool designed to be used in the early stages of a penetration test",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/laramies/theHarvester",
    packages=find_packages(exclude=['tests']),
    python_requires='>=3.10',
    scripts=['bin/theHarvester',
             'bin/restfulHarvest'],

    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    data_files=[
        ('/etc/theHarvester', [
            'wordlists/general/common.txt',
            'wordlists/dns-big.txt',
            'wordlists/dns-names.txt',
            'wordlists/dorks.txt',
            'wordlists/names_small.txt',
            'api-keys.yaml',
            'proxies.yaml'
        ]
        )
    ],
)
