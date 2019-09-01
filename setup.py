import setuptools
from theHarvester.lib.core import Core

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name='theHarvester',
    version=Core.version(),
    author="Christian Martorella",
    author_email="cmartorella@edge-security.com",
    description="theHarvester is a very simple, yet effective tool designed to be used in the early stages of a penetration test",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/laramies/theHarvester",
    packages=setuptools.find_packages(exclude=['tests']),
    entry_points={
        'console_scripts': [
            'theHarvester = theHarvester.__main__:entry_point'
        ]
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
        "Operating System :: OS Independent",
    ],
    data_files=[
        ('share/dict/theHarvester', [
            'wordlists/general/common.txt',
            'wordlists/dns-big.txt',
            'wordlists/dns-names.txt',
            'wordlists/dorks.txt',
            'wordlists/names_small.txt'
        ]
        )
    ],
)
