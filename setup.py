#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import arcula

from setuptools import setup, find_packages
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

with open(path.join(here, 'requirements.txt'), encoding='utf-8') as f:
    install_requires = f.read().strip().split('\n')


with open(path.join(here, 'requirements_dev.txt'), encoding='utf-8') as f:
    dev_requires = {'dev': f.read().strip().split('\n')}


setup(
    name=arcula.__name__,
    version=arcula.__version__,
    description='Arcula: A Secure Hierarchical Deterministic Wallet',

    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/aldur/Arcula',
    author='Adriano Di Luzio',
    author_email='adrianodl@hotmail.it',

    classifiers=[
        'Development Status :: 3 - Alpha',

        'Intended Audience :: Developers',
        'Intended Audience :: Financial and Insurance Industry',

        'Topic :: Software Development :: Build Tools',
        'Topic :: Office/Business :: Financial',

        'License :: OSI Approved :: MIT License',

        'Programming Language :: Python :: 3 :: Only',
        'Programming Language :: Python :: 3.7',
    ],

    packages=find_packages(exclude=['contrib', 'docs', 'tests']),
    python_requires='>=3.7',

    install_requires=install_requires,
    extras_require=dev_requires,
)
