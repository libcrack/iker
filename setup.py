#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: borja@libcrack.so
# Date: Wed Jan 28 16:35:57 CET 2015

import re
import os

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def read(relpath):
    """
    Return string containing the contents of the file at *relpath* relative to
    this file.
    """
    cwd = os.path.dirname(__file__)
    abspath = os.path.join(cwd,os.path.normpath(relpath))
    with open(abspath) as f:
        return f.read()

PACKAGE = os.path.basename(os.getcwd())
PACKAGES = [PACKAGE]
PROVIDES = [PACKAGE]
PACKAGE_DIR = {PACKAGE: PACKAGE}
SCRIPT_FILE = PACKAGE_DIR[PACKAGE] + '/__init__.py'
# SCRIPTS=['scripts/' + PACKAGE]
ENTRY_POINTS = {
    # 'console_scripts': [PACKAGE + '=' + PACKAGE + '.' + PACKAGE + ':main'],
    'console_scripts': ['{0}={0}.{0}:main'.format(PACKAGE)],
}

PLATFORMS = ['Linux']
KEYWORDS = 'ipsec ike'
INSTALL_REQUIRES = [
    x.replace('-','_') for x in read('requirements.txt').split('\n') if x != ''
    ]
# x.replace('-','_') for x in read('requirements.txt').split('\n') if x != ''
main_py = open(SCRIPT_FILE).read()
metadata = dict(re.findall("__([a-z]+)__ = '([^']+)'", main_py))
docstrings = re.findall('"""(.*?)"""', main_py, re.DOTALL)

VERSION = metadata['version']
WEBSITE = metadata['website']
LICENSE = metadata['license']
AUTHOR_EMAIL = metadata['author']
AUTHOR, EMAIL = re.match(r'(.*) <(.*)>', AUTHOR_EMAIL).groups()
DESCRIPTION = docstrings[0].strip()
if '\n\n' in DESCRIPTION:
    DESCRIPTION, LONG_DESCRIPTION = DESCRIPTION.split('\n\n', 1)
else:
    LONG_DESCRIPTION = None


CLASSIFIERS = [
    'Development Status :: 3 - Beta',
    'Environment :: Console',
    'Intended Audience :: Developers',
    'License :: GPL',
    'Operating System :: OS Independent',
    'Operating System :: POSIX :: Linux',
    'Natural Language :: English',
    'Programming Language :: Python',
    'Programming Language :: Python :: 3',
]

PARAMS = {
    'platforms': PLATFORMS,
    'name': PACKAGE,
    'version': VERSION,
    'description': DESCRIPTION,
    'keywords': KEYWORDS,
    'long_description': LONG_DESCRIPTION,
    'author': AUTHOR,
    'author_email': EMAIL,
    'url': WEBSITE,
    'license': LICENSE,
    'packages': PACKAGES,
    'package_dir': PACKAGE_DIR,
    #'scripts': SCRIPTS,
    'entry_points': ENTRY_POINTS,
    'provides': PROVIDES,
    'requires': INSTALL_REQUIRES,
    'install_requires': INSTALL_REQUIRES,
    'classifiers': CLASSIFIERS,
}

setup(**PARAMS)

# vim:ts=4 sts=4 tw=79 expandtab:
