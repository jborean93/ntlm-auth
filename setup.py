#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

# PyPi supports only reStructuredText, so pandoc should be installed
# before uploading package
try:
    import pypandoc
    long_description = pypandoc.convert('README.md', 'rst')
except ImportError:
    long_description = ''

install_requires = [ 'six' ]
# Python 2.6 doesn't have OrderedDict inbuilt, use the ordereddict library
# instead
try:
    from collections import OrderedDict
except ImportError:
    install_requires.append('ordereddict')
	
setup(
    name='ntlm-auth',
    version='1.0.3',
    packages=[ 'ntlm_auth' ],
    install_requires=install_requires,
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/ntlm-auth',
    description='Creates NTLM authentication structures',
    long_description=long_description,
    keywords='authentication auth microsoft ntlm lm',
    license='GNU Lesser GPL',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
)
