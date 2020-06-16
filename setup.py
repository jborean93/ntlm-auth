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

setup(
    name='ntlm-auth',
    version='1.5.0',
    packages=['ntlm_auth'],
    install_requires=[],
    extras_require={
        ':python_version<"2.7"': [
            'ordereddict'
        ],
        # Adds faster RC4 message encryption, optional as we can fallback
        # to the slower Python imp.
        'cryptography:python_version<"2.7"': [
            'cryptography<2.2'  # 2.2+ droppped Python 2.6 support
        ],
        'cryptography:python_version>="2.7"': [
            'cryptography'
        ]
    },
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/ntlm-auth',
    description='Creates NTLM authentication structures',
    long_description=long_description,
    keywords='authentication auth microsoft ntlm lm',
    license='MIT',
    python_requires='>=2.6,!=3.0.*,!=3.1.*,!=3.2.*,!=3.3.*',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
    ],
)
