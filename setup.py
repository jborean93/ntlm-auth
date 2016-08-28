#!/usr/bin/env python
# coding: utf-8

from setuptools import setup

setup(
    name='ntlm-auth',
    version='1.0.0',
    packages=[ 'ntlm_auth' ],
    install_requires=[ 'six' ],
    author='Jordan Borean',
    author_email='jborean93@gmail.com',
    url='https://github.com/jborean93/ntlm-auth',
    description='Creates NTLM authentication structures',
    long_description="""
        This package can create and parse NTLM authorisation tokens
        with all the latest standards such as NTLMv2, Extended Protection
        (CBT), message integrity and confidentiality (signing and sealing).
    """,
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
