# Changes

## 1.2.0 (Jun 7, 2018)

* Deprecated ntlm_auth.ntlm.Ntlm in favour of ntlm_auth.ntlm.NtlmContext
* This is because `Ntlm` is heavily geared towards HTTP auth which is not always the case, `NtlmContext` makes things more generic
* Updated docs and tests to reflect this
* Dropped support for Python 3.3

## 1.1.0 (Mar 7, 2018)

* Removed DES code as the license was found to be incorrect from the source
* Added new DES code not based on the original
* Fixed up some deprecation warnings
* Changed tests from running unittest to py.test
* Changed licence from GPL to MIT as code is not all my own

## 1.0.6 (Oct 16, 2017)

* More changes to packaging to better handle copyright and licensing

## 1.0.5 (Jun 22, 2017)

* Added support for password hashes when using NTLMv1 authentication
* Better handling of servers that fully conform to the NTLM spec, will check before trying to get the Version field in a challenge message instead of just failing.

## 1.0.2-1.0.4

* Various changes to get Python packaging to work with ordereddict no code changes

## 1.0.1 (Aug 29, 2016)

Major fork from python-ntlm3 which is no longer in active maintenance. Features added since that latest release there;

* Added support for Python 3.5
* Almost complete rewrite of how python-ntlm3 handled authentication to support newer features
* Added support for NTLMv2 auth and fixed up some older auth methods
* Moved code to separate classes to help cleanup the code
* Added support for channel_bindings (CBT) when supplying a certificate hash
* Added support for MIC data for authenticate messages
* Support for signing and sealing of messages
* More comments on each methods relating back to the MS-NLMP document pack on NTLM authentication for easier maintenance
* Created target_info.py to handle AV_PAIRS and putting it in the target info
* Renaming of some variables to match more closely with the Microsoft documentation, makes it easier to understand what is happening
* Rewriting of tests to accommodate these new changes and to cover the new cases
