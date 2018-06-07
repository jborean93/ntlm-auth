import base64
import hashlib
import os
import requests
import sys
import warnings

import pytest

from requests.auth import AuthBase

from ntlm_auth.constants import NegotiateFlags
from ntlm_auth.exceptions import NoAuthContextError
from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct
from ntlm_auth.ntlm import Ntlm, NtlmContext
from ntlm_auth.session_security import SessionSecurity

default_negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_128 | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_56 | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL


class TestInitialiseNtlm(object):

    def test_initialise_defaults(self):
        ntlm_context = Ntlm()
        expected_flags = \
            default_negotiate_flags | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 3
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm0(self):
        ntlm_context = Ntlm(ntlm_compatibility=0)
        expected_flags = default_negotiate_flags | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
        expected_ntlm_compatibility = 0
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm1(self):
        ntlm_context = Ntlm(ntlm_compatibility=1)
        expected_flags = \
            default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 1
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm2(self):
        ntlm_context = Ntlm(ntlm_compatibility=2)
        expected_flags = \
            default_negotiate_flags |\
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 2
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm3(self):
        ntlm_context = Ntlm(ntlm_compatibility=3)
        expected_flags = \
            default_negotiate_flags |\
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 3
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm4(self):
        ntlm_context = Ntlm(ntlm_compatibility=4)
        expected_flags = \
            default_negotiate_flags |\
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 4
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm5(self):
        ntlm_context = Ntlm(ntlm_compatibility=5)
        expected_flags = \
            default_negotiate_flags |\
            NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 5
        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility
        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_illegal_ntlm_compatibility_high(self):
        with pytest.raises(Exception) as exc:
            Ntlm(ntlm_compatibility=6)

        assert str(exc.value) == "Unknown ntlm_compatibility level - " \
                                 "expecting value between 0 and 5"

    def test_initialise_with_illegal_ntlm_compatibility_low(self):
        with pytest.raises(Exception) as exc:
            Ntlm(ntlm_compatibility=-1)

        assert str(exc.value) == "Unknown ntlm_compatibility level - " \
                                 "expecting value between 0 and 5"


class TestMessages(object):

    # Contains only lightweight tests, the actual message tests and its
    # permutations are in test_message.py
    def test_create_negotiate_message(self):
        ntlm_context = Ntlm()
        expected = b'TlRMTVNTUAABAAAAMrCI4gYABgAoAAAACAAIAC4AAAA' \
                   b'GAbEdAAAAD0RvbWFpbkNPTVBVVEVS'
        actual = ntlm_context.create_negotiate_message("Domain", "COMPUTER")
        assert actual == expected

    def test_create_authenticate_message(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.compute_response.get_windows_timestamp',
                            lambda: b"\x00" * 8)

        test_challenge_string = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x2f\x82\x88\xe2"
            b"\x38\x00\x00\x00\x33\x82\x8a\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x24\x00\x24\x00\x44\x00\x00\x00"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00\x02\x00\x0c\x00"
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00"
            b"\x69\x00\x6e\x00\x01\x00\x0c\x00"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00\x00\x00\x00\x00"
        )

        test_ntlm_context = Ntlm()
        test_ntlm_context.create_negotiate_message("Domain", "COMPUTER")
        test_ntlm_context.parse_challenge_message(test_challenge_string)

        expected_message = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x03\x00\x00\x00\x18\x00\x18\x00"
            b"\x6c\x00\x00\x00\x54\x00\x54\x00"
            b"\x84\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x48\x00\x00\x00\x08\x00\x08\x00"
            b"\x54\x00\x00\x00\x10\x00\x10\x00"
            b"\x5c\x00\x00\x00\x10\x00\x10\x00"
            b"\xd8\x00\x00\x00\x31\x82\x8a\xe2"
            b"\x05\x01\x28\x0a\x00\x00\x00\x0f"
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00"
            b"\x69\x00\x6e\x00\x55\x00\x73\x00"
            b"\x65\x00\x72\x00\x43\x00\x4f\x00"
            b"\x4d\x00\x50\x00\x55\x00\x54\x00"
            b"\x45\x00\x52\x00\x86\xc3\x50\x97"
            b"\xac\x9c\xec\x10\x25\x54\x76\x4a"
            b"\x57\xcc\xcc\x19\xaa\xaa\xaa\xaa"
            b"\xaa\xaa\xaa\xaa\x68\xcd\x0a\xb8"
            b"\x51\xe5\x1c\x96\xaa\xbc\x92\x7b"
            b"\xeb\xef\x6a\x1c\x01\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa"
            b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00"
            b"\x02\x00\x0c\x00\x44\x00\x6f\x00"
            b"\x6d\x00\x61\x00\x69\x00\x6e\x00"
            b"\x01\x00\x0c\x00\x53\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xc5\xda\xd2\x54\x4f\xc9\x79\x90"
            b"\x94\xce\x1c\xe9\x0b\xc9\xd0\x3e"
        )

        actual_message = \
            test_ntlm_context.create_authenticate_message("User", "Password",
                                                          "Domain", "COMPUTER")

        actual_session_security = test_ntlm_context.session_security

        assert actual_message == expected_message
        assert actual_session_security is not None

    def test_create_authenticate_message_without_security(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.compute_response.get_windows_timestamp',
                            lambda: b"\x00" * 8)

        test_challenge_string = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x03\x00\x0c\x00"
            b"\x38\x00\x00\x00\x03\x92\x8a\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x24\x00\x24\x00\x44\x00\x00\x00"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00\x02\x00\x0c\x00"
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00"
            b"\x69\x00\x6e\x00\x01\x00\x0c\x00"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00\x00\x00\x00\x00"
        )
        test_ntlm_context = Ntlm()
        test_ntlm_context.create_negotiate_message("Domain", "COMPUTER")
        test_ntlm_context.parse_challenge_message(test_challenge_string)

        expected_message = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x03\x00\x00\x00\x18\x00\x18\x00"
            b"\x6c\x00\x00\x00\x54\x00\x54\x00"
            b"\x84\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x48\x00\x00\x00\x08\x00\x08\x00"
            b"\x54\x00\x00\x00\x10\x00\x10\x00"
            b"\x5c\x00\x00\x00\x10\x00\x10\x00"
            b"\xd8\x00\x00\x00\x01\x92\x8a\xe2"
            b"\x05\x01\x28\x0a\x00\x00\x00\x0f"
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00"
            b"\x69\x00\x6e\x00\x55\x00\x73\x00"
            b"\x65\x00\x72\x00\x43\x00\x4f\x00"
            b"\x4d\x00\x50\x00\x55\x00\x54\x00"
            b"\x45\x00\x52\x00\x86\xc3\x50\x97"
            b"\xac\x9c\xec\x10\x25\x54\x76\x4a"
            b"\x57\xcc\xcc\x19\xaa\xaa\xaa\xaa"
            b"\xaa\xaa\xaa\xaa\x68\xcd\x0a\xb8"
            b"\x51\xe5\x1c\x96\xaa\xbc\x92\x7b"
            b"\xeb\xef\x6a\x1c\x01\x01\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa"
            b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00"
            b"\x02\x00\x0c\x00\x44\x00\x6f\x00"
            b"\x6d\x00\x61\x00\x69\x00\x6e\x00"
            b"\x01\x00\x0c\x00\x53\x00\x65\x00"
            b"\x72\x00\x76\x00\x65\x00\x72\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\xc5\xda\xd2\x54\x4f\xc9\x79\x90"
            b"\x94\xce\x1c\xe9\x0b\xc9\xd0\x3e"
        )

        actual_message = \
            test_ntlm_context.create_authenticate_message("User", "Password",
                                                          "Domain", "COMPUTER")
        actual_session_security = test_ntlm_context.session_security

        assert actual_message == expected_message
        assert actual_session_security is None

        # now test the properties map up the the correct NtlmContext ones
        assert test_ntlm_context.authenticate_message == \
            test_ntlm_context._context._authenticate_message
        test_ntlm_context.authenticate_message = b"1"
        assert test_ntlm_context._context._authenticate_message == b"1"

        assert test_ntlm_context.challenge_message == \
            test_ntlm_context._context._challenge_message
        test_ntlm_context.challenge_message = b"2"
        assert test_ntlm_context._context._challenge_message == b"2"

        assert test_ntlm_context.negotiate_flags == \
            test_ntlm_context._context.negotiate_flags
        test_ntlm_context.negotiate_flags = 1
        assert test_ntlm_context._context.negotiate_flags == 1

        assert test_ntlm_context.negotiate_message == \
            test_ntlm_context._context._negotiate_message
        test_ntlm_context.negotiate_message = b"3"
        assert test_ntlm_context._context._negotiate_message == b"3"

        assert test_ntlm_context.ntlm_compatibility == \
            test_ntlm_context._context.ntlm_compatibility
        test_ntlm_context.ntlm_compatibility = 2
        assert test_ntlm_context._context.ntlm_compatibility == 2

        assert test_ntlm_context.session_security == \
            test_ntlm_context._context._session_security
        test_ntlm_context.session_security = b"4"
        assert test_ntlm_context._context._session_security == b"4"


class TestNtlmContext(object):

    def test_ntlm_context(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.compute_response.get_windows_timestamp',
                            lambda: b"\x00" * 8)

        import binascii

        ch = 'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'
        cbt_data = GssChannelBindingsStruct()
        cbt_data[cbt_data.APPLICATION_DATA] = b"tls-server-end-point:" + \
                                              base64.b16decode(ch)
        ntlm_context = NtlmContext("User", "Password", "Domain", "COMPUTER",
                                   cbt_data=cbt_data)
        actual_nego = ntlm_context.step()
        expected_nego = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                        b"\x01\x00\x00\x00\x32\xb0\x88\xe2" \
                        b"\x06\x00\x06\x00\x28\x00\x00\x00" \
                        b"\x08\x00\x08\x00\x2e\x00\x00\x00" \
                        b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                        b"\x44\x6f\x6d\x61\x69\x6e\x43\x4f" \
                        b"\x4d\x50\x55\x54\x45\x52"
        assert actual_nego == expected_nego
        assert not ntlm_context.complete

        challenge_msg = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                        b"\x02\x00\x00\x00\x2f\x82\x88\xe2" \
                        b"\x38\x00\x00\x00\x33\x82\x8a\xe2" \
                        b"\x01\x23\x45\x67\x89\xab\xcd\xef" \
                        b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                        b"\x24\x00\x24\x00\x44\x00\x00\x00" \
                        b"\x06\x00\x70\x17\x00\x00\x00\x0f" \
                        b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                        b"\x65\x00\x72\x00\x02\x00\x0c\x00" \
                        b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                        b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
                        b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                        b"\x65\x00\x72\x00\x00\x00\x00\x00"
        actual_auth = ntlm_context.step(challenge_msg)
        expected_auth = b'\x4e\x54\x4c\x4d\x53\x53\x50\x00' \
                        b'\x03\x00\x00\x00\x18\x00\x18\x00' \
                        b'\x6c\x00\x00\x00\x68\x00\x68\x00' \
                        b'\x84\x00\x00\x00\x0c\x00\x0c\x00' \
                        b'\x48\x00\x00\x00\x08\x00\x08\x00' \
                        b'\x54\x00\x00\x00\x10\x00\x10\x00' \
                        b'\x5c\x00\x00\x00\x10\x00\x10\x00' \
                        b'\xec\x00\x00\x00\x31\x82\x8a\xe2' \
                        b'\x05\x01\x28\x0a\x00\x00\x00\x0f' \
                        b'\x44\x00\x6f\x00\x6d\x00\x61\x00' \
                        b'\x69\x00\x6e\x00\x55\x00\x73\x00' \
                        b'\x65\x00\x72\x00\x43\x00\x4f\x00' \
                        b'\x4d\x00\x50\x00\x55\x00\x54\x00' \
                        b'\x45\x00\x52\x00\x86\xc3\x50\x97' \
                        b'\xac\x9c\xec\x10\x25\x54\x76\x4a' \
                        b'\x57\xcc\xcc\x19\xaa\xaa\xaa\xaa' \
                        b'\xaa\xaa\xaa\xaa\x04\x10\xc4\x7a' \
                        b'\xcf\x19\x97\x89\xde\x7f\x20\x11' \
                        b'\x95\x7a\xea\x50\x01\x01\x00\x00' \
                        b'\x00\x00\x00\x00\x00\x00\x00\x00' \
                        b'\x00\x00\x00\x00\xaa\xaa\xaa\xaa' \
                        b'\xaa\xaa\xaa\xaa\x00\x00\x00\x00' \
                        b'\x02\x00\x0c\x00\x44\x00\x6f\x00' \
                        b'\x6d\x00\x61\x00\x69\x00\x6e\x00' \
                        b'\x01\x00\x0c\x00\x53\x00\x65\x00' \
                        b'\x72\x00\x76\x00\x65\x00\x72\x00' \
                        b'\x0a\x00\x10\x00\x6e\xa1\x9d\xf0' \
                        b'\x66\xda\x46\x22\x05\x1f\x9c\x4f' \
                        b'\x92\xc6\xdf\x74\x00\x00\x00\x00' \
                        b'\x00\x00\x00\x00\xe5\x69\x95\x1d' \
                        b'\x15\xd4\x73\x5f\x49\xe1\x4c\xf9' \
                        b'\xa7\xd3\xe6\x72'

        assert actual_auth == expected_auth
        assert ntlm_context.complete

        request_msg = b"test req"
        response_msg = b"test res"
        actual_wrapped = ntlm_context.wrap(request_msg)
        expected_wrapped = b"\x01\x00\x00\x00\xbc\xe3\x23\xa1" \
                           b"\x72\x06\x23\x78\x00\x00\x00\x00" \
                           b"\x70\x80\x1e\x11\xfe\x6b\x3a\xad"
        assert actual_wrapped == expected_wrapped

        server_sec = SessionSecurity(
            ntlm_context._session_security.negotiate_flags,
            ntlm_context._session_security.exported_session_key, "server"
        )
        server_unwrap = server_sec.unwrap(actual_wrapped[16:],
                                          actual_wrapped[0:16])
        assert server_unwrap == request_msg

        response_wrapped = server_sec.wrap(response_msg)

        actual_unwrap = ntlm_context.unwrap(
            response_wrapped[1] + response_wrapped[0]
        )
        assert actual_unwrap == response_msg

    def test_fail_wrap_no_context(self):
        ntlm_context = NtlmContext("", "")
        with pytest.raises(NoAuthContextError) as err:
            ntlm_context.wrap(b"")
        assert str(err.value) == \
            "Cannot wrap data as no security context has been established"

        with pytest.raises(NoAuthContextError) as err:
            ntlm_context.unwrap(b"")
        assert str(err.value) == \
            "Cannot unwrap data as no security context has been established"


class TestNtlmFunctional(object):
    """
    These tests are functional tests to test out the NTLM calculations and
    message structures with an actual Microsoft server rather than documented
    examples. Because it is reliant on IIS being present this can only run on
    the tests on appveyor and not travis-ci or locally. If these tests past it
    is a fairly good indication that everything works as expected in a real
    life scenario.

    This will test out all 4 NTLM compatibility levels (0-3) that affect client
    behaviour and test out their response code as well as if we can get the IIS
    page's contents. The credentials, urls and expected contents are all set up
    in the appveyor/setup_iis.ps1 script. There are 4 types of scenarios that
    will be tested with each compatibility level;

    1. A HTTP site that has Extended Protection set to None
    2. A HTTP site that has Extended Protection set to Require (CBT Required)
    3. A HTTPS site that has Extended Protection set to None
    4. A HTTPS site that has Extended Protection set to Require (CBT Required)

    Theoretically 1 and 2 are the same as CBT is only checked when running over
    HTTPS but it is best to verify. Scenario 4 would only work when running
    with the compatibility level of 3 as CBT support was only added in NTLMv2
    authentication.
    """

    @pytest.fixture(scope='class', autouse=True)
    def runner(self):
        server = os.environ.get('NTLM_SERVER', None)
        domain = os.environ.get('NTLM_DOMAIN', '')
        username = os.environ.get('NTLM_USERNAME', None)
        password = os.environ.get('NTLM_PASSWORD', None)

        if server and username and password:
            return server, domain, username, password
        else:
            pytest.skip("NTLM_USERNAME, NTLM_PASSWORD, NTLM_SERVER "
                        "environment variables were not set, integration "
                        "tests will be skipped")

    def test_ntlm_0_http_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_0_http_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_0_https_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 0)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_0_https_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 0)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_1_http_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_1_http_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_1_https_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 1)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_1_https_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 1)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_2_http_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_2_http_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_2_https_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 2)
        actual_code = actual.status_code

        # CBT is not support in ntlm levels less than 3, expected a 401
        assert actual_code == 401

    def test_ntlm_2_https_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 2)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_http_with_cbt_dep(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_http_without_cbt_dep(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_with_cbt_dep(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        # Only case where CBT should work as we are using NTLMv2 as the auth
        # type
        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_without_cbt_dep(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_http_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 3, legacy=False)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_http_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 3, legacy=False)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 3, legacy=False)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        # Only case where CBT should work as we are using NTLMv2 as the auth
        # type
        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 3, legacy=False)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def _send_request(self, server, domain, username, password, port,
                      ntlm_compatibility, legacy=True):
        """
        Sends a request to the url with the credentials specified. Returns the
        final response
        """
        # filter out warnings around older Python and unverified connections
        try:
            from requests.packages.urllib3.exceptions import \
                InsecurePlatformWarning
            warnings.simplefilter('ignore', category=InsecurePlatformWarning)
        except ImportError:
            pass

        try:
            from requests.packages.urllib3.exceptions import SNIMissingWarning
            warnings.simplefilter('ignore', category=SNIMissingWarning)
        except ImportError:
            pass

        try:
            from urllib3.exceptions import InsecureRequestWarning
            warnings.simplefilter('ignore', category=InsecureRequestWarning)
        except ImportError:
            pass

        url = "%s://%s:%d/contents.txt" \
              % ('http' if str(port).startswith('8') else 'https',
                 server, port)
        session = requests.Session()
        session.verify = False
        session.auth = NtlmAuth(domain, username, password, ntlm_compatibility,
                                legacy)
        request = requests.Request('GET', url)
        prepared_request = session.prepare_request(request)
        response = session.send(prepared_request)

        return response


# used by the functional tests to auth with an NTLM endpoint
class NtlmAuth(AuthBase):

    def __init__(self, domain, username, password, ntlm_compatibility, legacy):
        self.username = username
        self.domain = domain.upper()
        self.password = password
        self.ntlm_compatibility = ntlm_compatibility
        self.legacy = legacy

    def __call__(self, response):
        response.headers['Connection'] = 'Keep-Alive'
        response.register_hook('response', self.hook)
        return response

    def hook(self, response, **kwargs):
        if response.status_code == 401:
            if self.legacy:
                return self.retry_with_ntlm_auth_legacy('www-authenticate',
                                                        'Authorization',
                                                        response, 'NTLM',
                                                        kwargs)
            else:
                return self.retry_with_ntlm_auth('www-authenticate',
                                                 'Authorization', response,
                                                 'NTLM', kwargs)
        else:
            return response

    def retry_with_ntlm_auth(self, auth_header_field, auth_header, response,
                             auth_type, args):
        try:
            cert_hash = self._get_server_cert(response)
            cbt_data = GssChannelBindingsStruct()
            cbt_data[cbt_data.APPLICATION_DATA] = b"tls-server-end-point:" + \
                                                  base64.b16decode(cert_hash)
        except Exception:
            cbt_data = None

        context = NtlmContext(self.username, self.password, self.domain,
                              cbt_data=cbt_data,
                              ntlm_compatibility=self.ntlm_compatibility)

        # Consume the original response contents and release the connection for
        # later
        response.content
        response.raw.release_conn()

        # Create the negotiate request
        msg1_req = response.request.copy()
        msg1 = context.step()
        msg1_header = "%s %s" % (auth_type, base64.b64encode(msg1).decode())
        msg1_req.headers[auth_header] = msg1_header

        # Send the negotiate request and receive the challenge message
        disable_stream_args = dict(args, stream=False)
        msg2_resp = response.connection.send(msg1_req, **disable_stream_args)
        msg2_resp.content
        msg2_resp.raw.release_conn()

        # Parse the challenge response in the ntlm_context
        msg2_header = msg2_resp.headers[auth_header_field]
        msg2 = msg2_header.replace(auth_type + ' ', '')
        msg3 = context.step(base64.b64decode(msg2))

        # Create the authenticate request
        msg3_req = msg2_resp.request.copy()
        msg3_header = auth_type + ' ' + base64.b64encode(msg3).decode()
        msg3_req.headers[auth_header] = msg3_header

        # Send the authenticate request
        final_response = msg2_resp.connection.send(msg3_req, **args)
        final_response.history.append(response)
        final_response.history.append(msg2_resp)

        return final_response

    def retry_with_ntlm_auth_legacy(self, auth_header_field, auth_header,
                                    response, auth_type, args):
        try:
            cert_hash = self._get_server_cert(response)
        except Exception:
            cert_hash = None

        context = Ntlm(ntlm_compatibility=self.ntlm_compatibility)

        # Consume the original response contents and release the connection for
        # later
        response.content
        response.raw.release_conn()

        # Create the negotiate request
        msg1_req = response.request.copy()
        msg1 = context.create_negotiate_message(self.domain)
        msg1_header = "%s %s" % (auth_type, msg1.decode('ascii'))
        msg1_req.headers[auth_header] = msg1_header

        # Send the negotiate request and receive the challenge message
        disable_stream_args = dict(args, stream=False)
        msg2_resp = response.connection.send(msg1_req, **disable_stream_args)
        msg2_resp.content
        msg2_resp.raw.release_conn()

        # Parse the challenge response in the ntlm_context
        msg2_header = msg2_resp.headers[auth_header_field]
        msg2 = msg2_header.replace(auth_type + ' ', '')
        context.parse_challenge_message(msg2)

        # Create the authenticate request
        msg3_req = msg2_resp.request.copy()

        msg3 = context.create_authenticate_message(
            self.username, self.password, self.domain,
            server_certificate_hash=cert_hash
        )
        msg3_header = auth_type + ' ' + msg3.decode('ascii')
        msg3_req.headers[auth_header] = msg3_header

        # Send the authenticate request
        final_response = msg2_resp.connection.send(msg3_req, **args)
        final_response.history.append(response)
        final_response.history.append(msg2_resp)

        return final_response

    def _get_server_cert(self, response):
        if sys.version_info > (3, 0):
            socket = response.raw._fp.fp.raw._sock
        else:
            socket = response.raw._fp.fp._sock

        server_certificate = socket.getpeercert(True)
        hash_object = hashlib.sha256(server_certificate)
        server_certificate_hash = hash_object.hexdigest().upper()

        return server_certificate_hash
