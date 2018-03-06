import base64
import hashlib
import os
import requests
import sys
import warnings

import pytest

from requests.auth import AuthBase

from ntlm_auth.constants import AvId, MessageTypes, NegotiateFlags, \
    NTLM_SIGNATURE
from ntlm_auth.messages import TargetInfo
from ntlm_auth.ntlm import Ntlm

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

    def test_parse_challenge_message(self):
        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            "Domain".encode('utf-16-le')
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            "Server".encode('utf-16-le')
        test_challenge_string = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x03\x00\x0c\x00"
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
        test_ntlm_context.parse_challenge_message(test_challenge_string)

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 3800728115
        expected_server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.pack()
        expected_target_name = None
        expected_version = 1080863910962135046

        actual = test_ntlm_context.challenge_message

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info.pack()
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

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
            b"\x02\x00\x00\x00\x03\x00\x0c\x00"
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
        # Need to override the flags in the challenge message to match the
        # expectation, these flags are inconsequential and are done manually
        # for sanity
        test_ntlm_context.challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_ntlm_context.challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected_message = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x03\x00\x00\x00\x18\x00\x18\x00"
            b"\x6c\x00\x00\x00\x54\x00\x54\x00"
            b"\x84\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x48\x00\x00\x00\x08\x00\x08\x00"
            b"\x54\x00\x00\x00\x10\x00\x10\x00"
            b"\x5c\x00\x00\x00\x10\x00\x10\x00"
            b"\xd8\x00\x00\x00\x35\x82\x88\xe2"
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
        # Need to override the sign and seal flags so they don't return a
        # security context
        test_ntlm_context.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
        test_ntlm_context.negotiate_flags -=\
            NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL

        # Need to override the flags in the challenge message to match the
        # expectation, these flags are inconsequential and are done manualy for
        # sanity
        test_ntlm_context.challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_ntlm_context.challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected_message = base64.b64encode(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x03\x00\x00\x00\x18\x00\x18\x00"
            b"\x6c\x00\x00\x00\x54\x00\x54\x00"
            b"\x84\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x48\x00\x00\x00\x08\x00\x08\x00"
            b"\x54\x00\x00\x00\x10\x00\x10\x00"
            b"\x5c\x00\x00\x00\x10\x00\x10\x00"
            b"\xd8\x00\x00\x00\x35\x82\x88\xe2"
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

    def test_ntlm_3_http_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    81, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_http_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    82, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_with_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    441, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        # Only case where CBT should work as we are using NTLMv2 as the auth
        # type
        assert actual_code == 200
        assert actual_content == "contents"

    def test_ntlm_3_https_without_cbt(self, runner):
        actual = self._send_request(runner[0], runner[1], runner[2], runner[3],
                                    442, 3)
        actual_content = actual.content.decode('utf-8')
        actual_code = actual.status_code

        assert actual_code == 200
        assert actual_content == "contents"

    def _send_request(self, server, domain, username, password, port,
                      ntlm_compatibility):
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
        session.auth = NtlmAuth(domain, username, password, ntlm_compatibility)
        request = requests.Request('GET', url)
        prepared_request = session.prepare_request(request)
        response = session.send(prepared_request)

        return response


# used by the functional tests to auth with an NTLM endpoint
class NtlmAuth(AuthBase):

    def __init__(self, domain, username, password, ntlm_compatibility):
        self.username = username
        self.domain = domain.upper()
        self.password = password
        self.context = Ntlm(ntlm_compatibility=ntlm_compatibility)

    def __call__(self, response):
        response.headers['Connection'] = 'Keep-Alive'
        response.register_hook('response', self.hook)
        return response

    def hook(self, response, **kwargs):
        if response.status_code == 401:
            return self.retry_with_ntlm_auth('www-authenticate',
                                             'Authorization', response,
                                             'NTLM', kwargs)
        else:
            return response

    def retry_with_ntlm_auth(self, auth_header_field, auth_header, response,
                             auth_type, args):
        try:
            cert_hash = self._get_server_cert(response)
        except Exception:
            cert_hash = None

        # Consume the original response contents and release the connection for
        # later
        response.content
        response.raw.release_conn()

        # Create the negotiate request
        msg1_req = response.request.copy()
        msg1 = self.context.create_negotiate_message(self.domain)
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
        self.context.parse_challenge_message(msg2)

        # Create the authenticate request
        msg3_req = msg2_resp.request.copy()

        msg3 = self.context.create_authenticate_message(
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
