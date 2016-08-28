import unittest2 as unittest
import mock
import base64

from ntlm_auth.ntlm import Ntlm
from ntlm_auth.target_info import TargetInfo
from ntlm_auth.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE

from ..expected_values import *
from ..mock_functions import mock_random, mock_random_session_key, mock_timestamp, mock_version
from ..utils import HexToByte

default_negotiate_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_128 | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_56 | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_KEY_EXCH | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
default_ntlm_compatibility = 3

class Test_InitialiseNtlm(unittest.TestCase):
    def test_initialise_defaults(self):
        ntlm_context = Ntlm()
        expected_flags = default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = default_ntlm_compatibility

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
        expected_flags = default_negotiate_flags | \
                         NegotiateFlags.NTLMSSP_NEGOTIATE_NTLM | \
                         NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 1

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm2(self):
        ntlm_context = Ntlm(ntlm_compatibility=2)
        expected_flags = default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 2

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm3(self):
        ntlm_context = Ntlm(ntlm_compatibility=3)
        expected_flags = default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 3

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm4(self):
        ntlm_context = Ntlm(ntlm_compatibility=4)
        expected_flags = default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 4

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_ntlm5(self):
        ntlm_context = Ntlm(ntlm_compatibility=5)
        expected_flags = default_negotiate_flags | NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        expected_ntlm_compatibility = 5

        actual_flags = ntlm_context.negotiate_flags
        actual_ntlm_compatibility = ntlm_context.ntlm_compatibility

        assert actual_flags == expected_flags
        assert actual_ntlm_compatibility == expected_ntlm_compatibility

    def test_initialise_with_illegal_ntlm_compatibility_high(self):
        with self.assertRaises(Exception) as context:
            Ntlm(ntlm_compatibility=6)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception.args)

    def test_initialise_with_illegal_ntlm_compatibility_low(self):
        with self.assertRaises(Exception) as context:
            Ntlm(ntlm_compatibility=-1)

        self.assertTrue('Unknown ntlm_compatibility level - expecting value between 0 and 5' in context.exception.args)

class Test_Messages(object):
    # Contains only lightweight tests, the actual message tests and its permutations are in test_message.py
    def test_create_negotiate_message(self):
        test_ntlm_context = Ntlm()

        expected = 'TlRMTVNTUAABAAAAMrCI4gYABgAoAAAAEAAQAC4AAAAGAbEdAAAAD0RvbWFpbkMATwBNAFAAVQBUAEUAUgA='

        actual = test_ntlm_context.create_negotiate_message(domain_name, workstation_name).decode()

        assert actual == expected

    def test_parse_challenge_message(self):
        test_target_info = TargetInfo()
        test_target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = ntlmv2_netbios_domain_name
        test_target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = ntlmv2_netbios_server_name
        test_challenge_string = base64.b64encode(ntlmv2_challenge_message)
        test_ntlm_context = Ntlm()
        test_ntlm_context.parse_challenge_message(test_challenge_string)

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = ntlmv2_negotiate_flags
        expected_server_challenge = server_challenge
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.get_data()
        expected_target_name = None
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual = test_ntlm_context.challenge_message

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info.get_data()
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_create_authenticate_message(self, random_function, version_function, session_key_function, timestamp_function):
        test_challenge_string = base64.b64encode(ntlmv2_challenge_message)
        test_ntlm_context = Ntlm()
        test_ntlm_context.create_negotiate_message(domain_name, workstation_name)
        test_ntlm_context.parse_challenge_message(test_challenge_string)
        # Need to override the flags in the challenge message to match the expectation, these flags are inconsequential and are done manualy for sanity
        test_ntlm_context.challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_ntlm_context.challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected_message = base64.b64encode(ntlmv2_authenticate_message).decode()

        actual_message = test_ntlm_context.create_authenticate_message(user_name, password, domain_name, "COMPUTER").decode()
        actual_session_security = test_ntlm_context.session_security

        assert actual_message == expected_message
        assert actual_session_security is not None

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_create_authenticate_message_without_security(self, random_function, version_function, session_key_function, timestamp_function):
        test_challenge_string = base64.b64encode(ntlmv2_challenge_message)
        test_ntlm_context = Ntlm()
        test_ntlm_context.create_negotiate_message(domain_name, workstation_name)
        test_ntlm_context.parse_challenge_message(test_challenge_string)
        # Need to override the sign and seal flags so they don't return a security context
        test_ntlm_context.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
        test_ntlm_context.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL

        # Need to override the flags in the challenge message to match the expectation, these flags are inconsequential and are done manualy for sanity
        test_ntlm_context.challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_ntlm_context.challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected_message = base64.b64encode(ntlmv2_authenticate_message).decode()

        actual_message = test_ntlm_context.create_authenticate_message(user_name, password, domain_name, "COMPUTER").decode()
        actual_session_security = test_ntlm_context.session_security

        assert actual_message == expected_message
        assert actual_session_security is None