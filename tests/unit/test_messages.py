import mock
import unittest2 as unittest # for compatiblity with older version of python

from ntlm_auth.constants import NegotiateFlags, MessageTypes, NTLM_SIGNATURE
from ntlm_auth.messages import NegotiateMessage, ChallengeMessage, AuthenticateMessage, get_random_export_session_key
from ntlm_auth.target_info import TargetInfo
from ..expected_values import *
from ..mock_functions import mock_random, mock_random_session_key, mock_timestamp, mock_version
from ..utils import HexToByte, ByteToHex

class Test_Generic(unittest.TestCase):
    def test_random_session_key(self):
        expected_length = 16

        actual1 = get_random_export_session_key()
        actual2 = get_random_export_session_key()
        actual_length = len(actual1)

        assert actual_length == expected_length
        assert actual1 != actual2

class Test_Negotiate(unittest.TestCase):
    def test_negotiate_with_all(self):
        test_flags = ntlmv1_negotiate_flags

        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 b2 02 e2'
                             '06 00 06 00 28 00 00 00 10 00 10 00 2e 00 00 00'
                             '06 01 b1 1d 00 00 00 0f 44 6f 6d 61 69 6e 43 00'
                             '4f 00 4d 00 50 00 55 00 54 00 45 00 52 00')

        actual = NegotiateMessage(test_flags, domain_name, workstation_name).get_data()

        assert actual == expected

    def test_negotiate_without_version(self):
        test_flags = ntlmv1_negotiate_flags
        test_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION

        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 b2 02 e0'
                             '06 00 06 00 28 00 00 00 10 00 10 00 2e 00 00 00'
                             '00 00 00 00 00 00 00 00 44 6f 6d 61 69 6e 43 00'
                             '4f 00 4d 00 50 00 55 00 54 00 45 00 52 00')

        actual = NegotiateMessage(test_flags, domain_name, workstation_name).get_data()

        assert actual == expected

    def test_negotiate_without_domain_workstation(self):
        test_flags = ntlmv1_negotiate_flags

        expected = HexToByte('4e 54 4c 4d 53 53 50 00 01 00 00 00 32 82 02 e2'
                             '00 00 00 00 28 00 00 00 00 00 00 00 28 00 00 00'
                             '06 01 b1 1d 00 00 00 0f')

        actual = NegotiateMessage(test_flags, None, None).get_data()

        assert actual == expected

class Test_Challenge(unittest.TestCase):
    def test_challenge_no_version(self):
        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = ntlmv1_negotiate_flags
        expected_server_challenge = server_challenge
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = None

        actual = ChallengeMessage(ntlmv1_challenge_message)

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

    def test_challenge(self):
        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = ntlmv1_with_ess_negotiate_flags
        expected_server_challenge = server_challenge
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual = ChallengeMessage(ntlmv1_with_ess_challenge_message)

        actual_message_type = actual.message_type
        actual_negotiate_flags = actual.negotiate_flags
        actual_server_challenge = actual.server_challenge
        actual_signature = actual.signature
        actual_target_info = actual.target_info
        actual_target_name = actual.target_name
        actual_version = actual.version

        assert actual_message_type == expected_message_type
        assert actual_negotiate_flags == expected_negotiate_flags
        assert actual_server_challenge == expected_server_challenge
        assert actual_signature == expected_signature
        assert actual_target_info == expected_target_info
        assert actual_target_name == expected_target_name
        assert actual_version == expected_version

    def test_challenge_with_target_info(self):
        test_target_info = TargetInfo()
        test_target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = ntlmv2_netbios_domain_name
        test_target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = ntlmv2_netbios_server_name

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = ntlmv2_negotiate_flags
        expected_server_challenge = server_challenge
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.get_data()
        expected_target_name = None
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual = ChallengeMessage(ntlmv2_challenge_message)

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

    def test_challenge_message_with_target_name(self):
        # Same as the test above but with the flags modified to show it has the target name for coverage
        test_target_info = TargetInfo()
        test_target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = ntlmv2_netbios_domain_name
        test_target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = ntlmv2_netbios_server_name
        test_challenge_message = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                           '38 00 00 00 37 82 8a e2 01 23 45 67 89 ab cd ef'
                                           '00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00'
                                           '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                           '65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00'
                                           '69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00'
                                           '65 00 72 00 00 00 00 00')

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 3800728119
        expected_server_challenge = server_challenge
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.get_data()
        expected_target_name = ntlmv2_netbios_server_name
        expected_version = struct.unpack("<q", HexToByte('06 00 70 17 00 00 00 0f'))[0]

        actual = ChallengeMessage(test_challenge_message)

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

class Test_Authenticate(unittest.TestCase):
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    def test_authenticate_message_ntlm_v1(self, session_key, version_function):
        test_challenge_message = ChallengeMessage(ntlmv1_challenge_message)
        # Need to override the flags in the challenge message to match the expectation, these flags are inconsequential and are done manualy for sanity
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_REQUEST_TARGET
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO

        expected = ntlmv1_authenticate_message

        actual = AuthenticateMessage(user_name, password, domain_name, "COMPUTER", test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    def test_authenticate_without_domain_workstation(self, session_key, version_function):
        test_challenge_message = ChallengeMessage(ntlmv1_challenge_message)

        # Not a Microsoft example, using pre-computed value
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '50 00 00 00 18 00 18 00 68 00 00 00 00 00 00 00'
                             '48 00 00 00 08 00 08 00 48 00 00 00 00 00 00 00'
                             '50 00 00 00 10 00 10 00 80 00 00 00 31 82 02 e2'
                             '05 01 28 0a 00 00 00 0f 55 00 73 00 65 00 72 00'
                             '98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72'
                             'de f1 1c 7d 5c cd ef 13 67 c4 30 11 f3 02 98 a2'
                             'ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94'
                             '51 88 22 b1 b3 f3 50 c8 95 86 82 ec bb 3e 3c b7')

        actual = AuthenticateMessage(user_name, password, None, None, test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    def test_authenticate_message_ntlm_v1_non_unicode(self, session_key, version_function):
        test_challenge_message = ChallengeMessage(ntlmv1_challenge_message)
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_NEGOTIATE_OEM

        # Not a Microsoft example, using pre-computed value
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '62 00 00 00 18 00 18 00 7a 00 00 00 06 00 06 00'
                             '48 00 00 00 04 00 04 00 4e 00 00 00 10 00 10 00'
                             '52 00 00 00 10 00 10 00 92 00 00 00 32 82 02 e2'
                             '05 01 28 0a 00 00 00 0f 44 6f 6d 61 69 6e 55 73'
                             '65 72 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00'
                             '52 00 98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88'
                             'a1 72 de f1 1c 7d 5c cd ef 13 67 c4 30 11 f3 02'
                             '98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84'
                             '1f 94 51 88 22 b1 b3 f3 50 c8 95 86 82 ec bb 3e'
                             '3c b7')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation_name, test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    def test_authenticate_message_ntlm_v1_with_extended_security(self, random_function, version_function):
        test_challenge_message = ChallengeMessage(ntlmv1_with_ess_challenge_message)
        # Need to override the flags in the challenge message to match the expectation, these flags are inconsequential and are done manualy for sanity
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected = ntlmv1_with_ess_authenticate_message

        actual = AuthenticateMessage(user_name, password, domain_name, "COMPUTER", test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.messages.get_version', side_effect=mock_version)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_authenticate_message_ntlm_v2(self, random_function, version_function, session_key_function, timestamp_function):
        test_challenge_message = ChallengeMessage(ntlmv2_challenge_message)
        # Need to override the flags in the challenge message to match the expectation, these flags are inconsequential and are done manualy for sanity
        test_challenge_message.negotiate_flags -= NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected = ntlmv2_authenticate_message

        actual = AuthenticateMessage(user_name, password, domain_name, "COMPUTER", test_challenge_message, 3, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_authenticate_message_with_cbt(self, random_function, session_key_function, timestamp_function):
        test_challenge_message = ChallengeMessage(ntlmv2_challenge_message)
        test_server_cert_hash = 'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'

        # Not a Microsoft example, using pre-computed value
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '7c 00 00 00 68 00 68 00 94 00 00 00 0c 00 0c 00'
                             '48 00 00 00 08 00 08 00 54 00 00 00 20 00 20 00'
                             '5c 00 00 00 10 00 10 00 fc 00 00 00 31 82 8a e2'
                             '06 01 b1 1d 00 00 00 0f 44 00 6f 00 6d 00 61 00'
                             '69 00 6e 00 55 00 73 00 65 00 72 00 43 00 00 00'
                             '4f 00 00 00 4d 00 00 00 50 00 00 00 55 00 00 00'
                             '54 00 00 00 45 00 00 00 52 00 00 00 86 c3 50 97'
                             'ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa'
                             'aa aa aa aa 04 10 c4 7a cf 19 97 89 de 7f 20 11'
                             '95 7a ea 50 01 01 00 00 00 00 00 00 00 00 00 00'
                             '00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00'
                             '02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00'
                             '01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00'
                             '0a 00 10 00 6e a1 9d f0 66 da 46 22 05 1f 9c 4f'
                             '92 c6 df 74 00 00 00 00 00 00 00 00 e5 69 95 1d'
                             '15 d4 73 5f 49 e1 4c f9 a7 d3 e6 72')
        actual = AuthenticateMessage(user_name, password, domain_name, workstation_name, test_challenge_message, 3,
                                     test_server_cert_hash)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch("ntlm_auth.messages.get_random_export_session_key", side_effect=mock_random_session_key)
    def test_authenticate_message_with_mic(self, random_function, session_key_function):
        test_challenge_message = ChallengeMessage(ntlmv2_challenge_message)
        test_challenge_message.target_info[TargetInfo.MSV_AV_TIMESTAMP] = mock_timestamp()
        test_server_cert_hash = 'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'
        test_negotiate_message = NegotiateMessage(ntlmv2_negotiate_flags, domain_name, workstation_name)

        # Not a Microsoft example, using pre-computed value
        expected = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                             '8c 00 00 00 7c 00 7c 00 a4 00 00 00 0c 00 0c 00'
                             '58 00 00 00 08 00 08 00 64 00 00 00 20 00 20 00'
                             '6c 00 00 00 10 00 10 00 20 01 00 00 31 82 8a e2'
                             '06 01 b1 1d 00 00 00 0f 77 ff c5 e6 db 55 87 0e'
                             '65 8d 7c ff 33 cd 90 2e 44 00 6f 00 6d 00 61 00'
                             '69 00 6e 00 55 00 73 00 65 00 72 00 43 00 00 00'
                             '4f 00 00 00 4d 00 00 00 50 00 00 00 55 00 00 00'
                             '54 00 00 00 45 00 00 00 52 00 00 00 00 00 00 00'
                             '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             '00 00 00 00 a1 3d 03 8a d0 ca 02 64 33 89 7c 33'
                             '5e 0f 56 df 01 01 00 00 00 00 00 00 00 00 00 00'
                             '00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00'
                             '02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00'
                             '01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00'
                             '07 00 08 00 00 00 00 00 00 00 00 00 06 00 04 00'
                             '02 00 00 00 0a 00 10 00 6e a1 9d f0 66 da 46 22'
                             '05 1f 9c 4f 92 c6 df 74 00 00 00 00 00 00 00 00'
                             '1d 08 89 d1 a5 ee ed 21 91 9e 1a b8 27 c3 0b 17')

        actual = AuthenticateMessage(user_name, password, domain_name, workstation_name, test_challenge_message, 3,
                                     test_server_cert_hash)
        actual.add_mic(test_negotiate_message, test_challenge_message)
        actual = actual.get_data()

        assert actual == expected
