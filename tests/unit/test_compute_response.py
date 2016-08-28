import unittest2 as unittest # for compatiblity with older version of python
import mock
import time

from ntlm_auth.messages import ChallengeMessage
from ntlm_auth.target_info import TargetInfo
from ntlm_auth.compute_response import ComputeResponse, get_windows_timestamp
from ntlm_auth.constants import AvFlags
from ..expected_values import *
from ..mock_functions import mock_random, mock_timestamp
from ..utils import HexToByte

# Test AV_PAIR structure used for NTLMv2 Calculations
target_info = TargetInfo()
target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = ntlmv2_netbios_domain_name
target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = ntlmv2_netbios_server_name

ntlmv1_challenge_message = ChallengeMessage(ntlmv1_challenge_message)
ntlmv1_with_ess_challenge_message = ChallengeMessage(ntlmv1_with_ess_challenge_message)
ntlmv2_challenge_message = ChallengeMessage(ntlmv2_challenge_message)

"""
    [MS-NLMP] v28.0 2016-07-14

    4.2 Cryptographic Values for Validation
    The following tests use known inputs in the documentation and tests
    the outputs for various compute functions set out by Microsoft.
    Please do not modify the expected results unless it is otherwise specified
    as they will validate the functions work correctly.

    For tests that follow Microsoft examples, the examples are stored in expected_values.py
"""
class Test_Generic(unittest.TestCase):
    def test_get_timestamp_format(self):
        actual1 = struct.unpack("<q", get_windows_timestamp())[0]
        time.sleep(1)
        actual2 = struct.unpack("<q", get_windows_timestamp())[0]

        assert actual2 > actual1

class Test_HashResults(unittest.TestCase):
    # 4.2.2.2.2 - LMv1 Response
    def test_get_LMv1_response(self):
        expected = ntlmv1_lmv1_response

        actual = ComputeResponse._get_LMv1_response(password, server_challenge)

        assert actual == expected

    # 4.2.4.2.1 - LMv2 Response
    def test_get_LMv2_response(self):
        expected = ntlmv2_lmv2_response

        actual = ComputeResponse._get_LMv2_response(user_name, password, domain_name, server_challenge, client_challenge)

        assert actual == expected

    # 4.2.2.2.1 - NTLMv1 Response
    def test_get_NTLMv1_response(self):
        expected_response = ntlmv1_ntlmv1_response
        expected_key = ntlmv1_session_base_key

        actual_response, actual_key = ComputeResponse._get_NTLMv1_response(password, server_challenge)

        assert actual_response == expected_response
        assert actual_key == expected_key

    # 4.2.3.2.2 - NTLMv1 Response
    def test_get_NTLM2_response(self):
        expected_response = ntlmv1_with_ess_ntlmv1_response
        expected_key = ntlmv1_with_ess_session_base_key

        actual_response, actual_key = ComputeResponse._get_NTLM2_response(password, server_challenge, client_challenge)

        assert actual_response == expected_response
        assert actual_key == expected_key

    # 4.2.4.1.3 - temp
    def test_nt_v2_temp_response(self):
        test_target_info = TargetInfo(target_info.get_data())

        expected = ntlmv2_temp

        actual = ComputeResponse._get_NTLMv2_temp(timestamp, client_challenge, test_target_info)
        assert actual == expected

    # 4.2.4.2.2 - NTLMv2 Response
    def test_get_NTLMv2_response(self):
        test_target_info = target_info

        expected_response = ntlmv2_ntlmv2_response
        expected_key = ntlmv2_session_base_key

        actual_response, actual_key = ComputeResponse._get_NTLMv2_response(user_name, password, domain_name,
                                                       server_challenge, client_challenge, timestamp, test_target_info)

        assert actual_response == expected_response
        assert actual_key == expected_key

    def test_channel_bindings_value(self):
        # No example is explicitly set in MS-NLMP, using a random certificate hash and checking with the expected outcome
        expected = HexToByte('6E A1 9D F0 66 DA 46 22 05 1F 9C 4F 92 C6 DF 74')

        actual = ComputeResponse._get_channel_bindings_value('E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405')

        assert actual == expected

# Really are the same tests as above with the same expected results but this tests the logic of the lm and nt response method instead of the computation itself
class Test_ChallengeResults(unittest.TestCase):
    def test_lm_v1_response(self):
        test_challenge_message = ntlmv1_challenge_message

        expected = ntlmv1_lmv1_response

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_lm_challenge_response()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    def test_lm_v1_with_extended_security_response(self, random_function):
        test_challenge_message = ntlmv1_with_ess_challenge_message

        expected = ntlmv1_with_ess_lmv1_response

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 1).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v1_with_ntlm_2_response(self):
        test_challenge_message = ntlmv1_challenge_message

        # Not explicity in the example shown but it does expect the same response that we already have set
        expected = ntlmv1_ntlmv1_response

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 2).get_lm_challenge_response()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    def test_lm_v2_response(self, random_function):
        test_challenge_message = ntlmv2_challenge_message

        expected = ntlmv2_lmv2_response

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 3).get_lm_challenge_response()

        assert actual == expected

    @mock.patch('os.urandom', side_effect=mock_random)
    def test_lm_v2_response_with_no_server_target_info_timestamp(self, random_function):
        test_target_info = TargetInfo(target_info.get_data())
        test_challenge_message = ntlmv2_challenge_message
        test_challenge_message.target_info = test_target_info

        expected = ntlmv2_lmv2_response

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message, 3).get_lm_challenge_response()

        assert actual == expected

    def test_lm_v2_response_with_server_target_info_timestamp(self):
        test_target_info = TargetInfo(target_info.get_data())
        test_target_info[TargetInfo.MSV_AV_TIMESTAMP] = timestamp
        test_challenge_message = ntlmv2_challenge_message
        test_challenge_message.target_info = test_target_info

        # Not in MS-NLMP, using expected value
        expected = HexToByte('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                             '00 00 00 00 00 00 00 00')

        actual = ComputeResponse(user_name, password, domain_name, test_challenge_message,
                                 3).get_lm_challenge_response()

        assert actual == expected

    def test_nt_v1_response(self):
        test_challenge_message = ntlmv1_challenge_message

        expected_response = ntlmv1_ntlmv1_response
        expected_exchange_key = ntlmv1_key_exchange_key
        expected_target_info = None

        actual_response, actual_exchange_key, actual_target_info = ComputeResponse(user_name, password, domain_name,
                                                                                   test_challenge_message,
                                                                                   1).get_nt_challenge_response(ntlmv1_lmv1_response, None)

        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info

    @mock.patch('os.urandom', side_effect=mock_random)
    def test_nt_v1_with_extended_security_response(self, random_function):
        test_challenge_message = ntlmv1_with_ess_challenge_message

        expected_response = ntlmv1_with_ess_ntlmv1_response
        expected_exchange_key = ntlmv1_with_ess_key_exchange_key
        expected_target_info = None

        actual_response, actual_exchange_key, actual_target_info = ComputeResponse(user_name, password, domain_name,
                                                                                   test_challenge_message,
                                                                                   1).get_nt_challenge_response(ntlmv1_with_ess_lmv1_response, None)

        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_nt_v2_response(self, random_function, timestamp_function):
        test_target_info = TargetInfo(target_info.get_data())
        test_challenge_message = ntlmv2_challenge_message
        test_challenge_message.target_info = test_target_info

        expected_response = ntlmv2_ntlmv2_response
        expected_exchange_key = ntlmv2_session_base_key #in ntlmv2 session_base key is the same as exchange_key
        expected_target_info = test_target_info

        actual_response, actual_exchange_key, actual_target_info = ComputeResponse(user_name, password, domain_name,
                                                                                   test_challenge_message,
                                                                                   3).get_nt_challenge_response(ntlmv2_lmv2_response, None)

        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info


    # The following tests are different from the Microsoft examples, they don't give an example of these scenarios so I have made them up

    @mock.patch('os.urandom', side_effect=mock_random)
    @mock.patch('ntlm_auth.compute_response.get_windows_timestamp', side_effect=mock_timestamp)
    def test_nt_v2_response_no_target_info(self, random_function, timestamp_function):
        test_challenge_message = ntlmv2_challenge_message
        test_challenge_message.target_info = None

        expected_response = HexToByte('39 56 f2 e5 69 d9 af a3 ac 2d 4f 36 7d 38 b9 c5'
                                      '01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                      'aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00'
                                      '00 00 00 00')
        expected_exchange_key = HexToByte('e3 35 1f 5b e0 a0 2b c2 ee b8 76 52 f7 e0 77 75')
        expected_target_info = TargetInfo()

        actual_response, actual_exchange_key, actual_target_info = ComputeResponse(user_name, password, domain_name,
                                                                                   test_challenge_message,
                                                                                   3).get_nt_challenge_response(ntlmv2_lmv2_response, None)

        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info.get_data() == expected_target_info.get_data()

    @mock.patch('os.urandom', side_effect=mock_random)
    def test_nt_v2_response_with_timestamp_av_pair(self, random_function):
        test_target_info = TargetInfo(target_info.get_data())
        test_target_info[TargetInfo.MSV_AV_TIMESTAMP] = timestamp
        test_challenge_message = ntlmv2_challenge_message
        test_challenge_message.target_info = test_target_info

        expected_response = HexToByte('5d eb f3 87 1c 28 94 b8 1f 16 42 81 ed bf 0b ff'
                                      '01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                      'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                                      '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                                      '53 00 65 00 72 00 76 00 65 00 72 00 07 00 08 00'
                                      '00 00 00 00 00 00 00 00 06 00 04 00 02 00 00 00'
                                      '00 00 00 00 00 00 00 00')
        expected_exchange_key = HexToByte('9b 37 06 8f 99 7a 06 5f e9 c7 20 63 32 88 d4 8f')
        expected_target_info = test_target_info
        expected_target_info[TargetInfo.MSV_AV_FLAGS] = struct.pack("<L", AvFlags.MIC_PROVIDED)

        actual_response, actual_exchange_key, actual_target_info = ComputeResponse(user_name, password, domain_name,
                                                                                   test_challenge_message,
                                                                                   3).get_nt_challenge_response(ntlmv2_lmv2_response, None)

        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info