import struct
import time

from ntlm_auth.compute_response import ComputeResponse, get_windows_timestamp
from ntlm_auth.constants import AvId, AvFlags
from ntlm_auth.messages import ChallengeMessage, TargetInfo


class TestGeneric(object):

    def test_get_timestamp_format(self):
        actual1 = struct.unpack("<q", get_windows_timestamp())[0]
        time.sleep(1)
        actual2 = struct.unpack("<q", get_windows_timestamp())[0]
        assert actual2 > actual1


class TestHashResults(object):

    def test_get_LMv1_response(self):
        # 4.2.2.2.2 - LMv1 Response
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                   b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                   b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
        actual = ComputeResponse._get_LMv1_response("Password",
                                                    server_challenge)
        assert actual == expected

    def test_get_LMv2_response(self):
        # 4.2.4.2.1 - LMv2 Response
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        client_challenge = b"\xaa" * 8
        expected = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                   b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                   b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        actual = ComputeResponse._get_LMv2_response("User", "Password",
                                                    "Domain", server_challenge,
                                                    client_challenge)
        assert actual == expected

    def test_get_NTLMv1_response(self):
        # 4.2.2.2.1 - NTLMv1 Response
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected_response = b"\x67\xc4\x30\x11\xf3\x02\x98\xa2" \
                            b"\xad\x35\xec\xe6\x4f\x16\x33\x1c" \
                            b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
        expected_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                       b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        actual_response, actual_key = \
            ComputeResponse._get_NTLMv1_response("Password", server_challenge)
        assert actual_response == expected_response
        assert actual_key == expected_key

    def test_get_NTLM2_response(self):
        # 4.2.3.2.2 - NTLMv1 Response
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        client_challenge = b"\xaa" * 8
        expected_response = b"\x75\x37\xf8\x03\xae\x36\x71\x28" \
                            b"\xca\x45\x82\x04\xbd\xe7\xca\xf8" \
                            b"\x1e\x97\xed\x26\x83\x26\x72\x32"
        expected_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                       b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"

        actual_response, actual_key = \
            ComputeResponse._get_NTLM2_response("Password", server_challenge,
                                                client_challenge)
        assert actual_response == expected_response
        assert actual_key == expected_key

    def test_nt_v2_temp_response(self):
        # 4.2.4.1.3 - temp
        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        expected = b"\x01\x01\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                   b"\x00\x00\x00\x00\x02\x00\x0c\x00" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
                   b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                   b"\x65\x00\x72\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00"

        actual = ComputeResponse._get_NTLMv2_temp(b"\x00" * 8, b"\xaa" * 8,
                                                  test_target_info)
        assert actual == expected

    def test_get_NTLMv2_response(self):
        # 4.2.4.2.2 - NTLMv2 Response
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        client_challenge = b"\xaa" * 8
        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        expected_response = b"\x68\xcd\x0a\xb8\x51\xe5\x1c\x96" \
                            b"\xaa\xbc\x92\x7b\xeb\xef\x6a\x1c" \
                            b"\x01\x01\x00\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                            b"\x00\x00\x00\x00\x02\x00\x0c\x00" \
                            b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                            b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
                            b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                            b"\x65\x00\x72\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00"
        expected_key = b"\x8d\xe4\x0c\xca\xdb\xc1\x4a\x82" \
                       b"\xf1\x5c\xb0\xad\x0d\xe9\x5c\xa3"

        actual_response, actual_key = \
            ComputeResponse._get_NTLMv2_response("User", "Password", "Domain",
                                                 server_challenge,
                                                 client_challenge, b"\x00" * 8,
                                                 test_target_info)

        assert actual_response == expected_response
        assert actual_key == expected_key


class TestChallengeResults(object):

    def test_lm_v1_response(self):
        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        expected = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                   b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                   b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 1).get_lm_challenge_response()
        assert actual == expected

    def test_lm_v1_with_extended_security_response(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)

        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x0a\x82"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        expected = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00"
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 1).get_lm_challenge_response()
        assert actual == expected

    def test_lm_v1_with_ntlm_2_response(self):
        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )

        # Not explicitly in the example shown but it does expect the same
        # response that we already have set
        expected = b"\x67\xc4\x30\x11\xf3\x02\x98\xa2" \
                   b"\xad\x35\xec\xe6\x4f\x16\x33\x1c" \
                   b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 2).get_lm_challenge_response()
        assert actual == expected

    def test_lm_v2_response(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)

        test_challenge_message = ChallengeMessage(
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

        expected = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                   b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                   b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 3).get_lm_challenge_response()
        assert actual == expected

    def test_lm_v2_response_with_no_target_info_timestamp(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)

        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        test_challenge_message = ChallengeMessage(
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
        test_challenge_message.target_info = test_target_info

        expected = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                   b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                   b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 3).get_lm_challenge_response()
        assert actual == expected

    def test_lm_v2_response_with_server_target_info_timestamp(self):
        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        test_target_info[AvId.MSV_AV_TIMESTAMP] = b"\x00" * 8

        test_challenge_message = ChallengeMessage(
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
        test_challenge_message.target_info = test_target_info

        # Not in MS-NLMP, using expected value
        expected = b"\x00" * 24
        actual = ComputeResponse("User", "Password", "Domain",
                                 test_challenge_message,
                                 3).get_lm_challenge_response()
        assert actual == expected

    def test_nt_v1_response(self):
        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        test_lmv1_response = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                             b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                             b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"

        expected_response = b"\x67\xc4\x30\x11\xf3\x02\x98\xa2" \
                            b"\xad\x35\xec\xe6\x4f\x16\x33\x1c" \
                            b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94"
        expected_exchange_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                                b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        expected_target_info = None

        comp_response = ComputeResponse("User", "Password", "Domain",
                                        test_challenge_message, 1)
        actual_response, actual_exchange_key, actual_target_info = \
            comp_response.get_nt_challenge_response(test_lmv1_response, None)
        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info

    def test_nt_v1_with_extended_security_response(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)

        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x0a\x82"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x00\x00\x00\x00\x00"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        test_lmv1_response = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                             b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                             b"\x00\x00\x00\x00\x00\x00\x00\x00"

        expected_response = b"\x75\x37\xf8\x03\xae\x36\x71\x28" \
                            b"\xca\x45\x82\x04\xbd\xe7\xca\xf8" \
                            b"\x1e\x97\xed\x26\x83\x26\x72\x32"
        expected_exchange_key = b"\xeb\x93\x42\x9a\x8b\xd9\x52\xf8" \
                                b"\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc"
        expected_target_info = None

        comp_response = ComputeResponse("User", "Password", "Domain",
                                        test_challenge_message, 1)
        actual_response, actual_exchange_key, actual_target_info = \
            comp_response.get_nt_challenge_response(test_lmv1_response, None)
        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info

    def test_nt_v2_response(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.compute_response.get_windows_timestamp',
                            lambda: b"\x00" * 8)

        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        test_challenge_message = ChallengeMessage(
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
        test_challenge_message.target_info = test_target_info

        test_lmv2_response = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                             b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                             b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"

        expected_response = b"\x68\xcd\x0a\xb8\x51\xe5\x1c\x96" \
                            b"\xaa\xbc\x92\x7b\xeb\xef\x6a\x1c" \
                            b"\x01\x01\x00\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                            b"\x00\x00\x00\x00\x02\x00\x0c\x00" \
                            b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                            b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
                            b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                            b"\x65\x00\x72\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00"
        expected_exchange_key = b"\x8d\xe4\x0c\xca\xdb\xc1\x4a\x82" \
                                b"\xf1\x5c\xb0\xad\x0d\xe9\x5c\xa3"
        expected_target_info = test_target_info

        comp_response = ComputeResponse("User", "Password", "Domain",
                                        test_challenge_message, 3)
        actual_response, actual_exchange_key, actual_target_info = \
            comp_response.get_nt_challenge_response(test_lmv2_response, None)
        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info

    # The following tests are different from the Microsoft examples, they don't
    # give an example of these scenarios so I have made them up

    def test_nt_v2_response_no_target_info(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.compute_response.get_windows_timestamp',
                            lambda: b"\x00" * 8)

        test_challenge_message = ChallengeMessage(
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
        test_challenge_message.target_info = None

        test_lmv2_response = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                             b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                             b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"

        expected_response = b"\x39\x56\xf2\xe5\x69\xd9\xaf\xa3" \
                            b"\xac\x2d\x4f\x36\x7d\x38\xb9\xc5" \
                            b"\x01\x01\x00\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00"
        expected_exchange_key = b"\xe3\x35\x1f\x5b\xe0\xa0\x2b\xc2" \
                                b"\xee\xb8\x76\x52\xf7\xe0\x77\x75"
        expected_target_info = TargetInfo()

        comp_response = ComputeResponse("User", "Password", "Domain",
                                        test_challenge_message, 3)
        actual_response, actual_exchange_key, actual_target_info = \
            comp_response.get_nt_challenge_response(test_lmv2_response, None)
        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info.pack() == expected_target_info.pack()

    def test_nt_v2_response_with_timestamp_av_pair(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)

        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        test_target_info[AvId.MSV_AV_TIMESTAMP] = b"\x00" * 8

        test_challenge_message = ChallengeMessage(
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
        test_challenge_message.target_info = test_target_info

        test_lmv2_response = b"\x86\xc3\x50\x97\xac\x9c\xec\x10" \
                             b"\x25\x54\x76\x4a\x57\xcc\xcc\x19" \
                             b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa"

        expected_response = b"\x5d\xeb\xf3\x87\x1c\x28\x94\xb8" \
                            b"\x1f\x16\x42\x81\xed\xbf\x0b\xff" \
                            b"\x01\x01\x00\x00\x00\x00\x00\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                            b"\x00\x00\x00\x00\x02\x00\x0c\x00" \
                            b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                            b"\x69\x00\x6e\x00\x01\x00\x0c\x00" \
                            b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                            b"\x65\x00\x72\x00\x07\x00\x08\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                            b"\x06\x00\x04\x00\x02\x00\x00\x00" \
                            b"\x00\x00\x00\x00\x00\x00\x00\x00"
        expected_exchange_key = b"\x9b\x37\x06\x8f\x99\x7a\x06\x5f" \
                                b"\xe9\xc7\x20\x63\x32\x88\xd4\x8f"
        expected_target_info = test_target_info
        expected_target_info[AvId.MSV_AV_FLAGS] = \
            struct.pack("<L", AvFlags.MIC_PROVIDED)

        comp_response = ComputeResponse("User", "Password", "Domain",
                                        test_challenge_message, 3)
        actual_response, actual_exchange_key, actual_target_info = \
            comp_response.get_nt_challenge_response(test_lmv2_response, None)
        assert actual_response == expected_response
        assert actual_exchange_key == expected_exchange_key
        assert actual_target_info == expected_target_info
