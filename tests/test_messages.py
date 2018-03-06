from ntlm_auth.constants import AvId, NegotiateFlags, MessageTypes, \
    NTLM_SIGNATURE
from ntlm_auth.messages import AuthenticateMessage, ChallengeMessage, \
    NegotiateMessage, TargetInfo, get_random_export_session_key


class TestGeneric(object):

    def test_random_session_key(self):
        expected_length = 16
        actual1 = get_random_export_session_key()
        actual2 = get_random_export_session_key()
        actual_length = len(actual1)
        assert actual_length == expected_length
        assert actual1 != actual2


class TestTargetInfo(object):
    def test_del_item(self):
        target_info = TargetInfo()
        target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        del target_info[AvId.MSV_AV_NB_DOMAIN_NAME]

        # Contains the len and id of MSV_AV_NB_COMPUTER_NAME and the EOL as we
        # have remove MSV_AV_NB_DOMAIN_NAME
        expected = b"\x01\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x00\x00\x00\x00"
        actual = target_info.pack()
        assert actual == expected

    def test_add_item(self):
        target_info = TargetInfo()
        target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        expected = b"\x02\x00\x0c\x00\x44\x00\x6f\x00" \
                   b"\x6d\x00\x61\x00\x69\x00\x6e\x00" \
                   b"\x01\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x03\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x00\x00\x00\x00"
        target_info[AvId.MSV_AV_DNS_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"
        actual = target_info.pack()

        assert actual == expected

    def test_get_item(self):
        target_info = TargetInfo()
        target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        expected_value = b"\x44\x00\x6f\00\x6d\x00\x61\x00" \
                         b"\x69\x00\x6e\x00"
        expected_length = len(expected_value)
        actual = target_info[AvId.MSV_AV_NB_DOMAIN_NAME]
        assert len(actual) == expected_length
        assert actual == expected_value


class TestNegotiate(object):

    def test_negotiate_with_all(self):
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x01\x00\x00\x00\x32\xb2\x02\xe2" \
                   b"\x06\x00\x06\x00\x28\x00\x00\x00" \
                   b"\x08\x00\x08\x00\x2e\x00\x00\x00" \
                   b"\x06\x01\xb1\x1d\x00\x00\x00\x0f" \
                   b"\x44\x6f\x6d\x61\x69\x6e\x43\x4f" \
                   b"\x4d\x50\x55\x54\x45\x52"
        actual = NegotiateMessage(3791815219, "Domain", "COMPUTER").get_data()
        assert actual == expected

    def test_negotiate_without_version(self):
        test_flags = 3791815219 - NegotiateFlags.NTLMSSP_NEGOTIATE_VERSION
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x01\x00\x00\x00\x32\xb2\x02\xe0" \
                   b"\x06\x00\x06\x00\x28\x00\x00\x00" \
                   b"\x08\x00\x08\x00\x2e\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x44\x6f\x6d\x61\x69\x6e\x43\x4f" \
                   b"\x4d\x50\x55\x54\x45\x52"
        actual = NegotiateMessage(test_flags, "Domain", "COMPUTER").get_data()
        assert actual == expected

    def test_negotiate_without_domain_workstation(self):
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x01\x00\x00\x00\x32\x82\x02\xe2" \
                   b"\x00\x00\x00\x00\x28\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x28\x00\x00\x00" \
                   b"\x06\x01\xb1\x1d\x00\x00\x00\x0f"
        actual = NegotiateMessage(3791815219, None, None).get_data()
        assert actual == expected


class TestChallenge(object):

    def test_challenge_no_version(self):
        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 3791815219
        expected_server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = None

        challenge_msg = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                        b"\x02\x00\x00\x00\x0c\x00\x0c\x00" \
                        b"\x38\x00\x00\x00\x33\x82\x02\xe2" \
                        b"\x01\x23\x45\x67\x89\xab\xcd\xef" \
                        b"\x06\x00\x70\x17\x00\x00\x00\x0f" \
                        b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                        b"\x65\x00\x72\x00"
        actual = ChallengeMessage(challenge_msg)

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
        expected_negotiate_flags = 2181726771
        expected_server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected_signature = NTLM_SIGNATURE
        expected_target_info = None
        expected_target_name = None
        expected_version = 1080863910962135046

        challenge_msg = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                        b"\x02\x00\x00\x00\x0c\x00\x0c\x00" \
                        b"\x38\x00\x00\x00\x33\x82\x0a\x82" \
                        b"\x01\x23\x45\x67\x89\xab\xcd\xef" \
                        b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                        b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                        b"\x06\x00\x70\x17\x00\x00\x00\x0f" \
                        b"\x53\x00\x65\x00\x72\x00\x76\x00" \
                        b"\x65\x00\x72\x00"
        actual = ChallengeMessage(challenge_msg)

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

    def test_challenge_message_with_target_name(self):
        # Same as the test above but with the flags modified to show it has the
        # target name for coverage
        test_target_info = TargetInfo()
        test_target_info[AvId.MSV_AV_NB_DOMAIN_NAME] = \
            b"\x44\x00\x6f\x00\x6d\x00\x61\x00\x69\x00\x6e\x00"
        test_target_info[AvId.MSV_AV_NB_COMPUTER_NAME] = \
            b"\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00"

        expected_message_type = MessageTypes.NTLM_CHALLENGE
        expected_negotiate_flags = 3800728119
        expected_server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        expected_signature = NTLM_SIGNATURE
        expected_target_info = test_target_info.pack()
        expected_target_name = "Server".encode('utf-16-le')
        expected_version = 1080863910962135046

        challenge_msg = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                        b"\x02\x00\x00\x00\x0c\x00\x0c\x00" \
                        b"\x38\x00\x00\x00\x37\x82\x8a\xe2" \
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
        actual = ChallengeMessage(challenge_msg)

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


class TestAuthenticate(object):

    def test_authenticate_message_ntlm_v1(self, monkeypatch):
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")

        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        # Need to override the flags in the challenge message to match the
        # expectation, these flags are inconsequential and are done manualy for
        # sanity
        test_challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_REQUEST_TARGET
        test_challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_NEGOTIATE_TARGET_INFO

        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x6c\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x84\x00\x00\x00\x0c\x00\x0c\x00" \
                   b"\x48\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x54\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x5c\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x9c\x00\x00\x00\x35\x82\x80\xe2" \
                   b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x55\x00\x73\x00" \
                   b"\x65\x00\x72\x00\x43\x00\x4f\x00" \
                   b"\x4d\x00\x50\x00\x55\x00\x54\x00" \
                   b"\x45\x00\x52\x00\x98\xde\xf7\xb8" \
                   b"\x7f\x88\xaa\x5d\xaf\xe2\xdf\x77" \
                   b"\x96\x88\xa1\x72\xde\xf1\x1c\x7d" \
                   b"\x5c\xcd\xef\x13\x67\xc4\x30\x11" \
                   b"\xf3\x02\x98\xa2\xad\x35\xec\xe6" \
                   b"\x4f\x16\x33\x1c\x44\xbd\xbe\xd9" \
                   b"\x27\x84\x1f\x94\x51\x88\x22\xb1" \
                   b"\xb3\xf3\x50\xc8\x95\x86\x82\xec" \
                   b"\xbb\x3e\x3c\xb7"

        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_without_domain_workstation(self, monkeypatch):
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")

        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )

        # Not a Microsoft example, using pre-computed value
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x50\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x68\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x48\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x48\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x50\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x80\x00\x00\x00\x31\x82\x02\xe2" \
                   b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                   b"\x55\x00\x73\x00\x65\x00\x72\x00" \
                   b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                   b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                   b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13" \
                   b"\x67\xc4\x30\x11\xf3\x02\x98\xa2" \
                   b"\xad\x35\xec\xe6\x4f\x16\x33\x1c" \
                   b"\x44\xbd\xbe\xd9\x27\x84\x1f\x94" \
                   b"\x51\x88\x22\xb1\xb3\xf3\x50\xc8" \
                   b"\x95\x86\x82\xec\xbb\x3e\x3c\xb7"

        actual = AuthenticateMessage("User", "Password", None, None,
                                     test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_message_ntlm_v1_non_unicode(self, monkeypatch):
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")

        test_challenge_message = ChallengeMessage(
            b"\x4e\x54\x4c\x4d\x53\x53\x50\x00"
            b"\x02\x00\x00\x00\x0c\x00\x0c\x00"
            b"\x38\x00\x00\x00\x33\x82\x02\xe2"
            b"\x01\x23\x45\x67\x89\xab\xcd\xef"
            b"\x06\x00\x70\x17\x00\x00\x00\x0f"
            b"\x53\x00\x65\x00\x72\x00\x76\x00"
            b"\x65\x00\x72\x00"
        )
        test_challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_NEGOTIATE_UNICODE
        test_challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_NEGOTIATE_OEM

        # Not a Microsoft example, using pre-computed value
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x5a\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x72\x00\x00\x00\x06\x00\x06\x00" \
                   b"\x48\x00\x00\x00\x04\x00\x04\x00" \
                   b"\x4e\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x52\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x8a\x00\x00\x00\x32\x82\x02\xe2" \
                   b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                   b"\x44\x6f\x6d\x61\x69\x6e\x55\x73" \
                   b"\x65\x72\x43\x4f\x4d\x50\x55\x54" \
                   b"\x45\x52\x98\xde\xf7\xb8\x7f\x88" \
                   b"\xaa\x5d\xaf\xe2\xdf\x77\x96\x88" \
                   b"\xa1\x72\xde\xf1\x1c\x7d\x5c\xcd" \
                   b"\xef\x13\x67\xc4\x30\x11\xf3\x02" \
                   b"\x98\xa2\xad\x35\xec\xe6\x4f\x16" \
                   b"\x33\x1c\x44\xbd\xbe\xd9\x27\x84" \
                   b"\x1f\x94\x51\x88\x22\xb1\xb3\xf3" \
                   b"\x50\xc8\x95\x86\x82\xec\xbb\x3e" \
                   b"\x3c\xb7"
        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_message_ntlm_v1_with_ess(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")

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
        # Need to override the flags in the challenge message to match the
        # expectation, these flags are inconsequential and are done manualy
        # for sanity
        test_challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x6c\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x84\x00\x00\x00\x0c\x00\x0c\x00" \
                   b"\x48\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x54\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x5c\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x9c\x00\x00\x00\x35\x82\x08\x82" \
                   b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x55\x00\x73\x00" \
                   b"\x65\x00\x72\x00\x43\x00\x4f\x00" \
                   b"\x4d\x00\x50\x00\x55\x00\x54\x00" \
                   b"\x45\x00\x52\x00\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x75\x37\xf8\x03" \
                   b"\xae\x36\x71\x28\xca\x45\x82\x04" \
                   b"\xbd\xe7\xca\xf8\x1e\x97\xed\x26" \
                   b"\x83\x26\x72\x32"

        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 1, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_message_ntlm_v2(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_version',
                            lambda s: b"\x05\x01\x28\x0A\x00\x00\x00\x0F")
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
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

        # Need to override the flags in the challenge message to match the
        # expectation, these flags are inconsequential and are done manualy for
        # sanity
        test_challenge_message.negotiate_flags -= \
            NegotiateFlags.NTLMSSP_TARGET_TYPE_SERVER
        test_challenge_message.negotiate_flags |= \
            NegotiateFlags.NTLMSSP_REQUEST_TARGET

        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x6c\x00\x00\x00\x54\x00\x54\x00" \
                   b"\x84\x00\x00\x00\x0c\x00\x0c\x00" \
                   b"\x48\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x54\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x5c\x00\x00\x00\x10\x00\x10\x00" \
                   b"\xd8\x00\x00\x00\x35\x82\x88\xe2" \
                   b"\x05\x01\x28\x0a\x00\x00\x00\x0f" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x55\x00\x73\x00" \
                   b"\x65\x00\x72\x00\x43\x00\x4f\x00" \
                   b"\x4d\x00\x50\x00\x55\x00\x54\x00" \
                   b"\x45\x00\x52\x00\x86\xc3\x50\x97" \
                   b"\xac\x9c\xec\x10\x25\x54\x76\x4a" \
                   b"\x57\xcc\xcc\x19\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x68\xcd\x0a\xb8" \
                   b"\x51\xe5\x1c\x96\xaa\xbc\x92\x7b" \
                   b"\xeb\xef\x6a\x1c\x01\x01\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00" \
                   b"\x02\x00\x0c\x00\x44\x00\x6f\x00" \
                   b"\x6d\x00\x61\x00\x69\x00\x6e\x00" \
                   b"\x01\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\xc5\xda\xd2\x54\x4f\xc9\x79\x90" \
                   b"\x94\xce\x1c\xe9\x0b\xc9\xd0\x3e"

        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 3, None)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_message_with_cbt(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)
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
        test_server_cert_hash = \
            'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'

        # Not a Microsoft example, using pre-computed value
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x6c\x00\x00\x00\x68\x00\x68\x00" \
                   b"\x84\x00\x00\x00\x0c\x00\x0c\x00" \
                   b"\x48\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x54\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x5c\x00\x00\x00\x10\x00\x10\x00" \
                   b"\xec\x00\x00\x00\x31\x82\x8a\xe2" \
                   b"\x06\x01\xb1\x1d\x00\x00\x00\x0f" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x55\x00\x73\x00" \
                   b"\x65\x00\x72\x00\x43\x00\x4f\x00" \
                   b"\x4d\x00\x50\x00\x55\x00\x54\x00" \
                   b"\x45\x00\x52\x00\x86\xc3\x50\x97" \
                   b"\xac\x9c\xec\x10\x25\x54\x76\x4a" \
                   b"\x57\xcc\xcc\x19\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x04\x10\xc4\x7a" \
                   b"\xcf\x19\x97\x89\xde\x7f\x20\x11" \
                   b"\x95\x7a\xea\x50\x01\x01\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00" \
                   b"\x02\x00\x0c\x00\x44\x00\x6f\x00" \
                   b"\x6d\x00\x61\x00\x69\x00\x6e\x00" \
                   b"\x01\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x0a\x00\x10\x00\x6e\xa1\x9d\xf0" \
                   b"\x66\xda\x46\x22\x05\x1f\x9c\x4f" \
                   b"\x92\xc6\xdf\x74\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\xe5\x69\x95\x1d" \
                   b"\x15\xd4\x73\x5f\x49\xe1\x4c\xf9" \
                   b"\xa7\xd3\xe6\x72"
        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 3,
                                     test_server_cert_hash)
        actual.add_mic(None, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected

    def test_authenticate_message_with_mic(self, monkeypatch):
        monkeypatch.setattr('os.urandom', lambda s: b"\xaa" * 8)
        monkeypatch.setattr('ntlm_auth.messages.get_random_export_session_key',
                            lambda: b"\x55" * 16)

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
        test_challenge_message.target_info[AvId.MSV_AV_TIMESTAMP] = b"\x00" * 8
        test_server_cert_hash = \
            'E3CA49271E5089CC48CE82109F1324F41DBEDDC29A777410C738F7868C4FF405'
        test_negotiate_message = NegotiateMessage(3800728115, "Domain",
                                                  "COMPUTER")

        # Not a Microsoft example, using pre-computed value
        expected = b"\x4e\x54\x4c\x4d\x53\x53\x50\x00" \
                   b"\x03\x00\x00\x00\x18\x00\x18\x00" \
                   b"\x7c\x00\x00\x00\x7c\x00\x7c\x00" \
                   b"\x94\x00\x00\x00\x0c\x00\x0c\x00" \
                   b"\x58\x00\x00\x00\x08\x00\x08\x00" \
                   b"\x64\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x6c\x00\x00\x00\x10\x00\x10\x00" \
                   b"\x10\x01\x00\x00\x31\x82\x8a\xe2" \
                   b"\x06\x01\xb1\x1d\x00\x00\x00\x0f" \
                   b"\x8b\x69\xf5\x92\xb2\xd7\x8f\xd7" \
                   b"\x3a\x3a\x49\xdb\xfe\x19\x61\xbc" \
                   b"\x44\x00\x6f\x00\x6d\x00\x61\x00" \
                   b"\x69\x00\x6e\x00\x55\x00\x73\x00" \
                   b"\x65\x00\x72\x00\x43\x00\x4f\x00" \
                   b"\x4d\x00\x50\x00\x55\x00\x54\x00" \
                   b"\x45\x00\x52\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\xa1\x3d\x03\x8a" \
                   b"\xd0\xca\x02\x64\x33\x89\x7c\x33" \
                   b"\x5e\x0f\x56\xdf\x01\x01\x00\x00" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\xaa\xaa\xaa\xaa" \
                   b"\xaa\xaa\xaa\xaa\x00\x00\x00\x00" \
                   b"\x02\x00\x0c\x00\x44\x00\x6f\x00" \
                   b"\x6d\x00\x61\x00\x69\x00\x6e\x00" \
                   b"\x01\x00\x0c\x00\x53\x00\x65\x00" \
                   b"\x72\x00\x76\x00\x65\x00\x72\x00" \
                   b"\x07\x00\x08\x00\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00\x06\x00\x04\x00" \
                   b"\x02\x00\x00\x00\x0a\x00\x10\x00" \
                   b"\x6e\xa1\x9d\xf0\x66\xda\x46\x22" \
                   b"\x05\x1f\x9c\x4f\x92\xc6\xdf\x74" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x1d\x08\x89\xd1\xa5\xee\xed\x21" \
                   b"\x91\x9e\x1a\xb8\x27\xc3\x0b\x17"

        actual = AuthenticateMessage("User", "Password", "Domain", "COMPUTER",
                                     test_challenge_message, 3,
                                     test_server_cert_hash)
        actual.add_mic(test_negotiate_message, test_challenge_message)
        actual = actual.get_data()
        assert actual == expected
