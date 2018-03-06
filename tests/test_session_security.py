import pytest

from ntlm_auth.constants import NegotiateFlags
from ntlm_auth.session_security import SessionSecurity


class TestSessionSecurity(object):

    def test_invalid_source_param(self):
        with pytest.raises(ValueError) as exc:
            SessionSecurity(3791815219, b"\x55" * 16, source="unknown")
        assert str(exc.value) == "Invalid source parameter unknown, must be " \
                                 "client or server"

    def test_sign_and_seal_message_ntlmv1(self):
        test_session_security = SessionSecurity(3791815219, b"\x55" * 16)

        expected_seal = b"\x56\xfe\x04\xd8\x61\xf9\x31\x9a" \
                        b"\xf0\xd7\x23\x8a\x2e\x3b\x4d\x45" \
                        b"\x7f\xb8"
        expected_sign = b"\x01\x00\x00\x00\x00\x00\x00\x00" \
                        b"\x09\xdc\xd1\xdf\x2e\x45\x9d\x36"

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)
        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_sign_and_seal_message_ntlm2_no_key_exchange(self):
        session_key = b"\xeb\x93\x42\x9a\x8b\xd9\x52\xf8" \
                      b"\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc"
        test_session_security = SessionSecurity(2181726771, session_key)

        expected_seal = b"\xa0\x23\x72\xf6\x53\x02\x73\xf3" \
                        b"\xaa\x1e\xb9\x01\x90\xce\x52\x00" \
                        b"\xc9\x9d"
        expected_sign = b"\x01\x00\x00\x00\xff\x2a\xeb\x52" \
                        b"\xf6\x81\x79\x3a\x00\x00\x00\x00"

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)
        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_sign_and_seal_message_ntlm2_key_exchange(self):
        test_session_security = SessionSecurity(3800728116, b"\x55" * 16)

        expected_seal = b"\x54\xe5\x01\x65\xbf\x19\x36\xdc" \
                        b"\x99\x60\x20\xc1\x81\x1b\x0f\x06" \
                        b"\xfb\x5f"
        expected_sign = b"\x01\x00\x00\x00\x7f\xb3\x8e\xc5" \
                        b"\xc5\x5d\x49\x76\x00\x00\x00\x00"

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)
        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_unseal_message_ntlm1(self):
        negotiate_flags = 3791815219
        session_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1" \
                      b"\xcb\x74\x99\xbe\xcc\xcd\xf1" \
                      b"\x07\x84"
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data
        actual_data = test_session_security.unwrap(test_message,
                                                   test_signature)
        assert actual_data == expected_data

    def test_unseal_message_ntlm2_no_key_exchange(self):
        negotiate_flags = 2181726771
        session_key = b"\xeb\x93\x42\x9a\x8b\xd9\x52\xf8" \
                      b"\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc"
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data
        actual_data = test_session_security.unwrap(test_message,
                                                   test_signature)
        assert actual_data == expected_data

    def test_unseal_message_ntlm2_key_exchange(self):
        negotiate_flags = 3800728116
        session_key = b"\xff" * 16
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data
        actual_data = test_session_security.unwrap(test_message,
                                                   test_signature)
        assert actual_data == expected_data

    def test_unseal_message_incorrect_checksum(self):
        negotiate_flags = 3800728116
        session_key = b"\xff" * 16
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)
        # Overwrite signature to produce a bad checksum
        test_signature = b"\x01\x00\x00\x00\xb1\x98\xb8\x47" \
                         b"\xce\x7c\x58\x07\x00\x00\x00\x00"

        with pytest.raises(Exception) as exc:
            test_session_security.unwrap(test_message, test_signature)
        assert str(exc.value) == "The signature checksum does not match, " \
                                 "message has been altered"

    def test_unseal_message_incorrect_seq_num(self):
        negotiate_flags = 3800728116
        session_key = b"\xff" * 16
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)
        # Overwrite signature to produce a bad checksum
        test_signature = test_signature[:-4] + b"\x01\x00\x00\x00"

        with pytest.raises(Exception) as exc:
            test_session_security.unwrap(test_message, test_signature)

        assert str(exc.value) == "The signature sequence number does not " \
                                 "match up, message not received in the " \
                                 "correct sequence"

    def test_sign_no_seal_message(self):
        negotiate_flags = 3800728116 - NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
        test_session_security = SessionSecurity(negotiate_flags, b"\x55" * 16)

        expected_seal = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                        b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                        b"\x74\x00"
        # Because we aren't sealing beforehand the signature will be different
        # from the example
        expected_sign = b"\x01\x00\x00\x00\x74\xd0\x45\x34" \
                        b"\x2c\x4f\x1c\xd5\x00\x00\x00\x00"

        actual_seal, actual_sign = test_session_security.wrap(expected_seal)
        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_verify_sign_no_unseal_message(self):
        negotiate_flags = 3800728116 - NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
        session_key = b"\x55" * 16
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data
        actual_data = test_session_security.unwrap(test_message,
                                                   test_signature)
        assert test_message == expected_data
        assert actual_data == expected_data

    def test_nosign_or_seal_message(self):
        negotiate_flags = 3800728116 - \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL - \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
        test_session_security = SessionSecurity(negotiate_flags, b"\x55" * 16)

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        expected_seal = plaintext_data
        expected_sign = None

        actual_seal, actual_sign = test_session_security.wrap(plaintext_data)
        assert actual_seal == expected_seal
        assert actual_sign == expected_sign

    def test_no_verify_or_unseal_message(self):
        negotiate_flags = 3800728116 - \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL - \
                          NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN
        session_key = b"\x55" * 16
        test_session_security = SessionSecurity(negotiate_flags, session_key)
        test_server_session_security = SessionSecurity(negotiate_flags,
                                                       session_key,
                                                       source="server")

        plaintext_data = b"\x50\x00\x6c\x00\x61\x00\x69\x00" \
                         b"\x6e\x00\x74\x00\x65\x00\x78\x00" \
                         b"\x74\x00"
        test_message, test_signature = \
            test_server_session_security.wrap(plaintext_data)

        expected_data = plaintext_data
        actual_data = test_session_security.unwrap(test_message,
                                                   test_signature)
        assert test_message == expected_data
        assert test_signature is None
        assert actual_data == expected_data
