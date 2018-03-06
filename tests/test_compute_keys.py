import ntlm_auth.compute_keys as compute_keys

from ntlm_auth.constants import NegotiateFlags, SignSealConstants


class TestComputeKeys(object):

    def test_get_exchange_key_ntlm_v1_no_keys(self):
        test_flags = 3791815219
        expected = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                   b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        session_base_key = expected
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        ntlmv1_lmv1_response = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                               b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                               b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
        ntlmv1_lmowfv1 = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                         b"\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"

        actual = compute_keys._get_exchange_key_ntlm_v1(test_flags,
                                                        session_base_key,
                                                        server_challenge,
                                                        ntlmv1_lmv1_response,
                                                        ntlmv1_lmowfv1)
        assert actual == expected

    def test_get_exchange_key_ntlm_v1_non_nt_key(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY

        # Not in document, custom test
        expected = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                   b"\x00\x00\x00\x00\x00\x00\x00\x00"
        session_base_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                           b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        ntlmv1_lmv1_response = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                               b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                               b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
        ntlmv1_lmowfv1 = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                         b"\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"

        actual = compute_keys._get_exchange_key_ntlm_v1(test_flags,
                                                        session_base_key,
                                                        server_challenge,
                                                        ntlmv1_lmv1_response,
                                                        ntlmv1_lmowfv1)
        assert actual == expected

    def test_get_exchange_key_ntlm_v1_lm_key(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY

        # Not in document, custom test
        expected = b"\xb0\x9e\x37\x9f\x7f\xbe\xcb\x1e" \
                   b"\xaf\x0a\xfd\xcb\x03\x83\xc8\xa0"
        session_base_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                           b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        ntlmv1_lmv1_response = b"\x98\xde\xf7\xb8\x7f\x88\xaa\x5d" \
                               b"\xaf\xe2\xdf\x77\x96\x88\xa1\x72" \
                               b"\xde\xf1\x1c\x7d\x5c\xcd\xef\x13"
        ntlmv1_lmowfv1 = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                         b"\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"

        actual = compute_keys._get_exchange_key_ntlm_v1(test_flags,
                                                        session_base_key,
                                                        server_challenge,
                                                        ntlmv1_lmv1_response,
                                                        ntlmv1_lmowfv1)
        assert actual == expected

    def test_get_exchange_key_ntlm_v1_extended_session_security(self):
        test_flags = 2181726771
        expected = b"\xeb\x93\x42\x9a\x8b\xd9\x52\xf8" \
                   b"\xb8\x9c\x55\xb8\x7f\x47\x5e\xdc"
        session_base_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                           b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        lm_response = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                      b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                      b"\x00\x00\x00\x00\x00\x00\x00\x00"
        lm_hash = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x00"

        actual = compute_keys._get_exchange_key_ntlm_v1(test_flags,
                                                        session_base_key,
                                                        server_challenge,
                                                        lm_response,
                                                        lm_hash)
        assert actual == expected

    def test_get_exchange_key_ntlm_v2(self):
        expected = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                   b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        session_base_key = expected

        actual = compute_keys._get_exchange_key_ntlm_v2(session_base_key)
        assert actual == expected

    def test_get_sign_key(self):
        # No need to test multiple version as signing is only available in one
        # scenario, when ess is used
        expected = b"\x47\x88\xdc\x86\x1b\x47\x82\xf3" \
                   b"\x5d\x43\xfd\x98\xfe\x1a\x2d\x39"
        session_base_key = b"\x55" * 16

        actual = compute_keys.get_sign_key(session_base_key,
                                           SignSealConstants.CLIENT_SIGNING)
        assert actual == expected

    def test_get_seal_key_no_flag(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
        expected = b"\x55" * 16
        exported_session_key = expected

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected

    def test_get_seal_key_ntlm1_56(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_56 | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
        # Not in document, custom test
        expected = b"\x55\x55\x55\x55\x55\x55\x55\xa0"
        exported_session_key = b"\x55" * 16

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected

    def test_get_seal_key_ntlm1_40(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
        # Not in document, custom test
        expected = b"\x55\x55\x55\x55\x55\xe5\x38\xb0"
        exported_session_key = b"\x55" * 16

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected

    def test_get_seal_key_ntlm2_128(self):
        test_flags = 3800728115
        expected = b"\x59\xf6\x00\x97\x3c\xc4\x96\x0a" \
                   b"\x25\x48\x0a\x7c\x19\x6e\x4c\x58"
        exported_session_key = b"\x55" * 16

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected

    def test_get_seal_key_ntlm2_56(self):
        test_flags = 2181726771
        expected = b"\x04\xdd\x7f\x01\x4d\x85\x04\xd2" \
                   b"\x65\xa2\x5c\xc8\x6a\x3a\x7c\x06"

        session_base_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                           b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        lm_challenge_response = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x00"
        lm_hash = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x00"
        exported_session_key = compute_keys._get_exchange_key_ntlm_v1(
            test_flags,
            session_base_key,
            server_challenge,
            lm_challenge_response,
            lm_hash
        )

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected

    def test_get_seal_key_ntlm2_40(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        # Not in document, custom test
        expected = b"\x26\xb2\xc1\xe7\x7b\xe4\x53\x3d" \
                   b"\x55\x5a\x22\x0a\x0f\xde\xb9\x6c"

        session_base_key = b"\xd8\x72\x62\xb0\xcd\xe4\xb1\xcb" \
                           b"\x74\x99\xbe\xcc\xcd\xf1\x07\x84"
        server_challenge = b"\x01\x23\x45\x67\x89\xab\xcd\xef"
        lm_challenge_response = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                                b"\x00\x00\x00\x00\x00\x00\x00\x00"
        lm_hash = b"\xaa\xaa\xaa\xaa\xaa\xaa\xaa\xaa" \
                  b"\x00\x00\x00\x00\x00\x00\x00\x00"
        exported_session_key = compute_keys._get_exchange_key_ntlm_v1(
            test_flags,
            session_base_key,
            server_challenge,
            lm_challenge_response,
            lm_hash
        )

        actual = compute_keys.get_seal_key(test_flags,
                                           exported_session_key,
                                           SignSealConstants.CLIENT_SEALING)
        assert actual == expected
