import unittest2 as unittest # for compatiblity with older version of python

import ntlm_auth.compute_keys as compkeys
from ntlm_auth.constants import NegotiateFlags, SignSealConstants
from ..expected_values import *
from ..utils import HexToByte

class Test_ComputeKeys(unittest.TestCase):
    def test_get_exchange_key_ntlm_v1_no_keys(self):
        test_flags = ntlmv1_negotiate_flags

        expected = ntlmv1_session_base_key

        actual = compkeys._get_exchange_key_ntlm_v1(test_flags, ntlmv1_session_base_key, server_challenge,
                                                    ntlmv1_lmv1_response, ntlmv1_lmowfv1)

        assert actual == expected

    def test_get_exchange_key_ntlm_v1_non_nt_key(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_REQUEST_NON_NT_SESSION_KEY

        # Not in document, custom test
        expected = HexToByte('e5 2c ac 67 41 9a 9a 22 00 00 00 00 00 00 00 00')

        actual = compkeys._get_exchange_key_ntlm_v1(test_flags, ntlmv1_session_base_key, server_challenge,
                                                    ntlmv1_lmv1_response, ntlmv1_lmowfv1)

        assert actual == expected

    def test_get_exchange_key_ntlm_v1_lm_key(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY

        # Not in document, custom test
        expected = HexToByte('b0 9e 37 9f 7f be cb 1e af 0a fd cb 03 83 c8 a0')

        actual = compkeys._get_exchange_key_ntlm_v1(test_flags, ntlmv1_session_base_key, server_challenge,
                                                    ntlmv1_lmv1_response, ntlmv1_lmowfv1)

        assert actual == expected

    def test_get_exchange_key_ntlm_v1_extended_session_security(self):
        test_flags = ntlmv1_with_ess_negotiate_flags
        expected = ntlmv1_with_ess_key_exchange_key

        actual = compkeys._get_exchange_key_ntlm_v1(test_flags, ntlmv1_with_ess_session_base_key, server_challenge,
                                                    ntlmv1_with_ess_lmv1_response, ntlmv1_with_ess_lmowfv1)

        assert actual == expected

    def test_get_exchange_key_ntlm_v2(self):
        expected = session_base_key

        actual = compkeys._get_exchange_key_ntlm_v2(session_base_key)

        assert actual == expected

    def test_get_sign_key(self):
        # No need to test multiple version as signing is only available in one instance, when ess is used
        expected = ntlmv2_sign_key

        actual = compkeys.get_sign_key(session_base_key, SignSealConstants.CLIENT_SIGNING)

        assert actual == expected

    def test_get_seal_key_no_flag(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL
        test_exported_session_key = session_base_key

        expected = session_base_key

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected

    def test_get_seal_key_ntlm1_56(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_56 | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
        test_exported_session_key = session_base_key

        # Not in document, custom test
        expected = HexToByte('55 55 55 55 55 55 55 a0')

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected

    def test_get_seal_key_ntlm1_40(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_LM_KEY
        test_exported_session_key = session_base_key

        # Not in document, custom test
        expected = HexToByte('55 55 55 55 55 e5 38 b0')

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected

    def test_get_seal_key_ntlm2_128(self):
        test_flags = ntlmv2_negotiate_flags
        test_exported_session_key = session_base_key

        expected = ntlmv2_seal_key

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected

    def test_get_seal_key_ntlm2_56(self):
        test_flags = ntlmv1_with_ess_negotiate_flags
        test_session_base_key = ntlmv1_with_ess_session_base_key
        test_exported_session_key = compkeys._get_exchange_key_ntlm_v1(test_flags, test_session_base_key,
                                                                       server_challenge, ntlmv1_with_ess_lmv1_response,
                                                                       ntlmv1_with_ess_lmowfv1)

        expected = ntlmv1_with_ess_seal_key

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected

    def test_get_seal_key_ntlm2_40(self):
        test_flags = NegotiateFlags.NTLMSSP_NEGOTIATE_SIGN | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_SEAL | \
                     NegotiateFlags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        test_session_base_key = ntlmv1_with_ess_session_base_key
        test_exported_session_key = compkeys._get_exchange_key_ntlm_v1(test_flags, test_session_base_key,
                                                                       server_challenge, ntlmv1_with_ess_lmv1_response,
                                                                       ntlmv1_with_ess_lmowfv1)

        # Not in document, custom test
        expected = HexToByte('26 b2 c1 e7 7b e4 53 3d 55 5a 22 0a 0f de b9 6c')

        actual = compkeys.get_seal_key(test_flags, test_exported_session_key, SignSealConstants.CLIENT_SEALING)

        assert actual == expected
