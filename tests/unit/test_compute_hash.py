import unittest2 as unittest # for compatiblity with older version of python

import ntlm_auth.compute_hash as comphash
from ..expected_values import *

class Test_ComputeHash(unittest.TestCase):
    # 4.2.2.1.1 - LMOWFv1()
    def test_lmowfv1(self):
        expected = ntlmv1_lmowfv1

        actual = comphash._lmowfv1(password)

        assert actual == expected

    # 4.2.2.1.2 - NTOWFv1()
    def test_ntowfv1(self):
        expected = ntlmv1_ntowfv1

        actual = comphash._ntowfv1(password)

        assert actual == expected

    # 4.2.4.1.1 - NTOWFv2() and LMOWFv2()
    def test_ntowfv2(self):
        expected = ntlmv2_ntowfv2

        actual = comphash._ntowfv2(user_name, password, domain_name)

        assert actual == expected

    # 4.2.2.1.1 - LMOWFv1()
    def test_lmofv1_hash(self):
        expected = ntlmv1_lmowfv1

        actual = comphash._lmowfv1(password_hash)

        assert actual == expected

    # 4.2.2.1.2 - NTOWFv1()
    def test_ntofv1_hash(self):
        expected = ntlmv1_ntowfv1

        actual = comphash._ntowfv1(password_hash)

        assert actual == expected

    # 4.2.4.1.1 - NTOWFv2() and LMOWFv2()
    def test_ntowfv2(self):
        expected = ntlmv2_ntowfv2

        actual = comphash._ntowfv2(user_name, password_hash, domain_name)

        assert actual == expected
