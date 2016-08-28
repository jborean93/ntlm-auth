"""
These values below are tested using the examples in RFC 6229.
https://tools.ietf.org/html/rfc6229

This guide has been verified using 3 different programs and is used to help RC4 implementations

Please do not change the expected results if you test fails, if it does fail it is for a reason
"""

import unittest2 as unittest

from ntlm_auth.rc4 import ARC4
from ..utils import HexToByte

input_hex = HexToByte('00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00')

# Key handles to initialise the ARC4 state
key_40bit = HexToByte('01 02 03 04 05')
key_56bit = HexToByte('01 02 03 04 05 06 07')
key_128bit = HexToByte('01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10')

# Results for offset 0-32 for 40bit keys
line1_40bit = HexToByte('b2 39 63 05 f0 3d c0 27 cc c3 52 4a 0a 11 18 a8')
line2_40bit = HexToByte('69 82 94 4f 18 fc 82 d5 89 c4 03 a4 7a 0d 09 19')

# Results for offset 0-32 for 56bit keys
line1_56bit = HexToByte('29 3f 02 d4 7f 37 c9 b6 33 f2 af 52 85 fe b4 6b')
line2_56bit = HexToByte('e6 20 f1 39 0d 19 bd 84 e2 e0 fd 75 20 31 af c1')

# Results for offset 0-32 for 128bit keys
line1_128bit = HexToByte('9a c7 cc 9a 60 9d 1e f7 b2 93 28 99 cd e4 1b 97')
line2_128bit = HexToByte('52 48 c4 95 90 14 12 6a 6e 8a 84 f1 1d 1a 9e 1c')

# Only testing the 40, 56 and 128 bit key lengths as those are the only supported lengths with NTLM
class Test_ARC4(unittest.TestCase):
    def test_encrypt_40bit_key(self):
        test_handle = ARC4(key_40bit)

        expected1 = line1_40bit
        expected2 = line2_40bit

        actual1 = test_handle.update(input_hex)
        actual2 = test_handle.update(input_hex)

        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_40bit_key(self):
        test_handle = ARC4(key_40bit)
        test1 = line1_40bit
        test2 = line2_40bit

        expected = input_hex

        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)

        assert actual1 == expected
        assert actual2 == expected

    def test_encrypt_56bit_key(self):
        test_handle = ARC4(key_56bit)

        expected1 = line1_56bit
        expected2 = line2_56bit

        actual1 = test_handle.update(input_hex)
        actual2 = test_handle.update(input_hex)

        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_56bit_key(self):
        test_handle = ARC4(key_56bit)
        test1 = line1_56bit
        test2 = line2_56bit

        expected = input_hex

        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)

        assert actual1 == expected
        assert actual2 == expected

    def test_encrypt_128bit_key(self):
        test_handle = ARC4(key_128bit)

        expected1 = line1_128bit
        expected2 = line2_128bit

        actual1 = test_handle.update(input_hex)
        actual2 = test_handle.update(input_hex)

        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_128bit_key(self):
        test_handle = ARC4(key_128bit)
        test1 = line1_128bit
        test2 = line2_128bit

        expected = input_hex

        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)

        assert actual1 == expected
        assert actual2 == expected

