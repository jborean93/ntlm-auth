import pytest

from ntlm_auth.rc4 import _CryptographyARC4, _PythonARC4


@pytest.fixture(autouse=True)
def rc4(has_crypto):
    return _CryptographyARC4 if has_crypto else _PythonARC4


@pytest.mark.parametrize('has_crypto', [True, False])
class TestARC4(object):

    def test_encrypt_40bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05")
        expected1 = b"\xb2\x39\x63\x05\xf0\x3d\xc0\x27" \
                    b"\xcc\xc3\x52\x4a\x0a\x11\x18\xa8"
        expected2 = b"\x69\x82\x94\x4f\x18\xfc\x82\xd5" \
                    b"\x89\xc4\x03\xa4\x7a\x0d\x09\x19"
        actual1 = test_handle.update(b"\x00" * 16)
        actual2 = test_handle.update(b"\x00" * 16)
        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_40bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05")
        test1 = b"\xb2\x39\x63\x05\xf0\x3d\xc0\x27" \
                b"\xcc\xc3\x52\x4a\x0a\x11\x18\xa8"
        test2 = b"\x69\x82\x94\x4f\x18\xfc\x82\xd5" \
                b"\x89\xc4\x03\xa4\x7a\x0d\x09\x19"
        expected = b"\x00" * 16
        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)
        assert actual1 == expected
        assert actual2 == expected

    def test_encrypt_56bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05\x06\x07")
        expected1 = b"\x29\x3f\x02\xd4\x7f\x37\xc9\xb6" \
                    b"\x33\xf2\xaf\x52\x85\xfe\xb4\x6b"
        expected2 = b"\xe6\x20\xf1\x39\x0d\x19\xbd\x84" \
                    b"\xe2\xe0\xfd\x75\x20\x31\xaf\xc1"
        actual1 = test_handle.update(b"\x00" * 16)
        actual2 = test_handle.update(b"\x00" * 16)
        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_56bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05\x06\x07")
        test1 = b"\x29\x3f\x02\xd4\x7f\x37\xc9\xb6" \
                b"\x33\xf2\xaf\x52\x85\xfe\xb4\x6b"
        test2 = b"\xe6\x20\xf1\x39\x0d\x19\xbd\x84" \
                b"\xe2\xe0\xfd\x75\x20\x31\xaf\xc1"
        expected = b"\x00" * 16
        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)
        assert actual1 == expected
        assert actual2 == expected

    def test_encrypt_128bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05\x06\x07\x08"
                          b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
        expected1 = b"\x9a\xc7\xcc\x9a\x60\x9d\x1e\xf7" \
                    b"\xb2\x93\x28\x99\xcd\xe4\x1b\x97"
        expected2 = b"\x52\x48\xc4\x95\x90\x14\x12\x6a" \
                    b"\x6e\x8a\x84\xf1\x1d\x1a\x9e\x1c"
        actual1 = test_handle.update(b"\x00" * 16)
        actual2 = test_handle.update(b"\x00" * 16)
        assert actual1 == expected1
        assert actual2 == expected2

    def test_decrypt_128bit_key(self, rc4):
        test_handle = rc4(b"\x01\x02\x03\x04\x05\x06\x07\x08"
                          b"\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10")
        test1 = b"\x9a\xc7\xcc\x9a\x60\x9d\x1e\xf7" \
                b"\xb2\x93\x28\x99\xcd\xe4\x1b\x97"
        test2 = b"\x52\x48\xc4\x95\x90\x14\x12\x6a" \
                b"\x6e\x8a\x84\xf1\x1d\x1a\x9e\x1c"
        expected = b"\x00" * 16
        actual1 = test_handle.update(test1)
        actual2 = test_handle.update(test2)
        assert actual1 == expected
        assert actual2 == expected
