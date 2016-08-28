import pytest
import unittest2 as unittest

from ntlm_auth.U32 import U32

class Test_U32(unittest.TestCase):

    def test_can_pass_in_value_via_init(self):
        assert '0x64' in U32(100).__repr__()

    def test_negative_numbers_are_converted_to_positive(self):
        assert '0x64' in U32(-100).__repr__()

    def test_can_set_value_via_method(self):
        n = U32()
        assert '0x0' in n.__repr__()
        n.set(100)
        assert '0x64' in n.__repr__()

    def test_eq_values_are_eq(self):
        assert U32(100) == U32(100)

    def test_can_chr(self):
        assert U32(100).__chr__() == chr(ord('d'))

    def test_can_add(self):
        assert U32(100) + U32(0) == U32(100)
        assert U32(10) + U32(90) == U32(100)

    def test_can_sub(self):
        assert U32(100) - U32(0) == U32(100)
        assert U32(100) - U32(90) == U32(10)

    def test_can_multiply(self):
        assert U32(10) * U32(5) == U32(50)

    def test_can_divide(self):
        assert U32(50) / U32(5) == U32(10)

    def test_can_mod(self):
        assert U32(100) % U32(10) == U32(0)
        assert U32(9) % U32(2) == U32(1)

    def test_can_neg(self):
        assert -U32(100) == U32(100)

    def test_can_pos(self):
        assert +U32(100) == U32(100)

    def test_can_abs(self):
        assert abs(U32(100)) == U32(100)
        assert abs(-U32(100)) == U32(100)

    def test_can_compare(self):
        assert U32(100) > U32(99)
        assert U32(99) < U32(100)
        assert U32(100) == U32(100)
