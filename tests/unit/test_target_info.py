import unittest2 as unittest

from ntlm_auth.target_info import TargetInfo
from ..utils import HexToByte

def get_test_target_info():
    target_info = TargetInfo()
    target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME] = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')
    target_info[TargetInfo.MSV_AV_NB_COMPUTER_NAME] = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')

    return target_info

class Test_TargetInfo(unittest.TestCase):
    def test_del_item(self):
        target_info = get_test_target_info()
        # Contains the len and id of MSV_AV_NB_COMPUTER_NAME and the EOL as we have remove MSV_AV_NB_DOMAIN_NAME
        expected = HexToByte('01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00')
        target_info.__delitem__(TargetInfo.MSV_AV_NB_DOMAIN_NAME)
        actual = target_info.get_data()

        assert actual == expected

    def test_add_item(self):
        target_info = get_test_target_info()
        expected = HexToByte('02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00 53 00'
                             '65 00 72 00 76 00 65 00 72 00 03 00 0c 00 53 00 65 00 72 00 76 00'
                             '65 00 72 00 00 00 00 00')
        target_info[TargetInfo.MSV_AV_DNS_COMPUTER_NAME] = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
        actual = target_info.get_data()

        assert actual == expected

    def test_get_item(self):
        target_info = get_test_target_info()
        expected_value = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')
        expected_length = len(expected_value)
        (actual_length, actual_value) = target_info[TargetInfo.MSV_AV_NB_DOMAIN_NAME]

        assert actual_length == expected_length
        assert actual_value == expected_value