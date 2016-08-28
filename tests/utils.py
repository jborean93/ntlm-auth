from binascii import unhexlify, hexlify
from ntlm_auth.constants import NegotiateFlags

def dump_flags(negotiate_flags):
    """
    Print out the negotiate flags used in a packed values. Will also print out a warning if an unknown flag is set.
    """
    expected_flag_value = 0
    for flag_name, flag_value in vars(NegotiateFlags).items():
        if not flag_name.startswith("__"):
            if negotiate_flags & flag_value:
                print("%s present" % flag_name)
                expected_flag_value |= flag_value

    if negotiate_flags != expected_flag_value:
        print("WARNING: Negotiate Flags have extra values not found in our constants list")


def ByteToHex(byteStr):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    return ' '.join([hexlify(x) for x in byteStr])


def HexToByte(hexStr):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    hexStr = ''.join(hexStr.split(" "))

    return unhexlify(hexStr)
