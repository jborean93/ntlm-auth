from .expected_values import *

# Used in the client challenge, we want to return hex aa for the length as per Microsoft's example
def mock_random(ignore):
    return client_challenge


# Used to mock out the exported_session_key in the authenticate messages
def mock_random_session_key():
    return session_base_key


# Used to mock out the timestamp value as per Microsoft's example
def mock_timestamp():
    return timestamp


# Used to mock out the version value as per Microsoft's example (calculated manually)
def mock_version(ignore):
    return HexToByte('05 01 28 0A 00 00 00 0F')
