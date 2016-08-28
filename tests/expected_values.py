import struct
from .utils import HexToByte

"""
    [MS-NLMP] v28 2016-07-14

    These values are set in the MS-NLMP documentation for protocol examples. If writting a test
    that uses these values you should be using this instead of repeating it over and over again.
    If writing a custom test that deviates from the examples in MS-NLMP keep them in the test and
    not here.

    The variable naming structure is [auth version]_[example name]
"""

# 4.2.1 Common Values
user_name = 'User'
domain_name = 'Domain'
password = 'Password'
server_name = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
workstation_name = HexToByte('43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00').decode()

# Written as RandomSessionKey in document, in reality this is the session_base_key value
session_base_key = HexToByte('55 55 55 55 55 55 55 55 55 55 55 55 55 55 55 55')

timestamp = HexToByte('00 00 00 00 00 00 00 00')
client_challenge = HexToByte('aa aa aa aa aa aa aa aa')
server_challenge = HexToByte('01 23 45 67 89 ab cd ef')

# Not in the common values but each section uses the same in the GSS_WrapEx examples so putting it here
plaintext_data = HexToByte('50 00 6c 00 61 00 69 00 6e 00 74 00 65 00 78 00'
                           '74 00')

### 4.2.2 NTLMv1 Authentication
ntlmv1_negotiate_flags = struct.unpack("<I", HexToByte('33 82 02 e2'))[0]

# 4.2.2.1 NTLMv1 Authentication Calculations
ntlmv1_lmowfv1 = HexToByte('e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d')
ntlmv1_ntowfv1 = HexToByte('a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52')
ntlmv1_session_base_key = HexToByte('d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84')
ntlmv1_key_exchange_key = HexToByte('d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84')

# 4.2.2.2 NTLMv1 Results
ntlmv1_ntlmv1_response = HexToByte('67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c'
                                   '44 bd be d9 27 84 1f 94')
ntlmv1_lmv1_response = HexToByte('98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72'
                                 'de f1 1c 7d 5c cd ef 13')
ntlmv1_encrypted_session_key = HexToByte('51 88 22 b1 b3 f3 50 c8 95 86 82 ec bb 3e 3c b7')

# 4.2.2.3 NTLMv1 Messages
ntlmv1_challenge_message = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                     '38 00 00 00 33 82 02 e2 01 23 45 67 89 ab cd ef'
                                     '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                     '65 00 72 00')
ntlmv1_authenticate_message = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                                        '6c 00 00 00 18 00 18 00 84 00 00 00 0c 00 0c 00'
                                        '48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00'
                                        '5c 00 00 00 10 00 10 00 9c 00 00 00 35 82 80 e2'
                                        '05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00'
                                        '69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                                        '4d 00 50 00 55 00 54 00 45 00 52 00 98 de f7 b8'
                                        '7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d'
                                        '5c cd ef 13 67 c4 30 11 f3 02 98 a2 ad 35 ec e6'
                                        '4f 16 33 1c 44 bd be d9 27 84 1f 94 51 88 22 b1'
                                        'b3 f3 50 c8 95 86 82 ec bb 3e 3c b7')

# 4.2.2.4 NTLMv1 GSS_WrapEx Examples
ntlmv1_output_message = HexToByte('56 fe 04 d8 61 f9 31 9a f0 d7 23 8a 2e 3b 4d 45'
                                  '7f b8')
# MS example has random pad section with values when their compute guide says for it to be 0
ntlmv1_signature = HexToByte('01 00 00 00 00 00 00 00 09 dc d1 df 2e 45 9d 36')


### 4.2.3 NTLMv1 with Client Challenge
ntlmv1_with_ess_negotiate_flags = struct.unpack("<I", HexToByte('33 82 0a 82'))[0]

# 4.2.3.1 NTLMv1 with Client Challenge Calculations
# Not in the example but dervied from logic in the document (client_challenge + b'\0' * 16)
ntlmv1_with_ess_lmowfv1 = HexToByte('aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00')
ntlmv1_with_ess_ntowfv1 = HexToByte('a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52')
ntlmv1_with_ess_session_base_key = HexToByte('d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84')
ntlmv1_with_ess_key_exchange_key = HexToByte('eb 93 42 9a 8b d9 52 f8 b8 9c 55 b8 7f 47 5e dc')

# 4.2.3.2 NTLMv1 with Client Challenge Results
ntlmv1_with_ess_lmv1_response = HexToByte('aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00'
                                          '00 00 00 00 00 00 00 00')
ntlmv1_with_ess_ntlmv1_response = HexToByte('75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8'
                                            '1e 97 ed 26 83 26 72 32')

# 4.2.3.3 NTLMv1 with Client Challenge Messages
ntlmv1_with_ess_challenge_message = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 0c 00 0c 00'
                                              '38 00 00 00 33 82 0a 82 01 23 45 67 89 ab cd ef'
                                              '00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                                              '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                              '65 00 72 00')
ntlmv1_with_ess_authenticate_message = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                                                 '6c 00 00 00 18 00 18 00 84 00 00 00 0c 00 0c 00'
                                                 '48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00'
                                                 '5c 00 00 00 00 00 00 00 9c 00 00 00 35 82 08 82'
                                                 '05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00'
                                                 '69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                                                 '4d 00 50 00 55 00 54 00 45 00 52 00 aa aa aa aa'
                                                 'aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00'
                                                 '00 00 00 00 75 37 f8 03 ae 36 71 28 ca 45 82 04'
                                                 'bd e7 ca f8 1e 97 ed 26 83 26 72 32')

# 4.2.3.4 NTLMv1 with Client Challenge GSS_WrapEx Examples
ntlmv1_with_ess_seal_key = HexToByte('04 dd 7f 01 4d 85 04 d2 65 a2 5c c8 6a 3a 7c 06')
ntlmv1_with_ess_sign_key = HexToByte('60 e7 99 be 5c 72 fc 92 92 2a e8 eb e9 61 fb 8d')
ntlmv1_with_ess_output_message = HexToByte('a0 23 72 f6 53 02 73 f3 aa 1e b9 01 90 ce 52 00'
                                           'c9 9d')
ntlmv1_with_ess_signature = HexToByte('01 00 00 00 ff 2a eb 52 f6 81 79 3a 00 00 00 00')

### 4.2.4 NTLMv2 Authentication
ntlmv2_negotiate_flags = struct.unpack("<I", HexToByte('33 82 8a e2'))[0]
ntlmv2_netbios_server_name = HexToByte('53 00 65 00 72 00 76 00 65 00 72 00')
ntlmv2_netbios_domain_name = HexToByte('44 00 6f 00 6d 00 61 00 69 00 6e 00')

# 4.2.4.1 NTLMv2 Calculations
ntlmv2_ntowfv2 = HexToByte('0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f')
ntlmv2_session_base_key = HexToByte('8d e4 0c ca db c1 4a 82 f1 5c b0 ad 0d e9 5c a3')
ntlmv2_temp = HexToByte('01 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00'
                        'aa aa aa aa aa aa aa aa 00 00 00 00 02 00 0c 00'
                        '44 00 6f 00 6d 00 61 00 69 00 6e 00 01 00 0c 00'
                        '53 00 65 00 72 00 76 00 65 00 72 00 00 00 00 00'
                        '00 00 00 00')

# 4.2.4.2 NTLMv2 Results
ntlmv2_lmv2_response = HexToByte('86 c3 50 97 ac 9c ec 10 25 54 7 6 4a 57 cc cc 19'
                                 'aa aa aa aa aa aa aa aa')

# While the example only has the nt_proof_str, out methods return both that and the temp value
ntlmv2_ntlmv2_response = HexToByte('68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c') + ntlmv2_temp
ntlmv2_encrypted_session_key = HexToByte('c5 da d2 54 4f c9 79 90 94 ce 1c e9 0b c9 d0 3e')

# 4.2.4.3 NTLMv2 Messages
ntlmv2_challenge_message = HexToByte('4e 54 4c 4d 53 53 50 00 02 00 00 00 03 00 0c 00'
                                     '38 00 00 00 33 82 8a e2 01 23 45 67 89 ab cd ef'
                                     '00 00 00 00 00 00 00 00 24 00 24 00 44 00 00 00'
                                     '06 00 70 17 00 00 00 0f 53 00 65 00 72 00 76 00'
                                     '65 00 72 00 02 00 0c 00 44 00 6f 00 6d 00 61 00'
                                     '69 00 6e 00 01 00 0c 00 53 00 65 00 72 00 76 00'
                                     '65 00 72 00 00 00 00 00')
ntlmv2_authenticate_message = HexToByte('4e 54 4c 4d 53 53 50 00 03 00 00 00 18 00 18 00'
                                        '6c 00 00 00 54 00 54 00 84 00 00 00 0c 00 0c 00'
                                        '48 00 00 00 08 00 08 00 54 00 00 00 10 00 10 00'
                                        '5c 00 00 00 10 00 10 00 d8 00 00 00 35 82 88 e2'
                                        '05 01 28 0a 00 00 00 0f 44 00 6f 00 6d 00 61 00'
                                        '69 00 6e 00 55 00 73 00 65 00 72 00 43 00 4f 00'
                                        '4d 00 50 00 55 00 54 00 45 00 52 00 86 c3 50 97'
                                        'ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa'
                                        'aa aa aa aa 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b'
                                        'eb ef 6a 1c 01 01 00 00 00 00 00 00 00 00 00 00'
                                        '00 00 00 00 aa aa aa aa aa aa aa aa 00 00 00 00'
                                        '02 00 0c 00 44 00 6f 00 6d 00 61 00 69 00 6e 00'
                                        '01 00 0c 00 53 00 65 00 72 00 76 00 65 00 72 00'
                                        '00 00 00 00 00 00 00 00 c5 da d2 54 4f c9 79 90'
                                        '94 ce 1c e9 0b c9 d0 3e')

# 4.2.4.4 NTLMv2 GSS_WrapEx Examples
ntlmv2_seal_key = HexToByte('59 f6 00 97 3c c4 96 0a 25 48 0a 7c 19 6e 4c 58')
ntlmv2_sign_key = HexToByte('47 88 dc 86 1b 47 82 f3 5d 43 fd 98 fe 1a 2d 39')
ntlmv2_output_message = HexToByte('54 e5 01 65 bf 19 36 dc 99 60 20 c1 81 1b 0f 06'
                                  'fb 5f')
ntlmv2_signature = HexToByte('01 00 00 00 7f b3 8e c5 c5 5d 49 76 00 00 00 00')