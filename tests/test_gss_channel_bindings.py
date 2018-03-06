from ntlm_auth.gss_channel_bindings import GssChannelBindingsStruct


class TestGssChannelBindingsStruct(object):

    def test_application_data(self):
        struct = GssChannelBindingsStruct()
        struct[GssChannelBindingsStruct.APPLICATION_DATA] = b"abc"
        expected = b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x61\x62\x63"
        actual = struct.get_data()
        assert actual == expected

    def test_full_data(self):
        struct = GssChannelBindingsStruct()
        struct[GssChannelBindingsStruct.INITIATOR_ADDTYPE] = 2
        struct[GssChannelBindingsStruct.INITIATOR_ADDRESS] = b"abc"
        struct[GssChannelBindingsStruct.ACCEPTOR_ADDRTYPE] = 4
        struct[GssChannelBindingsStruct.ACCEPTOR_ADDRESS] = b"def"
        struct[GssChannelBindingsStruct.APPLICATION_DATA] = b"ghi"
        expected = b"\x02\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x61\x62\x63" \
                   b"\x04\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x64\x65\x66" \
                   b"\x03\x00\x00\x00" \
                   b"\x67\x68\x69"
        actual = struct.get_data()
        assert actual == expected
