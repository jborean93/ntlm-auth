import ntlm_auth.compute_hash as compute_hash


class TestComputeHash(object):

    def test_lmowfv1(self):
        # 4.2.2.1.1 - LMOWFv1()
        expected = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                   b"\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"
        actual = compute_hash._lmowfv1("Password")
        assert actual == expected

    def test_ntowfv1(self):
        # 4.2.2.1.2 - NTOWFv1()
        expected = b"\xa4\xf4\x9c\x40\x65\x10\xbd\xca" \
                   b"\xb6\x82\x4e\xe7\xc3\x0f\xd8\x52"
        actual = compute_hash._ntowfv1("Password")
        assert actual == expected

    def test_lmofv1_hash(self):
        # 4.2.2.1.1 - LMOWFv1()
        expected = b"\xe5\x2c\xac\x67\x41\x9a\x9a\x22" \
                   b"\x4a\x3b\x10\x8f\x3f\xa6\xcb\x6d"
        password_hash = "e52cac67419a9a224a3b108f3fa6cb6d:" \
                        "a4f49c406510bdcab6824ee7c30fd852"
        actual = compute_hash._lmowfv1(password_hash)
        assert actual == expected

    def test_ntowfv1_hash(self):
        # 4.2.2.1.2 - NTOWFv1()
        expected = b"\xa4\xf4\x9c\x40\x65\x10\xbd\xca" \
                   b"\xb6\x82\x4e\xe7\xc3\x0f\xd8\x52"
        password_hash = "e52cac67419a9a224a3b108f3fa6cb6d:" \
                        "a4f49c406510bdcab6824ee7c30fd852"
        actual = compute_hash._ntowfv1(password_hash)
        assert actual == expected

    def test_ntowfv2(self):
        # 4.2.4.1.1 - NTOWFv2() and LMOWFv2()
        expected = b"\x0c\x86\x8a\x40\x3b\xfd\x7a\x93" \
                   b"\xa3\x00\x1e\xf2\x2e\xf0\x2e\x3f"
        actual = compute_hash._ntowfv2("User", "Password", "Domain")
        assert actual == expected
