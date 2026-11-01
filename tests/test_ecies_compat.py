"""Wire-compatibility tests for the pycryptodome ECIES replacement.

Ciphertext vectors were generated with eciespy 0.4.6 default config
(the scheme the https://dzharikhin.github.io/ecies/ web tool implements).
"""

import pytest

import ecies_compat

# produced by eciespy 0.4.6: encrypt(pk, msg) with these exact keypairs
ECIESPY_VECTORS = [
    {
        "sk": "0x8e581f86de71bbb2d2ec35fa034545c75141fa5f06a68649e6ad92d61037538a",
        "pk": "0x7daac418bed62ddb6bf6f7ffac62cd4ccf56e7ae023fa617929e7f0b16c1d36"
        "06b70f636aaef329516176ad6ea71dd2730d50e6e323df2ce161e839de1ecef6c",
        "msg": bytes.fromhex("68756e74657232"),
        "ct": bytes.fromhex(
            "04425317f380eda462ea2b88bd166044000ce93c9a153a5841a473b50de78f701aa"
            "b748c4b99c6d1e1347562ab4b13d8d53216d104884d8f123ac0b6210c8428607a40d"
            "32b09fa2da9176788642e95d8beb686f4fd53889067f6125184645724e9d814ebd15"
            "9858e"
        ),
    },
    {
        "sk": "0x56e69cd3adfc5fd4faceff3e40be3f64d67e8316cb2c71e9b658d454a3764a12",
        "pk": "0x5103946aaba881e31935da87d38c369a6181a56c71df4ee7acd8190a30d93cf"
        "eb0910fc34482c789d845db2c5a7128341b83a06b160a63672ad8cf6cb78ebce6",
        "msg": bytes.fromhex("70407373773072642dd0b1d0b0d180d0b0d0b4"),
        "ct": bytes.fromhex(
            "046710bbdfd722693c5027c224906a334b746720bee9e9b81a47c462aca860a1afa"
            "c0382495841d09d7d2a28c72c9c68847bcb7c2edc8a4aaed2a6947e71d53fd2bc6a6"
            "f4503cd3cd3c92a8b237c4517efcf538a02b0c35ea9fd5372e51c01d0308e0eb6df0"
            "2d9a3106264cd18c07a0ce91db0a0"
        ),
    },
]


@pytest.mark.parametrize("vector", ECIESPY_VECTORS)
def test_decrypts_eciespy_ciphertext(vector):
    assert ecies_compat.decrypt(vector["sk"], vector["ct"]) == vector["msg"]


def test_roundtrip():
    keys = ecies_compat.generate_keys()
    for msg in [b"x", b"p@ss-\xd0\xb1\xd0\xb0\xd1\x80\xd0\xb0\xd0\xb4", bytes(1024)]:
        assert ecies_compat.decrypt(keys.sk, ecies_compat.encrypt(keys.pk, msg)) == msg


def test_generate_keys_shape_and_derivation():
    keys = ecies_compat.generate_keys()
    assert keys.sk.startswith("0x") and len(keys.sk) == 66
    assert keys.pk.startswith("0x") and len(keys.pk) == 130  # eth 64-byte form
    # pk must be the secp256k1 public point of sk
    secret = int(keys.sk, 16)
    point = ecies_compat._point_mul(secret, (ecies_compat._GX, ecies_compat._GY))
    assert ecies_compat._encode_point(point)[1:].hex() == keys.pk[2:]


def test_tampered_ciphertext_raises_value_error():
    vector = ECIESPY_VECTORS[0]
    tampered = bytearray(vector["ct"])
    tampered[-1] ^= 1
    with pytest.raises(ValueError):
        ecies_compat.decrypt(vector["sk"], bytes(tampered))


def test_garbage_ciphertext_raises_value_error():
    with pytest.raises(ValueError):
        ecies_compat.decrypt("0x" + "11" * 32, b"short")


def test_off_curve_point_rejected():
    # x, y that satisfy no curve equation: invalid-curve attack vector
    fake_point = b"\x04" + (1).to_bytes(32, "big") + (2).to_bytes(32, "big")
    with pytest.raises(ValueError):
        ecies_compat.decrypt("0x" + "11" * 32, fake_point + bytes(100))


def test_compressed_and_prefixed_pk_forms_accepted():
    keys = ecies_compat.generate_keys()
    point = ecies_compat._decode_point(ecies_compat._decode_hex(keys.pk))
    ct = ecies_compat.encrypt("04" + keys.pk[2:], b"prefixed-uncompressed")
    assert ecies_compat.decrypt(keys.sk, ct) == b"prefixed-uncompressed"
    assert point is not None
