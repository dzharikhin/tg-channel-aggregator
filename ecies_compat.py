"""ECIES over secp256k1, wire-compatible with eciespy default config.

eciespy/coincurve ship no wheels for Python 3.14 and their sdists fail to
build, so this module replaces the narrow subset used by auth.py:
encrypt(pk_hex, data) / decrypt(sk_hex, ciphertext) / generate_keys().

Wire format (matches eciespy ECIES_CONFIG defaults:
secp256k1, uncompressed ephemeral+shared points, HKDF-SHA256 -> 32 bytes,
AES-256-GCM with 16-byte nonce):

    ciphertext = ephemeral_pk(65B, 0x04||x||y) || nonce(16B) || tag(16B) || ct
    sym_key    = HKDF-SHA256(ephemeral_pk || shared_point, 32, salt=b"")
"""

import dataclasses
import os
import secrets
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF

# secp256k1 domain parameters
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8

_NONCE_LENGTH = 16
_TAG_LENGTH = 16
_UNCOMPRESSED_POINT_LENGTH = 65
_ETH_PUBLIC_KEY_LENGTH = 64


Point = Optional[tuple[int, int]]  # None is the point at infinity (identity)


def _inv(value: int) -> int:
    return pow(value, _P - 2, _P)


def _point_add(p1: Point, p2: Point) -> Point:
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None
    if p1 == p2:
        slope = 3 * x1 * x1 % _P * _inv(2 * y1) % _P
    else:
        slope = (y2 - y1) * _inv((x2 - x1) % _P) % _P
    x3 = (slope * slope - x1 - x2) % _P
    y3 = (slope * (x1 - x3) - y1) % _P
    return x3, y3


def _point_mul(scalar: int, point: Point) -> Point:
    result: Point = None
    addend = point
    while scalar:
        if scalar & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        scalar >>= 1
    return result


def _encode_point(point: Point) -> bytes:
    x, y = point
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


def _is_on_curve(point: Point) -> bool:
    x, y = point
    return (y * y - x * x * x - 7) % _P == 0


def _decode_point(data: bytes) -> Point:
    if len(data) == _ETH_PUBLIC_KEY_LENGTH:  # ethereum form without 0x04 prefix
        data = b"\x04" + data
    if len(data) != _UNCOMPRESSED_POINT_LENGTH or data[0] != 0x04:
        raise ValueError(f"Unsupported public key encoding: {len(data)} bytes")
    point = (int.from_bytes(data[1:33], "big"), int.from_bytes(data[33:65], "big"))
    if not 0 <= point[0] < _P or not 0 <= point[1] < _P or not _is_on_curve(point):
        raise ValueError("Public key is not a valid secp256k1 point")
    return point


def _decode_hex(value: str) -> bytes:
    if value.startswith(("0x", "0X")):
        value = value[2:]
    return bytes.fromhex(value)


def _derive_key(ephemeral_point: bytes, shared_point: bytes) -> bytes:
    # identical call to eciespy's derive_key: HKDF-SHA256, 32 bytes, empty salt
    return HKDF(ephemeral_point + shared_point, 32, b"", SHA256, num_keys=1)


@dataclasses.dataclass
class Keys:
    sk: str
    pk: str


def generate_keys() -> Keys:
    """Random secp256k1 keypair in the ethereum hex forms auth.py needs."""
    secret = secrets.randbelow(_N - 1) + 1
    public = _point_mul(secret, (_GX, _GY))
    return Keys(
        sk="0x" + secret.to_bytes(32, "big").hex(),
        # eth_keys PublicKey.to_hex() form: 64 bytes x||y, no 0x04 prefix
        pk="0x" + _encode_point(public)[1:].hex(),
    )


def encrypt(receiver_pk_hex: str, data: bytes) -> bytes:
    receiver_public_key = _decode_point(_decode_hex(receiver_pk_hex))
    ephemeral_secret = secrets.randbelow(_N - 1) + 1
    ephemeral_point = _encode_point(_point_mul(ephemeral_secret, (_GX, _GY)))
    shared_point = _encode_point(_point_mul(ephemeral_secret, receiver_public_key))
    sym_key = _derive_key(ephemeral_point, shared_point)

    nonce = os.urandom(_NONCE_LENGTH)
    cipher = AES.new(sym_key, AES.MODE_GCM, nonce)
    encrypted, tag = cipher.encrypt_and_digest(data)
    return ephemeral_point + nonce + tag + encrypted


def decrypt(receiver_sk_hex: str, data: bytes) -> bytes:
    secret = int.from_bytes(_decode_hex(receiver_sk_hex), "big")
    if not 0 < secret < _N:
        raise ValueError("Invalid secret key")

    key_size = _UNCOMPRESSED_POINT_LENGTH
    ephemeral_point = _encode_point(_decode_point(data[0:key_size]))
    encrypted = data[key_size:]
    sym_key = _derive_key(
        ephemeral_point,
        _encode_point(_point_mul(secret, _decode_point(ephemeral_point))),
    )

    nonce = encrypted[:_NONCE_LENGTH]
    tag = encrypted[_NONCE_LENGTH : _NONCE_LENGTH + _TAG_LENGTH]
    cipher = AES.new(sym_key, AES.MODE_GCM, nonce)
    # decrypt_and_verify raises ValueError("MAC check failed"), like eciespy
    return cipher.decrypt_and_verify(encrypted[_NONCE_LENGTH + _TAG_LENGTH :], tag)
