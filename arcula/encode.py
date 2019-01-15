#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Handle encoding/decoding and (de)serialization."""

import typing
if typing.TYPE_CHECKING:
    import ecdsa

__author__ = 'aldur'


def int_to_bytes_32(k: int) -> bytes:
    """Serialize an integer to the corresponding big endian bytes."""
    assert 0 <= k < 2 ** 256
    return k.to_bytes(32, byteorder='big')


def bytes_32_to_int(b: bytes) -> int:
    """Deserialize an integer from the corresponding big endian bytes."""
    assert len(b) == 32
    return int.from_bytes(b, byteorder='big')


def int_to_bytes_8(k: int) -> bytes:
    """Serialize an integer to the corresponding big endian bytes."""
    assert 0 <= k < 2 ** 64
    return k.to_bytes(8, byteorder='big')


def bytes_8_to_int(b: bytes) -> int:
    """Deserialize an integer from the corresponding big endian bytes."""
    assert len(b) == 8
    return int.from_bytes(b, byteorder='big')


def verification_key_to_bytes_33(pk: 'ecdsa.VerifyingKey') -> bytes:
    """
    Serialize a verification key to its compressed form.
    https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc
    """
    pk = pk.pubkey.point
    return (b'\x02' if pk.y() % 2 == 0 else b'\x03') + int_to_bytes_32(pk.x())
