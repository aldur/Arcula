#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Crypto-related tools"""

import hashlib
import typing
import secrets

import ecdsa

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__author__ = 'aldur'


def sha3_512(m: bytes) -> bytes:
    """Return the SHA3_512 digest of the provided message."""
    h = hashlib.sha3_512()
    h.update(m)
    return h.digest()


def sha3_512_half(m: bytes) -> bytes:
    """Return the SHA3_512_half digest of the provided message."""
    h = hashlib.sha3_512()
    h.update(m)
    d = h.digest()
    return d[:len(d) // 2]


def sha3_512_half_k(k: bytes, m: bytes) -> bytes:
    """Use SHA3_512 as a PRF, with key `k`, for message `m`."""
    return sha3_512_half(k + m)


def aes_ae(k: bytes, m: bytes) -> typing.Tuple[bytes, bytes]:
    """Authenticated AES Encryption of message `m` with key `k`."""
    assert len(k) == 256 // 8
    aes_ccm = AESGCM(k)
    nonce = secrets.token_bytes(12)  # NIST recommends 96 bits for best performance.
    cipher = aes_ccm.encrypt(nonce, m, None)
    return nonce, cipher


def aes_ad(k: bytes, c: typing.Tuple[bytes, bytes]) -> bytes:
    """Authenticated AES Decryption of cipher-text `c` with key `k`."""
    return AESGCM(k).decrypt(*c, None)


def ecdsa_keygen(seed: bytes, curve: ecdsa.curves.Curve) -> ecdsa.SigningKey:
    """Deterministically generate an ECDSA signing key from a `seed `of bytes."""
    assert len(seed) == 256 // 8
    exponent = ecdsa.util.randrange_from_seed__trytryagain(seed, curve.order)
    return ecdsa.SigningKey.from_secret_exponent(exponent, curve)


def ecdsa_sign(k: ecdsa.SigningKey, message: bytes) -> bytes:
    """
    Generate an ECDSA signature of `message` under the signing key `k`.
    The hashing algorithm is SHA256.
    Outputs the strict DER canonical encoding of the signature (BIP66).
    """
    return k.sign(message, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der_canonize)
