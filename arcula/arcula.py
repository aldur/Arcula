#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Arcula: a secure, hierarchical deterministic wallet."""

import typing

import ecdsa

from . import hierarchy, crypto, encode, dhka

__author__ = 'aldur'


class Arcula(dhka.DHKA):
    """
    Setup the wallet by assigning a pair of signing keys and an authorization certificate to the nodes of the hierarchy.

    Inherits from the Deterministic Hierarchical Key Assignment scheme as we use it for the derivation of the signing
    keys.
    Derives the cold storage keys from half the initial seed and then runs the DHKA with the remaining half.

    Takes a `root` node encoding the hierarchy and an ECDSA `curve`.
    `hash_f`, `prf_f`, `enc_f`, `dec_f` are respectively:
    1. A hash function that outputs 256 bits.
    2. A PRF function that outputs 256 bits.
    3/4. A symmetric encryption and decryption function.
    Please refer to their type hinting for their signatures.
    """

    def __init__(
            self, root: hierarchy.ArculaNode,
            hash_f: typing.Callable[[bytes], bytes] = crypto.sha3_512_half,
            prf_f: typing.Callable[[bytes, bytes], bytes] = crypto.sha3_512_half_k,
            enc_f: typing.Callable[[bytes, bytes], typing.Tuple[bytes, bytes]] = crypto.aes_ae,
            dec_f: typing.Callable[[bytes, typing.Tuple[bytes, bytes]], bytes] = crypto.aes_ad,
            curve: ecdsa.curves.Curve = ecdsa.SECP256k1
    ):
        super().__init__(root, prf_f, enc_f, dec_f)
        self.hash_f = hash_f  # A hash function that outputs 256 bits
        self.curve: ecdsa.curves.Curve = curve  # An ECDSA curve

        self.cold_storage_public_key: typing.Optional[ecdsa.VerifyingKey] = None  # The cold storage public key

    def _cold_storage_keys(self, seed: bytes) -> ecdsa.SigningKey:
        """Generate the cold storage pair of signing keys starting from the initial `seed`."""
        return crypto.ecdsa_keygen(seed, curve=self.curve)

    @staticmethod
    def _create_certificate(
            cold_storage_key: ecdsa.SigningKey, public_signing_key: ecdsa.VerifyingKey, identifier: int
    ) -> typing.Tuple[bytes, typing.Tuple[bytes, bytes]]:
        """
        Create a certificate of the `cold_storage_key` that authorizes the `public_signing_key` to spend of behalf of
        the `identifier`.

        Outputs the `certificate` itself and the pair (`public_signing_key`, `identifier`) that, concatenated,
        is the message within the certificate.
        The `certificate` is encoded through the canonical DER serialization format described in BIP66
        https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki.

        The current implementation encodes the `identifier` as 8 big endian bytes and the `public_signing_key` to a
        33 bytes compressed representation.
        """
        public_signing_key = encode.verification_key_to_bytes_33(public_signing_key)
        identifier = encode.int_to_bytes_8(identifier)
        return crypto.ecdsa_sign(cold_storage_key, public_signing_key + identifier), (public_signing_key, identifier)

    def keygen(self, seed: bytes):
        """Generate a pair of signing keys and a certificate for each node of the hierarchy."""
        assert len(seed) == 512 // 8, len(seed)
        super().keygen(seed[:256 // 8])

        # Setup the wallet key.
        cold_storage_key = self._cold_storage_keys(seed[256 // 8:])
        self.cold_storage_public_key = cold_storage_key.get_verifying_key()

        q = [self.root, ]
        visited = set()
        while q:
            u = q.pop(0)
            visited.add(u)
            u._signing_key = crypto.ecdsa_keygen(u._key, self.curve)
            u.certificate = self._create_certificate(cold_storage_key, u._signing_key.get_verifying_key(), u.id)

            assert len(set(e.id for e in u.edges)) == len(u.edges)
            for v in u.edges:
                if v not in visited:
                    q.append(v)

        del cold_storage_key  # Warning: This does not actually delete the keys from memory.
