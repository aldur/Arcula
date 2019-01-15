#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""A Deterministic Hierarchical Key Assignment Scheme."""

import typing

from . import hierarchy, crypto, encode
from .constants import CryptoConstants as cc

__author__ = 'aldur'


class DHKA(hierarchy.Hierarchy):
    """
    A deterministic hierarchical key assignment scheme.

    Takes a `root` node encoding the hierarchy.
    `prf_f`, `enc_f`, `dec_f` are respectively:
    1. A PRF function that outputs 256 bits.
    2/3. A symmetric encryption and decryption function.
    Please refer to their type hinting for their signatures.
    """

    def __init__(
            self, root: hierarchy.DHKANode,
            prf_f: typing.Callable[[bytes, bytes], bytes] = crypto.sha3_512_half_k,
            enc_f: typing.Callable[[bytes, bytes], typing.Tuple[bytes, bytes]] = crypto.aes_ae,
            dec_f: typing.Callable[[bytes, typing.Tuple[bytes, bytes]], bytes] = crypto.aes_ad,
    ):
        super().__init__(root)

        self.prf_f = prf_f  # A PRF that outputs 256 bits
        self.enc_f = enc_f
        self.dec_f = dec_f

    def _label_secret_encryption_key_from_parent(self, parent_secret: bytes, identifier: int) \
            -> typing.Tuple[bytes, bytes, bytes, bytes]:
        """Generate the label, secret, encryption key, and private key for a node, starting from the parent's secret."""
        label = encode.int_to_bytes_8(identifier)
        secret = self.prf_f(parent_secret, cc.PRF_SECRET_PREFIX.value + label)
        encryption_key = self.prf_f(secret, cc.PRF_ENCRYPTION_PREFIX.value + label)
        private_key = self.prf_f(secret, cc.PRF_PRIVATE_KEY_PREFIX.value + label)

        return label, secret, encryption_key, private_key

    def _edge_encryption_key(self, parent_encryption_key: bytes, child_label: bytes) -> bytes:
        """Generate the encryption key for an edge."""
        return self.prf_f(parent_encryption_key, cc.PRF_EDGE_PREFIX.value + child_label)

    def _encrypt_edge(self, edge_encryption_key: bytes, message: bytes) -> typing.Tuple[bytes, bytes]:
        """
        Encrypt a `message` of the form (`child_encryption_key`, `child_private_key`) to be associated with an edge.
        """
        return self.enc_f(edge_encryption_key, message)

    def keygen(self, seed: bytes):
        """Generate a private/public key pair for each node of the tree."""
        root = self.root
        root._label, root._secret, root._encryption_key, root._key = \
            self._label_secret_encryption_key_from_parent(seed, root.id)

        q = [root]
        visited = set()

        while q:
            u = q.pop(0)
            visited.add(u)

            for i, v in enumerate(u.edges):
                if v in visited:
                    assert False, 'The poset is not a tree.'
                q.append(v)

                v._label, v._secret, v._encryption_key, v._key = \
                    self._label_secret_encryption_key_from_parent(u._secret, v.id)

                edge_encryption_key = self._edge_encryption_key(u._encryption_key, v._label)
                edge_encryption = self._encrypt_edge(edge_encryption_key, v._encryption_key + v._key)

                u.encrypted_edges.append(edge_encryption)

            assert len(u.encrypted_edges) == len(u.edges)
