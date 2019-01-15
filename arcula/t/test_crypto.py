#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ecdsa
import hashlib
import unittest

from .. import crypto

__author__ = 'aldur'


class CryptoTestCase(unittest.TestCase):
    def test_sha3_512(self):
        v = b'foo'
        truth = bytes.fromhex(
            '4bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c'
            '82cbebc68e3b70a2a1480b4bb5d437a7cba6ecf9d89f9ff3ccd14cd6146ea7e7'
        )

        self.assertEqual(crypto.sha3_512(v), truth)
        self.assertEqual(len(crypto.sha3_512(v)), 512 // 8)

    def test_sha3_512_half(self):
        v = b'foo'
        truth = bytes.fromhex('4bca2b137edc580fe50a88983ef860ebaca36c857b1f492839d6d7392452a63c')

        self.assertEqual(crypto.sha3_512_half(v), truth)
        self.assertEqual(len(crypto.sha3_512_half(v)), 512 // 8 // 2)

    def test_sha3_512_half_k(self):
        v = b'test_sha3_512_half_k_v'
        k = b'test_sha3_512_half_k_k'
        truth = crypto.sha3_512_half(k + v)

        self.assertEqual(crypto.sha3_512_half_k(k, v), truth)
        self.assertEqual(len(crypto.sha3_512_half_k(k, v)), 512 // 8 // 2)

    def test_aes_gcm(self):
        self.assertRaises(AssertionError, crypto.aes_ae, bytes(10), b'')

        k = crypto.sha3_512_half(b'test_aes_gcm_k')
        m = b'test_aes_gcm_m'
        self.assertEqual(m, crypto.aes_ad(k, crypto.aes_ae(k, m)))

    def test_ecdsa_keygen(self):
        seed = crypto.sha3_512_half(b'test_ecdsa_keygen')

        k1 = crypto.ecdsa_keygen(seed, ecdsa.curves.SECP256k1)
        k2 = crypto.ecdsa_keygen(seed, ecdsa.curves.SECP256k1)

        self.assertEqual(k1.to_der(), k2.to_der())

    def test_ecdsa_sign(self):
        m = b'test_ecdsa_sign_m'
        k = crypto.ecdsa_keygen(crypto.sha3_512_half(b'test_ecdsa_sign_k'), ecdsa.curves.SECP256k1)
        signature = crypto.ecdsa_sign(k, m)

        self.assertTrue(k.get_verifying_key().verify(signature, m,
                                                     hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der))


if __name__ == '__main__':
    unittest.main()
