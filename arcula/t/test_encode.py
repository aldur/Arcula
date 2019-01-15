#!/usr/bin/env python
# -*- coding: utf-8 -*-

import ecdsa
import unittest

from .. import encode, crypto

__author__ = 'aldur'


class EncodeTestCase(unittest.TestCase):
    def test_int_to_bytes_32(self):
        v = 0
        truth = bytes(32)
        self.assertEqual(encode.int_to_bytes_32(v), truth)
        self.assertEqual(len(encode.int_to_bytes_32(v)), 32)

        v = 1
        truth = bytes([0] * 31 + [1])
        self.assertEqual(encode.int_to_bytes_32(v), truth)
        self.assertEqual(len(encode.int_to_bytes_32(v)), 32)

        v = -1
        self.assertRaises(AssertionError, encode.int_to_bytes_32, v)

        v = 2 ** 256
        self.assertRaises(AssertionError, encode.int_to_bytes_32, v)

    def test_bytes_32_to_int(self):
        v = bytes(32)
        truth = 0
        self.assertEqual(encode.bytes_32_to_int(v), truth)

        v = bytes([0] * 31 + [1])
        truth = 1
        self.assertEqual(encode.bytes_32_to_int(v), truth)

    def test_int_to_bytes_8(self):
        v = 0
        truth = bytes(8)
        self.assertEqual(encode.int_to_bytes_8(v), truth)
        self.assertEqual(len(encode.int_to_bytes_8(v)), 8)

        v = 1
        truth = bytes([0] * 7 + [1])
        self.assertEqual(encode.int_to_bytes_8(v), truth)
        self.assertEqual(len(encode.int_to_bytes_8(v)), 8)

        v = -1
        self.assertRaises(AssertionError, encode.int_to_bytes_8, v)

        v = 2 ** 64
        self.assertRaises(AssertionError, encode.int_to_bytes_8, v)

    def test_bytes_8_to_int(self):
        v = bytes(8)
        truth = 0
        self.assertEqual(encode.bytes_8_to_int(v), truth)

        v = bytes([0] * 7 + [1])
        truth = 1
        self.assertEqual(encode.bytes_8_to_int(v), truth)

    def test_verification_key_to_bytes_33(self):
        k = crypto.ecdsa_keygen(crypto.sha3_512_half(b'k'), curve=ecdsa.SECP256k1).get_verifying_key()
        e = encode.verification_key_to_bytes_33(k)
        self.assertEqual(len(e), 33)

        point = k.pubkey.point
        if point.y() % 2 == 0:
            self.assertEqual(e[0], 0x02)
        else:
            self.assertEqual(e[0], 0x03)

        self.assertEqual(encode.bytes_32_to_int(e[1:]), point.x())


if __name__ == '__main__':
    unittest.main()
