#!/usr/bin/env python
# -*- coding: utf-8 -*-

import bitcash
import ecdsa
import hashlib
import unittest

from .. import hierarchy, crypto, arcula, encode, bip44

__author__ = 'aldur'


class ArculaTestCase(unittest.TestCase):

    def assert_is_valid_DER_signature_encoding(self, signature: bytes):
        """
        Check whether a signature is in a valid DER canonical encoding.
        Adapted from the Bitcoin-code source code.
        """
        self.assertTrue(8 < len(signature) < 72)
        self.assertTrue(signature[0] == 0x30)
        self.assertTrue(signature[1] == len(signature) - 2)
        self.assertTrue(signature[2] == 0x02)

        len_r = signature[3]
        self.assertTrue(len_r != 0)
        self.assertTrue(not signature[4] & 0x80)
        self.assertTrue(len_r <= len(signature) - 7)
        self.assertTrue(not (len_r > 1 and (signature[4] == 0x00) and not (signature[5] & 0x80)))

        start_s = len_r + 4
        self.assertTrue(signature[start_s] == 0x02)
        len_s = signature[start_s + 1]
        self.assertTrue(len_s != 0)
        self.assertTrue(not signature[start_s + 2] & 0x80)
        self.assertTrue(start_s + len_s + 2 == len(signature))
        self.assertTrue(not (len_s > 1 and (signature[start_s + 2] == 0x00) and not (signature[start_s + 3] & 0x80)))

    def test_root(self):
        root = hierarchy.ArculaNode(0, tag='tag')
        seed = crypto.sha3_512(b'secret_seed')

        wallet = arcula.Arcula(root)
        wallet.keygen(seed)

        cold_storage_private_key = crypto.ecdsa_keygen(seed[len(seed) // 2:], curve=wallet.curve)
        cold_storage_public_key = cold_storage_private_key.get_verifying_key()
        self.assertEqual(wallet.cold_storage_public_key.to_der(), cold_storage_public_key.to_der())

        self.assertIsNotNone(root.certificate)
        self.assertIsNotNone(root._signing_key)

        certificate, message = root.certificate
        signing_public_key = encode.verification_key_to_bytes_33(root._signing_key.get_verifying_key())
        identifier = encode.int_to_bytes_8(root.id)
        self.assertEqual(message, (signing_public_key, identifier))
        self.assertEqual(
            signing_public_key,
            encode.verification_key_to_bytes_33(crypto.ecdsa_keygen(root._key, wallet.curve).get_verifying_key())
        )

        self.assertTrue(cold_storage_public_key.verify(certificate, signing_public_key + identifier,
                                                       hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der))
        self.assert_is_valid_DER_signature_encoding(certificate)

        # Also make sure that is a valid Bitcoin Cash signature.
        self.assertTrue(bitcash.PrivateKeyTestnet.from_int(
            cold_storage_private_key.privkey.secret_multiplier).verify(certificate, signing_public_key + identifier))

    def test_public_derivation_hardcoded(self):
        seed = crypto.sha3_512(b'secret_seed_')
        root = hierarchy.ArculaNode(0, tag='tag')

        child_zero = hierarchy.ArculaNode(0, tag='child_zero')
        child_one = hierarchy.ArculaNode(1, tag='child_one')
        root.edges += [child_zero, child_one]

        grandson_zero = hierarchy.ArculaNode(0, tag='grandson_zero')
        child_one.edges.append(grandson_zero)

        wallet = arcula.Arcula(root)
        wallet.keygen(seed)

        cold_storage_private_key = crypto.ecdsa_keygen(seed[len(seed) // 2:], curve=wallet.curve)
        cold_storage_public_key = cold_storage_private_key.get_verifying_key()
        self.assertEqual(wallet.cold_storage_public_key.to_der(), cold_storage_public_key.to_der())

        for u in [root, child_zero, child_one]:
            certificate, message = u.certificate
            signing_public_key = encode.verification_key_to_bytes_33(u._signing_key.get_verifying_key())
            identifier = encode.int_to_bytes_8(u.id)
            self.assertEqual(message, (signing_public_key, identifier))
            self.assertEqual(
                signing_public_key,
                encode.verification_key_to_bytes_33(crypto.ecdsa_keygen(u._key, wallet.curve).get_verifying_key())
            )
            self.assertTrue(cold_storage_public_key.verify(certificate, signing_public_key + identifier,
                                                           hashfunc=hashlib.sha256, sigdecode=ecdsa.util.sigdecode_der))
            self.assert_is_valid_DER_signature_encoding(certificate)

    def test_public_derivation_wallet(self):
        seed = crypto.sha3_512(b'_secret_seed')
        root = bip44.bip44_tree({
            'BTC': ((1, 2), (0, 1)),
            'LTC': ((2, 3), ),
        }, cls=hierarchy.ArculaNode)

        wallet = arcula.Arcula(root)
        wallet.keygen(seed)

        cold_storage_private_key = crypto.ecdsa_keygen(seed[len(seed) // 2:], curve=wallet.curve)
        cold_storage_public_key = cold_storage_private_key.get_verifying_key()
        self.assertEqual(wallet.cold_storage_public_key.to_der(), cold_storage_public_key.to_der())

        q = [root]
        while q:
            u = q.pop()

            certificate, message = u.certificate
            signing_public_key = encode.verification_key_to_bytes_33(u._signing_key.get_verifying_key())
            identifier = encode.int_to_bytes_8(u.id)
            self.assertEqual(message, (signing_public_key, identifier))
            self.assertEqual(
                signing_public_key,
                encode.verification_key_to_bytes_33(crypto.ecdsa_keygen(u._key, wallet.curve).get_verifying_key())
            )
            self.assertTrue(wallet.cold_storage_public_key.verify(certificate, signing_public_key + identifier,
                                                                  hashfunc=hashlib.sha256,
                                                                  sigdecode=ecdsa.util.sigdecode_der))
            self.assert_is_valid_DER_signature_encoding(certificate)


if __name__ == '__main__':
    unittest.main()
