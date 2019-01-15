#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

__author__ = 'aldur'

from .. import hierarchy, crypto, dhka, constants, encode, bip44


class DHKATestCase(unittest.TestCase):
    def assert_node(self, node):
        label = encode.int_to_bytes_8(node.id)
        self.assertEqual(node._label, label)

        self.assertIsNotNone(node._label)
        self.assertIsNotNone(node._secret)
        self.assertIsNotNone(node._encryption_key)

    def assert_node_from_parent_secret(self, tree, child_node, parent_secret):
        label = encode.int_to_bytes_8(child_node.id)
        self.assertEqual(child_node._label, label)

        secret = tree.prf_f(parent_secret, constants.CryptoConstants.PRF_SECRET_PREFIX.value + label)
        self.assertEqual(child_node._secret, secret)

        t = tree.prf_f(secret, constants.CryptoConstants.PRF_ENCRYPTION_PREFIX.value + label)
        self.assertEqual(child_node._encryption_key, t)

        k = tree.prf_f(secret, constants.CryptoConstants.PRF_PRIVATE_KEY_PREFIX.value + label)
        self.assertEqual(child_node._key, k)

    def assert_edge_public(self, tree, parent_node, child_node, edge_cipher):
        r = tree.prf_f(parent_node._encryption_key, constants.CryptoConstants.PRF_EDGE_PREFIX.value + child_node._label)
        self.assertEqual(tree.dec_f(r, edge_cipher), child_node._encryption_key + child_node._key)

    def test_root(self):
        root = hierarchy.DHKANode(0, tag='tag')
        seed = crypto.sha3_512(b'secret_seed')

        tree = dhka.DHKA(root)
        tree.keygen(seed)

        self.assert_node(root)
        self.assert_node_from_parent_secret(tree, root, seed)
        self.assertEqual(len(root.encrypted_edges), 0)

    def test_private_derivation_hardcoded(self):
        seed = crypto.sha3_512(b'secret_seed_')
        root = hierarchy.DHKANode(0, tag='tag')

        child_zero = hierarchy.DHKANode(0, tag='child_zero')
        child_one = hierarchy.DHKANode(1, tag='child_one')
        root.edges += [child_zero, child_one]

        grandson_zero = hierarchy.DHKANode(0, tag='grandson_zero')
        child_one.edges.append(grandson_zero)

        tree = dhka.DHKA(root)
        tree.keygen(seed)

        self.assert_node(root)
        self.assert_node(child_zero)
        self.assert_node(child_one)

        self.assert_node_from_parent_secret(tree, root, seed)

        self.assert_node_from_parent_secret(tree, child_zero, root._secret)
        self.assert_edge_public(tree, root, child_zero, root.encrypted_edges[0])

        self.assert_node_from_parent_secret(tree, child_one, root._secret)
        self.assert_node_from_parent_secret(tree, grandson_zero, child_one._secret)

    def test_private_derivation_bip44(self):
        seed = crypto.sha3_512(b'_secret_seed')
        root = bip44.bip44_tree({
            'BTC': ((1, 2), (0, 1)),
            'LTC': ((2, 3), ),
        }, cls=hierarchy.DHKANode)

        tree = dhka.DHKA(root)
        tree.keygen(seed)

        q = [root]
        while q:
            u = q.pop()
            self.assertEqual(len(u.edges), len(u.encrypted_edges))
            for i, v in enumerate(u.edges):
                self.assert_node_from_parent_secret(tree, v, u._secret)
                self.assert_edge_public(tree, u, v, u.encrypted_edges[i])


if __name__ == '__main__':
    unittest.main()
