#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import unittest

from .. import bip44

__author__ = 'aldur'


class BIP44TestCase(unittest.TestCase):
    def test_bip44_two_coins(self):
        config = {
            'BTC': ((1, 2), (5, 3), (0, 1)),
            'LTC': ((5, 5), ),
        }
        m = bip44.bip44_tree(config)
        self.assertEqual(m.tag, 'm')

        n_nodes = 1  # master node
        n_nodes += 1  # BIP44 purpose
        for k, v in config.items():
            n_nodes += 1  # A node for each coin
            n_nodes += len(v)  # A node for each account
            n_nodes += 2 * len(v)  # Each account has a private/public branch
            n_nodes += sum(itertools.chain.from_iterable(v))  # The private/public addresses.

        q = [m]
        seen = set()
        while q:
            u = q.pop(0)
            seen.add(u)

            for i, v in enumerate(u.edges):
                self.assertFalse(v in seen)
                q.append(v)

        self.assertEqual(len(seen), n_nodes)

    def test_bip44_find_with_path(self):
        config = {
            'BTC': ((1, 2), (5, 4), (0, 1)),
            'LTC': ((5, 5), ),
        }
        m = bip44.bip44_tree(config)
        self.assertRaises(AssertionError, bip44.find_bip44_node_with_path, m, '')

        btc_node = bip44.find_bip44_node_with_path(m, "m/44'/BTC")
        self.assertEqual(btc_node.tag, 'BTC')

        self.assertEqual(len(btc_node.edges), 3)
        address_one_node = bip44.find_bip44_node_with_path(m, "m/44'/BTC/1")
        self.assertEqual(address_one_node.id, 1)
        self.assertEqual(len(address_one_node.edges), 2)

        address_one_pub_node = bip44.find_bip44_node_with_path(m, "m/44'/BTC/1/xpub")
        self.assertEqual(address_one_pub_node.id, 0)
        self.assertEqual(address_one_pub_node.tag.lower(), 'xpub')
        self.assertEqual(len(address_one_pub_node.edges), 1)

        address_one_account_node = bip44.find_bip44_node_with_path(m, "m/44'/BTC/1/xpub/3")
        self.assertEqual(address_one_account_node.id, 3)
        self.assertEqual(len(address_one_account_node.edges), 0)

        self.assertRaises(IndexError, bip44.find_bip44_node_with_path, m, "m/44'/BTC/1/xpub/4")
        self.assertRaises(AssertionError, bip44.find_bip44_node_with_path, m, "m/44'/BTC/1/xpub/3/0")


if __name__ == '__main__':
    unittest.main()
