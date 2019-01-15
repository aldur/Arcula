#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Implement a wallet with the structure defined by BIP44."""

import ecdsa
import typing

from . import hierarchy, constants, arcula

__author__ = 'aldur'


def bip44_tree(config: dict, cls=hierarchy.Node) -> hierarchy.Node:
    """
    Return the root node of a BIP44-compatible partially ordered hierarchy.
    https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki

    The `config` parameter is a dictionary of the following form:
    - the keys of the dictionary are crypto-coins;
    - the values of the dictionary specify the number of accounts to generate for each coin,
        and the number of public/private addresses to generate for each account.

    As an example:
        {'BTC': (
            (1, 2), (4, 5), (0, 1)
        )}

    The previous dictionary represents a single coin, BTC.
    There are three accounts, that respectively have 1, 4, and 0 private addresses and 2, 5, and 1 public addresses.
    """
    master_node = cls(0, tag='m')
    purpose_node = cls(44 + constants.CryptoConstants.BIP32_HARDENED_INDEX.value, tag="44'")
    master_node.edges.append(purpose_node)

    for coin, coin_config in config.items():
        assert isinstance(coin, str)
        assert coin_config
        coin_node = cls(constants.CoinType[coin].value, coin)
        purpose_node.edges.append(coin_node)

        for i, (n_private_addresses, n_public_addresses) in enumerate(coin_config):
            assert n_private_addresses > 0 or n_public_addresses > 0
            account_node = cls(i)
            coin_node.edges.append(account_node)

            public_node = cls(0, 'XPUB')
            account_node.edges.append(public_node)
            private_node = cls(1, 'XPRV')
            account_node.edges.append(private_node)

            previous_node = private_node
            for j in range(n_private_addresses):
                private_address_node = cls(j)
                previous_node.edges.append(private_address_node)
                previous_node = private_address_node

            previous_node = public_node
            for j in range(n_public_addresses):
                public_address_node = cls(j)
                previous_node.edges.append(public_address_node)
                previous_node = public_address_node

    return master_node


def find_bip44_node_with_path(master: hierarchy.Node, path: str) -> hierarchy.Node:
    """
    Take the `master` node of a BIP44 hierarchy and a `path` and return the corresponding node.

    The `path` should:
        1. always start with "m/44'"
        2. select a coin "/BTC"
        3. select an account "/2"
        4. select the public/private branch "/xpub"
        5. select an address "/5"

    As an example:
        m/44'/BTC/2/xpub/5

    Any suffix of a string that starts with "m/44'" is considered valid.
    """
    assert path and path.startswith("m/44'")
    path = path[len("m/44'/"):]
    path.strip('/')
    path = path.upper()
    path = path.split("/")
    path[0] = constants.CoinType[path[0]]  # Convert the coin to its corresponding index.
    path = [0 if i == 'XPUB' else i for i in path]  # Convert the public/private branches to their indexes.
    path = [1 if i == 'XPRIV' else i for i in path]
    path = [int(i) for i in path]

    assert master is not None
    assert master.id == 0 and master.tag == "m"
    assert len(master.edges) == 1

    master = master.edges[0]
    assert master.id == 44 + constants.CryptoConstants.BIP32_HARDENED_INDEX.value and master.tag == "44'"
    assert len(master.edges) > 0

    coin = path.pop(0)
    for i, v in enumerate(master.edges):
        if v.id == coin:
            master = v
            break
    else:
        assert False, "Could not find specified coin."

    if not path:
        return master

    master = master.edges[path.pop(0)]  # Address node
    if not path:
        return master

    master = master.edges[path.pop(0)]  # public/private chain
    if not path:
        return master

    for _ in range(path.pop(0) + 1):  # Go down the chain until the i-th account.
        master = master.edges[0]

    assert not path
    return master


class ArculaBIP44:
    """A Secure, Hierarchical Deterministic Wallet."""
    def __init__(self, seed: bytes, config: dict):
        root: hierarchy.ArculaNode = bip44_tree(config, cls=hierarchy.ArculaNode)
        self.arcula = arcula.Arcula(root)
        self.arcula.keygen(seed)

    def get_cold_storage_public_key(self) -> ecdsa.VerifyingKey:
        """Return the cold storage public key corresponding to the wallet."""
        return self.arcula.cold_storage_public_key

    def get_signing_key_certificate(self, path: str) -> typing.Tuple[ecdsa.SigningKey, typing.Tuple]:
        """Return the signing key of the node at `path` and its authorization certificate."""
        node = find_bip44_node_with_path(self.arcula.root, path)
        return node._signing_key, node.certificate


def main():
    pass
