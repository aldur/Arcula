#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Represent an access hierarchy as a graph."""

import ecdsa

import typing

__author__ = 'aldur'


class Node:
    """A generic graph node, identified by a numeric `id` and an additional `tag`, that holds a `_key`."""

    def __init__(self, identifier: int, tag: str = None):
        assert 0 <= identifier < 2 ** 64
        self.id: int = identifier  # A 8 bytes-max node identifier.
        self.tag: str = tag  # An optional tag holding additional info.

        self.edges: typing.List[Node] = []  # Exit edges from this node.

        self._key: typing.Optional[bytes] = None  # Holds the node's key

    def __repr__(self) -> str:
        return f'{self.id}' if self.tag is None else f'{self.tag}'

    def __str__(self) -> str:
        return self.__repr__()


class DHKANode(Node):
    """
    A node of the DHKA, identified by a numeric `id` and an additional `tag`, that holds a `_label`, a `_secret`,
    and an `_encryption_key` (in addition to the private `_key`).
    """
    def __init__(self, identifier: int, tag: str = None):
        super().__init__(identifier, tag)

        self._label: typing.Optional[bytes] = None
        self._secret: typing.Optional[bytes] = None
        self._encryption_key: typing.Optional[bytes] = None

        self.encrypted_edges = []  # Holds encrypted public information associated to the edges.


class ArculaNode(DHKANode):
    """
    A node of the Arcula HDW, identified by a numeric `id` and an additional `tag`, that additionally holds:
    1. A `_signing_key` (pair, secret and public);
    2. A `certificate` (authorizing the signing key to spend on behalf of this node's identifier `id`).
    """
    def __init__(self, identifier: int, tag: str = None):
        super().__init__(identifier, tag)
        self.certificate: typing.Optional[bytes] = None
        self._signing_key: typing.Optional[ecdsa.SigningKey] = None


class Hierarchy:
    """The access hierarchy of a (deterministic) key assignment scheme or of a hierarchical deterministic wallet."""

    def __init__(self, root: Node):
        assert root is not None
        self.root = root

    def keygen(self, seed: bytes):
        """Setup the key assignment scheme or the hierarchical deterministic wallet."""
        raise NotImplementedError
