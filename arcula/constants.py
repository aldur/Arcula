#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Package-related constants."""

import enum

__author__ = 'aldur'


class CryptoConstants(enum.Enum):
    """Hold the crypto-related constants."""
    BIP32_HARDENED_INDEX = 2 ** 31
    SEED_HMAC_KEY = b'Bitcoin Seed'

    PRF_ENCRYPTION_PREFIX = b'\x00'
    PRF_PRIVATE_KEY_PREFIX = b'\x01'
    PRF_EDGE_PREFIX = b'\x02'
    PRF_SECRET_PREFIX = b'\x03'


class CoinType(enum.IntEnum):
    """
    BIP44 coin type specifications.
    Taken from https://github.com/satoshilabs/slips/blob/master/slip-0044.md.
    Make sure that they all are uppercase.
    """
    BTC = 0x80000000
    TEST = 0x80000001
    LTC = 0x80000002
    BCH = 0x80000091


assert all(k.isupper() for k in CoinType.__members__)
