#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Send and receive coins from an Arcula wallet on the BCH test network.

You can ignore any function starting with an underscore.
The `test_faucet_to_wallet` function sends BCH from the testnet faucet to a wallet address.
The `wallet_to_test_faucet` function sends them back to the faucet.

In our tests, we used this tool to generate the following transactions:
1. https://explorer.bitcoin.com/tbch/tx/337a67d36b8ecdd6bfbf2db654e54d71fcfd7a295cc97494e47272d305a6f444
2. https://explorer.bitcoin.com/tbch/tx/10594853b5dc6d482fc1abf24b68afde04ba71bbf7c780db4c98381064ded302
"""

import bitcash
import ecdsa
import mnemonic
import requests
import time

from bitcash.transaction import VERSION_1, LOCK_TIME, HASH_TYPE, SEQUENCE, TxIn, \
    construct_input_block, construct_output_block
from bitcash.crypto import double_sha256, sha256
from bitcash.utils import int_to_varint, hex_to_bytes, int_to_unknown_bytes, bytes_to_hex
from bitcash.network.meta import Unspent

from arcula import bip44, crypto, encode

__author__ = 'aldur'

BCH_TO_SATOSHI = 10 ** 8
BCH_FEES_SATOSHI = 0.001 * BCH_TO_SATOSHI

BLOCKDOZER_T_API = 'https://tbch.blockdozer.com/insight-api/'
BITCOIN_EXPLORER_URL = 'https://explorer.bitcoin.com/tbch/tx/{}'

# --- User configuration starts here. --- #
# Configure the wallet here.
# Refer to `arcula.bip44` for the documentation of `WALLET_CONFIG`.
WALLET_CONFIG = {
    'BCH': (
        # (n. of public, private addresses)
        (1, 2),
        (4, 5),
        (0, 1)
    )
}

# This is the account of the wallet that will receive and send money.
FROM_ACCOUNT = "m/44'/BCH/1/xpub/3"

# This fixes the randomness of the seed generation process.
MNEMONIC_SEED = b'correct horse battery staple'
# --- User configuration ends here. --- #


def verification_key_to_address(v_key):
    """Convert an ECDSA key to a Bitcoin Cash address."""
    return bitcash.format.public_key_to_address(encode.verification_key_to_bytes_33(v_key), version='test')


def arcula_locking_script(cold_storage_key: ecdsa.VerifyingKey, identifier: bytes) -> bytes:
    """Create an Arcula locking script for `cold_storage_key` and `identifier`."""
    cold_storage_key = encode.verification_key_to_bytes_33(cold_storage_key)
    cold_storage_key = int_to_unknown_bytes(len(cold_storage_key)) + cold_storage_key
    identifier = int_to_unknown_bytes(len(identifier)) + identifier

    # Bitcoin OP codes
    OP_CHECKSIG = b'\xac'
    OP_DUP = b'\x76'
    OP_CAT = b'\x7e'
    OP_TOALTSTACK = b'\x6b'
    OP_FROMALTSTACK = b'\x6c'
    OP_CHECKDATASIGVERIFY = b'\xbb'

    return OP_DUP + OP_TOALTSTACK + identifier + OP_CAT + cold_storage_key + \
        OP_CHECKDATASIGVERIFY + OP_FROMALTSTACK + OP_CHECKSIG


def _construct_arcula_output_block(outputs):
    """Construct an Arcula output."""
    assert len(outputs) == 1
    output_block = b''

    for data in outputs:
        (dest, i), amount = data
        assert amount

        script = arcula_locking_script(dest, i)
        output_block += amount.to_bytes(8, byteorder='little')

        output_block += int_to_unknown_bytes(len(script), byteorder='little')
        output_block += script

    return output_block


def _tx_in_boilerplate(unspent, output, script_code, construct_output_block_f):
    script = hex_to_bytes(unspent.script)
    script_len = int_to_unknown_bytes(len(script), byteorder='little')
    tx_id = hex_to_bytes(unspent.txid)[::-1]
    tx_index = unspent.txindex.to_bytes(4, byteorder='little')
    amount = unspent.amount.to_bytes(8, byteorder='little')
    tx_in = TxIn(script, script_len, tx_id, tx_index, amount)

    hash_previous_outputs = double_sha256(tx_id + tx_index)
    hash_sequence = double_sha256(SEQUENCE)

    output_block = construct_output_block_f([output])
    hash_outputs = double_sha256(output_block)

    to_be_hashed = (
            VERSION_1 +
            hash_previous_outputs +
            hash_sequence +
            tx_in.txid +
            tx_in.txindex +
            int_to_varint(len(script_code)) +
            script_code +
            tx_in.amount +
            SEQUENCE +
            hash_outputs +
            LOCK_TIME +
            HASH_TYPE
    )
    hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin Cash
    return tx_in, hashed, output_block


def _tx_out_boilerplate(tx_in, unlocking_script, output_block):
    tx_in.script = unlocking_script
    tx_in.script_len = int_to_unknown_bytes(len(unlocking_script), byteorder='little')

    input_count = int_to_unknown_bytes(1, byteorder='little')
    output_count = int_to_unknown_bytes(1, byteorder='little')
    return bytes_to_hex(
        VERSION_1 +
        input_count +
        construct_input_block([tx_in]) +
        output_count +
        output_block +
        LOCK_TIME
    )


def _create_apkh2pkh_transaction(cold_storage_key, signing_key, certificate, unspent, output):
    """Create a ArculaPublicKeyHash2PublicKeyHash transaction."""
    certificate, (public_signing_key, identifier) = certificate
    script_code = arcula_locking_script(cold_storage_key, identifier)
    tx_in, hashed, output_block = _tx_in_boilerplate(unspent, output, script_code, construct_output_block)

    signature = signing_key.sign(hashed) + b'\x41'
    unlocking_script = (
        int_to_varint(len(signature)) +
        signature +
        int_to_varint(len(certificate)) +
        certificate +
        int_to_varint(len(public_signing_key)) +
        public_signing_key
    )

    return _tx_out_boilerplate(tx_in, unlocking_script, output_block)


def _create_pkh2apkh_transaction(private_key, unspent, output):
    """Create a PublicKeyHash2ArculaPublicKeyHash transaction."""
    script_code = private_key.scriptcode
    tx_in, hashed, output_block = _tx_in_boilerplate(unspent, output, script_code, _construct_arcula_output_block)
    signature = private_key.sign(hashed) + b'\x41'

    public_key = private_key.public_key
    public_key_len = len(public_key).to_bytes(1, byteorder='little')
    unlocking_script = (
        int_to_unknown_bytes(len(signature), byteorder='little') +
        signature +
        public_key_len +
        public_key
    )

    return _tx_out_boilerplate(tx_in, unlocking_script, output_block)


def test_faucet_to_wallet(w):
    """Transfer BCH from a PKH address to an Arcula wallet address (deterministically generated)."""
    # Compute the address that will receive from the testnet faucet. https://coinfaucet.eu/en/bch-testnet/
    # This is not a wallet address, hence we'll have to use its private verification key to spend the first transaction.
    initial_key = crypto.ecdsa_keygen(crypto.sha3_512_half(b'initial_key' + MNEMONIC_SEED), w.arcula.curve)
    initial_address = verification_key_to_address(initial_key.get_verifying_key())
    print(
        f"Before continuing please use the faucet (https://coinfaucet.eu/en/bch-testnet/) to fund the following "
        f"test-net address: '{initial_address}'. "
    )
    input('Press any key to continue...')

    unspent_outputs = bitcash.network.NetworkAPI.get_unspent_testnet(initial_address)
    unspent_output, *_ = unspent_outputs
    bch_to_send = (unspent_output.amount - BCH_FEES_SATOSHI) / BCH_TO_SATOSHI
    assert bch_to_send > 0, bch_to_send

    # This is the address of the wallet that will receive the funds through our Arcula transaction format,
    # and then will spend them again.
    wallet_key, from_identifier = w.get_cold_storage_public_key(FROM_ACCOUNT)
    wallet_address = verification_key_to_address(wallet_key)

    print(f"Sending {bch_to_send} BCH to the wallet '{wallet_address}' node with identifier '{from_identifier}'...")

    tx_hex = _create_pkh2apkh_transaction(
        bitcash.PrivateKeyTestnet.from_int(initial_key.privkey.secret_multiplier),
        unspent_output,
        ((wallet_key, from_identifier), int(bch_to_send * BCH_TO_SATOSHI)),
    )

    bitcash.network.NetworkAPI.broadcast_tx_testnet(tx_hex)
    tx_hash = bitcash.transaction.calc_txid(tx_hex)

    print(f"Transaction: '{BITCOIN_EXPLORER_URL.format(tx_hash)}'.")
    return tx_hash


def wallet_to_test_faucet(w, tx_hash, faucet_address='mv4rnyY3Su5gjcDNzbMLKBQkBicCtHUtFB'):
    """Transfer BCH from an Arcula wallet address (deterministically generated) back to the faucet."""
    # This is the address holding the funds using our Arcula transaction format.
    cold_storage_key = w.get_cold_storage_public_key()
    cold_storage_address = verification_key_to_address(cold_storage_key)
    from_signing_key, from_certificate = w.get_signing_key_certificate(FROM_ACCOUNT)

    r = requests.get(f"{BLOCKDOZER_T_API}/tx/{tx_hash}")
    assert r.status_code == 200, r.status_code
    unspent, *_ = r.json()['vout']
    unspent_output = \
        Unspent(int(float(unspent['value']) * BCH_TO_SATOSHI), -1, unspent['scriptPubKey']['hex'], tx_hash, 0)
    bch_to_send = (unspent_output.amount - BCH_FEES_SATOSHI) / BCH_TO_SATOSHI
    assert bch_to_send > 0, bch_to_send

    print(f"Sending {bch_to_send} BCH from the wallet '{cold_storage_address}' node "
          f"with identifier '{from_certificate[1]}' to '{faucet_address}'...")

    tx_hex = _create_apkh2pkh_transaction(
        cold_storage_key,
        bitcash.PrivateKeyTestnet.from_int(from_signing_key.privkey.secret_multiplier),
        from_certificate,
        unspent_output,
        (faucet_address, int(bch_to_send * BCH_TO_SATOSHI)),
    )

    bitcash.network.NetworkAPI.broadcast_tx_testnet(tx_hex)
    tx_hash = bitcash.transaction.calc_txid(tx_hex)

    print(f"Transaction: '{BITCOIN_EXPLORER_URL.format(tx_hash)}'.")
    return tx_hash


def main():
    m = mnemonic.Mnemonic(language='english').to_mnemonic(crypto.sha3_512(MNEMONIC_SEED)[:256 // 8])
    seed = mnemonic.Mnemonic.to_seed(m)

    print('Generating wallet...')
    w = bip44.ArculaBIP44(seed, WALLET_CONFIG)  # Create a BIP44 wallet with 3 accounts.

    # Faucet: https://coinfaucet.eu/en/bch-testnet/
    tx_hash = test_faucet_to_wallet(w)
    print('Waiting for the transaction to propagate...')
    time.sleep(3)
    wallet_to_test_faucet(w, tx_hash)


if __name__ == '__main__':
    main()
