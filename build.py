#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Build script for the final TSEC firmware blob.

Given a directory of the individual stages, this script signs and
encrypts them properly and builds the final binary blob to be used
by the initial bootloader.

Arguments
---------
stages : str
    Path to an intermediate directory containing the individual
    stages of the firmware.
output : str
    Path to the output file to write the firmware binary to.
"""

import argparse
from binascii import hexlify, unhexlify
from pathlib import Path
from struct import pack
import warnings

from Crypto.Cipher import AES

try:
    import KEYS
    has_keys = True
except ImportError:
    warnings.warn("The output will not work on hardware", stacklevel=2)
    has_keys = False

NULL_KEY = unhexlify("00000000000000000000000000000000")

CODE_ALIGNMENT = 1 << 8


def _align_up(value: int, size: int) -> int:
    return (value + (size - 1)) & -size


def _append_padding(blob: bytes, align: int) -> bytes:
    expected_len = _align_up(len(blob), align)
    return blob + b"\x00" * (expected_len - len(blob))


def _sxor(x: bytes, y: bytes) -> bytes:
    return bytearray(a ^ b for a, b in zip(x, y))


def _hswap(size: int) -> int:
    return (
        ((size & 0xFF) << 0x8 | (size & 0xFF00) >> 0x8) << 0x10
        | ((size & 0xFF0000) >> 0x10) << 0x8
        | size >> 0x18
    )


def read_blob(path: Path) -> bytes:
    """Reads a binary blob from a given path and pads it out so that it
    has correct Falcon code alignment.
    """
    # Read the blob from the given path.
    with open(path, "rb") as f:
        blob = f.read()

    # Pad out the binary so that it fits whole pages in the Falcon code segment.
    return _append_padding(blob, CODE_ALIGNMENT)


def aes_cmac_calculate(data: bytes, key: bytes, iv: bytes = None) -> bytes:
    """Computes an AES-CMAC key over the given data, using the given key an IV."""
    # Use null IV if no key was supplied.
    if not iv:
        iv = bytearray(AES.block_size)

    ciphertext = iv

    # Encrypt the blocks separately.
    for i in range(0, len(data), AES.block_size):
        # XOR the block with current ciphertext, encrypt it and store the result.
        block_cipher = _sxor(data[i: i + AES.block_size], ciphertext)
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(block_cipher)

    return ciphertext


def generate_boot_auth_hash(boot: bytes) -> bytes:
    """Generates an authentication hash that will be used by KeygenLdr to verify
    the integrity of the Boot blob.
    """
    # If no keys are available, return a null key instead of the actual CMAC.
    if not has_keys:
        return NULL_KEY

    code_sig_01 = KEYS.USR_KEYS[0]

    # Prepare the signature key by encrypting a buffer of zeroes
    # with the hswapped Boot blob size stored in the last word.
    sig_key = bytearray(AES.block_size)
    sig_key[0xC:] = _hswap(len(boot)).to_bytes(4, "little")
    sig_key = AES.new(code_sig_01, AES.MODE_ECB).encrypt(sig_key)

    # Calculate the CMAC key using the signature key as IV.
    return aes_cmac_calculate(boot, code_sig_01, sig_key)


def encrypt_keygen(keygen: bytes) -> bytes:
    """Encrypts the Keygen stage using AES-128-CBC."""
    # If no keys are available, pass back Keygen as-is.
    if not has_keys:
        return keygen

    return AES.new(KEYS.USR_KEYS[1], AES.MODE_CBC, KEYS.KEYGEN_AES_IV).encrypt(keygen)


def calculate_davies_meyer_mac(data: bytes, address: int) -> bytes:
    """Computes a MAC key over a given blob of data with its given IMEM start address using
    the Davies-Meyer MAC algorithm.
    """
    address = 0
    ciphertext = bytearray(AES.block_size)

    # Process every code page separately.
    for i in range(0, len(data), CODE_ALIGNMENT):
        # Process all blocks in the page separately.
        blocks = data[i: i + CODE_ALIGNMENT] + pack("<IIII", address, 0, 0, 0)
        for k in range(0, len(blocks), AES.block_size):
            # Encrypt the block with AES-128-ECB and XOR with existing ciphertext.
            block_cipher = AES.new(blocks[k: k + AES.block_size], AES.MODE_ECB).encrypt(ciphertext)
            ciphertext = _sxor(block_cipher, ciphertext)

        # Advance to the next page.
        address += 0x100

    return ciphertext


def generate_hs_auth_signature(data: bytes, address: int) -> bytes:
    """Generates an auth signature that can be used for Heavy Secure Mode authentication
    over a given code blob.
    """
    assert len(data) % 0x100 == 0

    # If no keys are available, return a null key instead of the actual signature.
    if not has_keys:
        return NULL_KEY

    # Craft the Heavy Secure Mode authentication signature for the given code blob.
    mac = calculate_davies_meyer_mac(data, address)
    return AES.new(KEYS.HS_SIGNING_KEY, AES.MODE_ECB).encrypt(mac)


def build_and_sign_firmware(args):
    """Builds the final TSEC firmware blob given the separate stages."""
    # Read the separate firmware stages from the build directory.
    boot = read_blob(args.stages / "boot.bin")
    keygenldr = read_blob(args.stages / "keygenldr.bin")
    keygen = read_blob(args.stages / "keygen.bin")
    securebootldr = read_blob(args.stages / "securebootldr.bin")
    secureboot = read_blob(args.stages / "secureboot.bin")

    # TODO: Implement remaining crypto.

    # Generate an auth hash for the Boot blob.
    boot_cmac = generate_boot_auth_hash(boot)

    # Generate the auth signatures for KeygenLdr and Keygen.
    keygenldr_auth_sig = generate_hs_auth_signature(keygenldr, len(boot))
    keygen_auth_sig = generate_hs_auth_signature(keygen, len(boot) + len(keygen))

    # Encrypt the Keygen blob.
    keygen = encrypt_keygen(keygen)
    if has_keys:
        keygen_iv = KEYS.KEYGEN_AES_IV
    else:
        keygen_iv = NULL_KEY

    # Generate the key data blob containing metadata used across all stages.
    key_table = pack(
        "16s16s16s16s16s16s16sIIIII124x",
        NULL_KEY,                                       # 0x10 bytes debug key (empty)
        boot_cmac,                                      # 0x10 bytes Boot auth hash
        keygenldr_auth_sig,                             # 0x10 bytes KeygenLdr auth hash
        keygen_auth_sig,                                # 0x10 bytes Keygen auth hash
        keygen_iv,                                      # 0x10 bytes Keygen AES IV
        b"HOVI_EKS_01\x00\x00\x00\x00\x00",             # 0x10 bytes HOVI EKS seed
        b"HOVI_COMMON_01\x00\x00",                      # 0x10 bytes HOVI COMMON seed
        len(boot),                                      # 0x4 bytes Boot stage size
        len(keygenldr),                                 # 0x4 bytes KeygenLdr stage size
        len(keygen),                                    # 0x4 bytes Keygen stage size
        len(securebootldr),                             # 0x4 bytes SecureBootLdr stage size
        len(secureboot),                                # 0x4 bytes SecureBoot stage size
    )
    key_table = _append_padding(key_table, CODE_ALIGNMENT)
    assert len(key_table) == 0x100

    # Write the final firmware blob to the output file.
    with open(args.output, "wb") as f:
        f.write(boot)
        f.write(key_table)
        f.write(keygenldr)
        f.write(keygen)
        f.write(secureboot)
        f.write(securebootldr)


def main(parser, args):
    # TODO: Implement the build of the separate stages.

    # Build the final TSEC firmware binary.
    build_and_sign_firmware(args)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Build script for the final TSEC firmware blob."
    )
    parser.set_defaults(func=main)

    parser.add_argument(
        "stages",
        nargs="?",
        type=lambda s: Path(s),
        help="Path to a build directory with the individual stages.",
    )
    parser.add_argument(
        "output",
        help="Path to the final TSEC firmware binary.",
        nargs="?",
        default="tsec_fw.bin"
    )

    return parser, parser.parse_args()


if __name__ == "__main__":
    parser, args = parse_args()
    args.func(parser, args)
