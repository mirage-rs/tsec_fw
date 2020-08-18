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

from Crypto.Cipher import AES

try:
    import KEYS
except ImportError:
    raise RuntimeError("Cannot build the firmware without keys") from None

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
    code_sig_01 = KEYS.USR_KEYS[0]

    # Prepare the signature key by encrypting a buffer of zeroes
    # with the hswapped Boot blob size stored in the last word.
    sig_key = bytearray(AES.block_size)
    sig_key[0xC:] = _hswap(len(boot)).to_bytes(4, "little")
    sig_key = AES.new(code_sig_01, AES.MODE_ECB).encrypt(sig_key)

    # Calculate the CMAC key using the signature key as IV.
    return aes_cmac_calculate(boot, code_sig_01, sig_key)


def main(parser, args):
    # Read the separate firmware stages from the build directory.
    boot = read_blob(args.stages / "boot.bin")
    keygenldr = read_blob(args.stages / "keygenldr.bin")
    keygen = read_blob(args.stages / "keygen.bin")
    securebootldr = read_blob(args.stages / "securebootldr.bin")
    secureboot = read_blob(args.stages / "secureboot.bin")

    # TODO: Implement remaining crypto.

    # Encrypt the Keygen blob with AES-128-CBC.
    keygen = AES.new(KEYS.USR_KEYS[1], AES.MODE_CBC, KEYS.KEYGEN_AES_IV).encrypt(keygen)

    # Generate the key data blob containing metadata used across all stages.
    key_table = pack(
        "16s16s16s16s16s16s16sIIIII124x",
        unhexlify("00000000000000000000000000000000"),  # 0x10 bytes debug key (empty)
        generate_boot_auth_hash(boot),                  # 0x10 bytes Boot auth hash
        unhexlify("00000000000000000000000000000000"),  # 0x10 bytes KeygenLdr auth hash
        unhexlify("00000000000000000000000000000000"),  # 0x10 bytes Keygen auth hash
        KEYS.KEYGEN_AES_IV,                             # 0x10 bytes Keygen AES IV
        b"HOVI_EKS_01\x00\x00\x00\x00\x00",             # 0x10 bytes HOVI EKS seed
        b"HOVI_COMMON_01\x00\x00",                      # 0x10 bytes HOVI COMMON seed
        len(boot),                                      # 0x4 bytes Boot stage size
        len(keygenldr),                                 # 0x4 bytes KeygenLdr stage size
        len(keygen),                                    # 0x4 bytes Keygen stage size
        len(securebootldr),                             # 0x4 bytes SecureBootLdr stage size
        len(secureboot),                                # 0x4 bytes SecureBoot stage size
    )
    key_table = _append_padding(key_table, CODE_ALIGNMENT)

    # Write the final firmware blob to the output file.
    with open(args.output, "wb") as f:
        f.write(boot)
        f.write(key_table)
        f.write(keygenldr)
        f.write(keygen)
        f.write(secureboot)
        f.write(securebootldr)


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
