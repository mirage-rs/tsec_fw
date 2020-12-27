#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
from pathlib import Path
from shutil import rmtree, which
from struct import pack, unpack
import subprocess
import sys
from warnings import warn

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

try:
    import KEYS
    has_keys = True
except ImportError:
    warn("The output will not work on hardware", stacklevel=2)
    has_keys = False

ROOT_DIR = Path(__file__).parent
BUILD_DIR = ROOT_DIR / "build"
STAGES_DIR = ROOT_DIR / "stages"
LIB_DIR = ROOT_DIR / "lib"
FIRMWARE = ROOT_DIR / "tsec_fw.bin"

NULL_KEY = b"\x00" * AES.block_size
CODE_ALIGN = 1 << 8

ASM_SUFFIX = ".fuc"
BIN_SUFFIX = ".bin"
STAGES = (
    "boot",
    "keygenldr",
    "keygen",
)
# m4 macros that are going to be defined in every stage build.
KEY_DATA_PHYS_START = 0x300
KEY_DATA_REAL_SIZE = 0x84
KEY_DATA_ALIGNED_SIZE = 0x100
M4_DEFS = {
    "_KEY_DATA_ADDR": KEY_DATA_PHYS_START,
    "_KEY_DATA_SIZE": KEY_DATA_REAL_SIZE,
    "_KEY_DATA_LEGACY_SIZE": 0x7C,
    "_KEY_DATA_ALIGNED_SIZE": KEY_DATA_ALIGNED_SIZE,
    "_IS_KEYGEN_DECRYPTED": 1,
}


def is_tool_installed(name: str):
    return which(name) is not None


def assemble(stage_name: str, m4_defs: dict = {}):
    source = STAGES_DIR / stage_name / "src"
    source_file = source / f"{stage_name}{ASM_SUFFIX}"
    stage = BUILD_DIR / f"{stage_name}{BIN_SUFFIX}"

    # Let m4 process all macros first before building.
    m4_defs = [f"--define={name}={value}" for name, value in m4_defs.items()]
    result = subprocess.run([
        "m4", "-I", str(LIB_DIR), "-I", str(source), *m4_defs,
        str(source / f"{stage_name}_main.fuc"),
    ], stdout=subprocess.PIPE, universal_newlines=True)

    # Write the resulting output to a new file called like the stage itself.
    with source_file.open("w", encoding="utf-8") as f:
        f.write(result.stdout)

    # Assemble the firmware blob into the build directory.
    subprocess.run([
        "envyas", "-m", "falcon", "-V", "fuc5", "-F", "crypt",
        str(source_file), "-i", "-o", str(stage),
    ])


def align_up(value: int, align: int):
    return (value + (align - 1)) & -align


def sxor(x: bytes, y: bytes):
    return bytearray(a ^ b for a, b in zip(x, y))


def read_stage_blob(stage_name: str):
    with (BUILD_DIR / f"{stage_name}{BIN_SUFFIX}").open("rb") as f:
        blob = f.read()
    return blob + b"\x00" * (align_up(len(blob), CODE_ALIGN) - len(blob))


def hswap(value: int):
    # Ported from Falcon assembly:
    # hswap b16 value
    # hswap b32 value
    # hswap b16 value
    return (
        ((value & 0xFF) << 0x8 | (value & 0xFF00) >> 0x8) << 0x10
        | ((value & 0xFF0000) >> 0x10) << 0x8
        | (value & 0xFF000000) >> 0x18
    )


def calculate_boot_cmac(boot: bytes, signature: bytes):
    if not has_keys:
        return NULL_KEY

    # Encrypt the signature of KeygenLdr with the CODE_SIG_01 KEK for AES encryption.
    code_sig_01_key = AES.new(
        KEYS.KEYGENLDR_KEKS[0],
        AES.MODE_ECB
    ).encrypt(signature)
    code_sig_01 = AES.new(code_sig_01_key, AES.MODE_ECB)

    # Calculate the CMAC using the CODE_SIG_01 key and the previous signature key.
    # We can't use Crypto.Hash.CMAC here because NVIDIA's algorithm is customized.
    cmac = code_sig_01.encrypt(pack("<IIII", 0, 0, 0, hswap(len(boot))))
    for i in range(0, len(boot), AES.block_size):
        cmac = code_sig_01.encrypt(sxor(boot[i:i + AES.block_size], cmac))

    return cmac


def calculate_davies_meyer_mac(blob: bytes, addr: int) -> bytes:
    assert addr % 0x100 == 0

    mac = bytearray(AES.block_size)
    for i in range(0, len(blob), AES.block_size):
        blocks = blob[i:i + CODE_ALIGN] + pack("<IIII", addr, 0, 0, 0)
        for j in range(0, len(blocks), AES.block_size):
            cipher = AES.new(blocks[j:j + AES.block_size],
                             AES.MODE_ECB).encrypt(mac)
            mac = sxor(cipher, mac)

        # Advance to the next page.
        addr += CODE_ALIGN

    return mac


def calculate_cauth_signature(blob: bytes, addr: int) -> bytes:
    assert len(blob) % 0x100 == 0
    if not has_keys:
        return NULL_KEY

    mac = calculate_davies_meyer_mac(blob, addr)
    return AES.new(KEYS.SIGNING_KEY, AES.MODE_ECB).encrypt(mac)


def build_and_sign_firmware():
    BUILD_DIR.mkdir(exist_ok=True)

    if (KEYS.ENCRYPT_KEYGEN if has_keys else False):
        M4_DEFS["_IS_KEYGEN_DECRYPTED"] = 0

    stage_start_addrs = []
    start_addr = 0
    for stage in STAGES:
        stage_start_addrs.append(start_addr)
        M4_DEFS["_START_ADDR"] = start_addr
        assemble(stage, M4_DEFS)
        start_addr += len(read_stage_blob(stage))

    boot = read_stage_blob("boot")
    keygenldr = read_stage_blob("keygenldr")
    keygen = read_stage_blob("keygen")

    # Sign KeygenLdr and Keygen for Heavy Secure mode authentication.
    keygenldr_hash = calculate_cauth_signature(keygenldr, stage_start_addrs[1])
    keygen_hash = calculate_cauth_signature(keygen, stage_start_addrs[2])

    # Calculate a CMAC over Boot code that will be verified by KeygenLdr.
    boot_cmac = calculate_boot_cmac(boot, keygenldr_hash)

    # Encrypt Keygen, if desired.
    if (KEYS.ENCRYPT_KEYGEN if has_keys else False):
        code_enc_01_key = AES.new(
            KEYS.KEYGENLDR_KEKS[1], AES.MODE_ECB).encrypt(keygenldr_hash)
        keygen = AES.new(code_enc_01_key, AES.MODE_CBC,
                         KEYS.KEYGEN_AES_IV).encrypt(keygen)

    # Pack the key data blob containing auth hashes, keygen seeds and stage sizes.
    key_data = pack(
        "16s16s16s16s16s16s16sIIIII124x",
        # 0x10 bytes Keygen debug key
        KEYS.KEYGEN_DEBUG_KEY if has_keys else NULL_KEY,
        # 0x10 bytes Boot auth hash
        boot_cmac,
        # 0x10 bytes KeygenLdr cauth hash
        keygenldr_hash,
        # 0x10 bytes Keygen cauth hash
        keygen_hash,
        # 0x10 bytes Keygen AES IV
        KEYS.KEYGEN_AES_IV if has_keys else NULL_KEY,
        # 0x10 bytes HOVI EKS seed
        KEYS.KEYGEN_TSEC_SEEDS[0] if has_keys else NULL_KEY,
        # 0x10 bytes HOVI COMMON seed
        KEYS.KEYGEN_TSEC_SEEDS[1] if has_keys else NULL_KEY,
        # 0x4 bytes Boot stage size
        len(boot),
        # 0x4 bytes KeygenLdr stage size
        len(keygenldr),
        # 0x4 bytes Keygen stage size
        0,
        # 0x4 bytes SecureBootLdr stage size
        0,
        # 0x4 bytes SecureBoot stage size
        0,
    )

    # Write the final TSEC firmware blob.
    with FIRMWARE.open("wb") as f:
        f.write(boot)
        f.write(key_data)
        f.write(keygenldr)
        f.write(keygen)


def do_cleanup():
    rmtree(BUILD_DIR, ignore_errors=True)

    for stage in STAGES:
        (STAGES_DIR / stage / "src" / f"{stage}.fuc").unlink(missing_ok=True)

    FIRMWARE.unlink(missing_ok=True)


COMMANDS = {
    # The empty default command, which builds and signs the TSEC firmware.
    "make": build_and_sign_firmware,
    # Cleans up all intermediary build files and the final firmware blob.
    "clean": do_cleanup,
}

if __name__ == "__main__":
    assert os.name != "nt", "Builds are discouraged on Windows due to incompatible dependencies"

    # Make sure the user has the required dependencies installed.
    assert is_tool_installed(
        "envyas"), "Please install https://github.com/envytools/envytools"
    assert is_tool_installed(
        "m4"), "Please install m4 using your package manager"

    try:
        handler = COMMANDS.get(sys.argv[1])
    except IndexError:
        handler = COMMANDS[""]

    if not handler:
        print(f"Usage: {sys.argv[0]} {'|'.join(COMMANDS.keys())}")
    else:
        handler()
