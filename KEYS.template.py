# -*- coding: utf-8 -*-

from binascii import unhexlify

#: Static keys that are derived by KeygenLdr to prevent potential attackers
#: from tampering with the blobs or analyzing the code.
#:
#: The following algorithm derives these keys, using a variable seed:
#: usr_key = aes_encrypt(aes_encrypt(csecret(0x26), get_seed()), auth_hash)
USR_KEYS = [
    unhexlify("00000000000000000000000000000000"),  # CODE_SIG_01
    unhexlify("00000000000000000000000000000000"),  # CODE_ENC_01
]

assert len(USR_KEYS) == 2
assert all(map(any, USR_KEYS)), "Please provide real keys in order to continue"

#: The AES IV that should be used for AES-128-CBC over Keygen stage code.
KEYGEN_AES_IV = unhexlify("00000000000000000000000000000000")

#: The signing key for authenticating code into the Heavy Secure Mode of the
#: Falcon which grants full privileges to the running code.
#:
#: The following algorithm derives the key that is used for auth:
#: hs_signing_key = aes_encrypt(csecret(0x1), b"\x00" * 0x10)
HS_SIGNING_KEY = unhexlify("00000000000000000000000000000000")

assert any(HS_SIGNING_KEY), "Please provide real keys in order to continue"
