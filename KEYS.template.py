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
