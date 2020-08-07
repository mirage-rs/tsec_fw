# -*- coding: utf-8 -*-

from binascii import unhexlify

#: Keys that are derived by KeygenLdr by encrypting a seed with csecret 0x26
#: and an auth signature, used to prevent potential attackers from tampering
#: with the Boot and Keygen stages.
USR_KEYS = [
    unhexlify("00000000000000000000000000000000"),  # CODE_SIG_01
    unhexlify("00000000000000000000000000000000"),  # CODE_ENC_01
]

assert len(USR_KEYS) == 2
assert all(map(lambda k: any(k), USR_KEYS)), "Please provide real keys in order to continue"
