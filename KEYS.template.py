# -*- coding: utf-8 -*-

from binascii import unhexlify

##########################################
## Falcon Heavy Secure Mode Signing Key ##
##########################################

SIGNING_KEY = unhexlify("00000000000000000000000000000000")

assert any(SIGNING_KEY), "Please fill this file with real keys"

# Optional; Used to encrypt SecureBoot if you have it, but will build regardless.
CSECRET_06 = unhexlify("00000000000000000000000000000000")

##############################################
## Keys used throughout the KeygenLdr stage ##
##############################################

KEYGENLDR_KEKS = [
    unhexlify("00000000000000000000000000000000"),  # CODE_SIG_01
    unhexlify("00000000000000000000000000000000"),  # CODE_ENC_01
]

assert len(KEYGENLDR_KEKS) == 2
assert all(map(any, KEYGENLDR_KEKS)), "Please fill this file with real keys"

KEYGEN_AES_IV = unhexlify("00000000000000000000000000000000")

###########################################
## Keys used throughout the Keygen stage ##
###########################################

KEYGEN_DEBUG_KEY = unhexlify("00000000000000000000000000000000")

KEYGEN_TSEC_SEEDS = [
    unhexlify("00000000000000000000000000000000"),  # HOVI_EKS_01
    unhexlify("00000000000000000000000000000000"),  # HOVI_COMMON_01
]

assert len(KEYGEN_TSEC_SEEDS) == 2
assert all(map(any, KEYGEN_TSEC_SEEDS)), "Please fill this file with real keys"

###############################################
## Keys used throughout the SecureBoot stage ##
###############################################

HOVI_ENC_KEY = unhexlify("00000000000000000000000000000000")

assert any(HOVI_ENC_KEY), "Please fill this file with real keys"

HOVI_SIG_KEY = unhexlify("00000000000000000000000000000000")

assert any(HOVI_SIG_KEY), "Please fill this file with real keys"

HOVI_IV = unhexlify("00000000000000000000000000000000")
