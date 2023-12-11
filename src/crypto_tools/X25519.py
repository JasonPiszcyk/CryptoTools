#!/usr/bin/env python3
'''
* X25519.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* X25519 Key exchange
*
'''

# System Imports
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import binascii
import sys


# Our Module Imports
from crypto_tools.constants import *

#
# Globals
#

###########################################################################
#
# Keys
#
###########################################################################
#
# generate_keys
#
def generate_keys():
    '''
    Generate an X25519 Key Pair

    Parameters:
        None

    Return Value:
        object: The X25519 Private key
    '''
    # Generate the keys
    private_key = X25519PrivateKey.generate()

    return private_key


#
# derive_key
#
def derive_key(local_private_key=None, remote_public_key=None, info=b"", key_length=32):
    '''
    Derive the shared key

    Parameters:
        local_private_key: The private key generated locally
        remote_public_key: The public key sent from the remote end
        info: String to be the same on both ends

    Return Value:
        object: The X25519 Private key
    '''
    if not local_private_key: return None
    if not remote_public_key: return None

    # Check type of data
    if not isinstance(info, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Derive a key from the combination of public/private keys
    # Derived key length fixed 
    shared_key = local_private_key.exchange(remote_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(), length=key_length, salt=None, info=info,).derive(shared_key)

    return derived_key


###########################################################################
#
# In case this is run directly rather than imported...
#
###########################################################################
'''
Handle case of being run directly rather than imported
'''
if __name__ == "__main__":
    pass
