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
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import base64

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
# Serialisation
#
###########################################################################
#
# serialise_private_key
#
def serialise_private_key(private_key=None):
    '''
    Serialise a Private Key (eg PEM format)

    Parameters:
        private_key: The private key to serialise

    Return Value:
        string: The private key in PEM format
    '''
    if not private_key: return ""

    # Serialise the key
    serial_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    try:
        # Try to decode the data (eg just a string)
        return serial_key.decode()
    except UnicodeDecodeError:
        return serial_key


#
# serialise_public_key
#
def serialise_public_key(public_key=None):
    '''
    Serialise a Public Key (eg PEM format)

    Parameters:
        public_key: The public key to serialise

    Return Value:
        string: The public key in PEM format
    '''
    if not public_key: return ""

    # Serialise the key
    serial_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        # Try to decode the data (eg just a string)
        return serial_key.decode()
    except UnicodeDecodeError:
        return serial_key


#
# deserialise_private_key
#
def deserialise_private_key(key_pem=None):
    '''
    Deserialise a Private Key (eg PEM format back into Ed25519PrivateKey class)

    Parameters:
        key_pem: The key in PEM format

    Return Value:
        object: The Ed25519 Private key
    '''
    if not key_pem: return None

    # Check type of data
    if not isinstance(key_pem, bytes):
        # Assume everything else is a string...
        key_pem = str(key_pem).encode(ENCODE_METHOD)

    # Deserialise the key
    priv_key = load_pem_private_key(key_pem, password=None)
    return priv_key


#
# deserialise_public_key
#
def deserialise_public_key(key_pem=None):
    '''
    Deserialise a Public Key (eg PEM format back into Ed25519PublicKey class)

    Parameters:
        key_pem: The key in PEM format

    Return Value:
        object: The Ed25519 Public key
    '''
    if not key_pem: return None

    # Check type of data
    if not isinstance(key_pem, bytes):
        # Assume everything else is a string...
        key_pem = str(key_pem).encode(ENCODE_METHOD)

    # Deserialise the key
    pub_key = load_pem_public_key(key_pem)
    return pub_key


###########################################################################
#
# Format
#
###########################################################################
#
# format_fernet
#
def format_fernet(key=None):
    '''
    Format the key for use with Fernet

    Parameters:
        keyL The key to format

    Return Value:
        string: The private key in PEM format
    '''
    return base64.urlsafe_b64encode(key[:32])


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
