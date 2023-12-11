#!/usr/bin/env python3
'''
* ed25519.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Basic Encryption Functionality - ED25519 (Eliptic Curve Signing)
*
'''

# System Imports
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature


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
    Generate an ed25519 Key Pair

    Parameters:
        None

    Return Value:
        object: The Ed25519 Private key
    '''
    # Generate the keys
    private_key = ed25519.Ed25519PrivateKey.generate()

    return private_key


###########################################################################
#
# Encryption
#
###########################################################################
#
# encrypt
#
def encrypt():
    '''
    Not Supported 

    Parameters:
        None

    Return Value:
        None
    '''
    raise TypeError("Ed25519 cannot be used for encrpytion/decryption")


#
# decrypt
#
def decrypt():
    '''
    Not Supported 

    Parameters:
        None

    Return Value:
        None
    '''
    raise TypeError("Ed25519 cannot be used for encrpytion/decryption")


###########################################################################
#
# Signing / Verification
#
###########################################################################
#
# sign
#
def sign(data=b"", private_key=None):
    '''
    Sign a message using the specified private key

    Parameters:
        data: The data to be signed (as a unicode string)
        private_key: The private key to do the signing

    Return Value:
        None (will raise exception if a problem occurs)
    '''
    if not private_key: raise ValueError("Private key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Sign the data and return the signature
    return private_key.sign(data)


#
# verify
#
def verify(data=b"", signature=None, public_key=None):
    '''
    Verify data using the specified signature and public key

    Parameters:
        data: The data to be verified (as a unicode string)
        signature: The signature to be verified
        public_key: The public key used to verify the message

    Return Value:
        None (will raise exception if a problem occurs)
    '''
    if not signature: raise ValueError("Signature not supplied")
    if not public_key: raise ValueError("Public key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Verify the signature
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        raise RuntimeWarning("Invalid Ed25519 Signature")

    # Signature has been verified
    return True


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
    priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(key_pem)
    return priv_key


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
