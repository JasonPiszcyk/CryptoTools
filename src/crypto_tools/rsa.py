#!/usr/bin/env python3
'''
* rsa.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Basic Encryption Functionality - RSA (Asymmetric Encryption)
*
'''

# System Imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

# Our Module Imports
from crypto_tools.constants import *

#
# Globals
#



###########################################################################
#
# Encryption
#
###########################################################################
#
# encrypt
#
def encrypt(data=b"", public_key=None):
    '''
    Encrypt data 

    Parameters:
        data: The data to be encrypted
        public_key: The encryption key

    Return Value:
        bytes: The encrypted form of the data
    '''
    if not public_key:
        raise ValueError("Public key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


#
# decrypt
#
def decrypt(data=b"", private_key=None):
    '''
    Decrypt data 

    Parameters:
        data: The data to be decrypted
        private_key: The decryption key

    Return Value:
        string(possibly bytes): The unencrypted form of the data
    '''
    if not private_key:
        raise ValueError("Private key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)
    
    try:
        unencrypted_data = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        raise RuntimeWarning("Decryption Failed")

    try:
        # Try to decode the data (eg just a string)
        return unencrypted_data.decode()
    except UnicodeDecodeError:
        return unencrypted_data


###########################################################################
#
# Signing
#
###########################################################################
#
# sign
#
def sign(data=b"", private_key=None):
    '''
    Sign a message using the specified private key

    Parameters:
        datga: The data to be signed (as a string)
        private_key: The private key to do the signing

    Return Value:
        None (will raise exception if a problem occurs)
    '''
    if not private_key:
        raise ValueError("Private key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Sign the data and return the signature
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    ).hex()


#
# verify
#
def verify(data=b"", signature=None, public_key=None):
    '''
    Verify data using the specified signature and public key

    Parameters:
        data: The data to be verified (as a string)
        signature: The signature to be verified
        public_key: The public key used to verify the message

    Return Value:
        None (will raise exception if a problem occurs)
    '''
    if not signature:
        raise ValueError("Signature not supplied")

    if not public_key:
        raise ValueError("Public key was not supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Verify the signature
    try:
        public_key.verify(
            bytes.fromhex(signature),
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise RuntimeWarning("Invalid RSA Signature")

    # Signature has been verified
    return True


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
    Generate an RSA Key Pair

    Parameters:
        None

    Return Value:
        object: The RSA private key
    '''
    # Generate the keys
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    return private_key


#
# serialise_private_key
#
def serialise_private_key(private_key=None):
    '''
    Serialise a Private Key (eg PEM format)

    Parameters:
        private_key: The private key to serialise

    Return Value:
        string: The RSA private key in PEM format
    '''
    if private_key is None:
        return ""

    # Serialise the key
    serial_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
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
        string: The RSA public key in PEM format
    '''
    if public_key is None:
        return ""

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
    Deserialise a Private Key (eg PEM format back into RSAPrivateKey class)

    Parameters:
        key_pem: The key in PEM format

    Return Value:
        object: The RSA private key
    '''
    if key_pem is None:
        return ""

    # Check type of data
    if not isinstance(key_pem, bytes):
        # Assume everything else is a string...
        key_pem = str(key_pem).encode(ENCODE_METHOD)

    # Deserialise the key
    priv_key = serialization.load_pem_private_key(data=key_pem, password=None)
    return priv_key


#
# deserialise_public_key
#
def deserialise_public_key(key_pem=None):
    '''
    Deserialise a Public Key (eg PEM format back into RSA class)

    Parameters:
        key_pem: The key in PEM format

    Return Value:
        object: The RSA key
    '''
    if key_pem is None:
        return ""

    # Check type of data
    if not isinstance(key_pem, bytes):
        # Assume everything else is a string...
        key_pem = str(key_pem).encode(ENCODE_METHOD)

    # Deserialise the key
    pub_key = serialization.load_pem_public_key(data=key_pem)
    return pub_key


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
