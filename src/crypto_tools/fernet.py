#!/usr/bin/env python3
'''
* fernet.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Basic Encryption Functionality - Fernet (Symmetric Encryption)
*
'''

# System Imports
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from typing import get_args

import base64
import secrets

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
# generate_key
#
def generate_key():
    '''
    Generate an encryption key

    Parameters:
        None

    Return Value:
        object: The Fernet object
    '''
    return Fernet.generate_key()


#
# generate_salt
#
def generate_salt():
    '''
    Generate asalt

    Parameters:
        None

    Return Value:
        bytes: A generated salt
    '''
    return secrets.token_bytes(SALT_SIZE)


#
# use_key
#
def use_key(key=None):
    '''
    Use a key derived elsewhere

    Parameters:
        key: A URL-safe base64-encoded 32-byte key

    Return Value:
        object: The Fernet object
    '''
    if not key: return None

    return Fernet(key)


#
# derive_key
#
def derive_key(salt=None, password="", security="high"):
    '''
    Derive a key from a password

    Parameters:
        salt: The salt use in the derivation of the password (or a new one will be generated)
        password: The password for the password generation
        security: Determines the computation time of the key.  Must be one of
            "low", "medium", or "high"

    Return Value:
        bytes: The salt
        bytes: The key
    '''
    # Determine the computational cost for the key
    security_options = get_args(SECURITY_LEVELS)
    assert security in security_options, \
            f"'{security}' is not in {security_options}"

    if security == "low":
        _computation_cost = SCRYPT_N_LOW
    elif security == "medium":
        _computation_cost = SCRYPT_N_MEDIUM
    else:
        _computation_cost = SCRYPT_N_HIGH

    if not salt:
        # Generate a salt
        salt = generate_salt()

    # Check type of the password
    if not isinstance(password, bytes):
        # Assume everything else is a string...
        password = str(password).encode(ENCODE_METHOD)

    # Derive the key from the password/salt
    _kdf = Scrypt(salt=salt, length=SCRYPT_LENGTH, n=_computation_cost, r=SCRYPT_R, p=SCRYPT_P)
    _key = base64.urlsafe_b64encode(_kdf.derive(password))

    return ( salt, _key )


###########################################################################
#
# Encryption / Decryption
#
###########################################################################
#
# encrypt
#
def encrypt(data=b"", key=None):
    '''
    Encrypt data 

    Parameters:
        data: The data to be encrypted
        key: The encryption key

    Return Value:
        bytes: The encrypted form of the data
    '''
    if not key:
        raise ValueError("Encryption key must be supplied")
    
    fernet = Fernet(key)

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    return fernet.encrypt(data)


#
# decrypt
#
def decrypt(data=b"", key=None):
    '''
    Decrypt data using the key in the class

    Parameters:
        data: The data to be decrypted
        key: The encryption key

    Return Value:
        string(possibly bytes): The unencrypted form of the data
    '''
    if not key:
        raise ValueError("Encryption key must be supplied")
    
    fernet = Fernet(key)
    try:
        unencrypted_data = fernet.decrypt(data)
    except InvalidToken:
        raise RuntimeWarning("Invalid encryption key")

    try:
        # Try to decode the data (eg just a string)
        return unencrypted_data.decode()
    except UnicodeDecodeError:
        return unencrypted_data


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
