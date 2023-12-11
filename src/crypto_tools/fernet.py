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
