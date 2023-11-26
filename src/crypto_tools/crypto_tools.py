#!/usr/bin/env python3
'''
* name.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Description
*
'''

# System Imports
import cryptography
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import secrets
import base64



# Our Module Imports

#
# Globals
#
ENCODE_METHOD = "utf-8"
SALT_SIZE = 16

SCRYPT_LENGTH = 32
SCRYPT_N = 2**20
SCRYPT_R = 8
SCRYPT_P = 1



###########################################################################
#
# EncryptedFile Class
#
###########################################################################
#
# EncryptedFile
#
class EncryptedFile():
    ''' Encrypted File '''
    # Attributes
    filename = ""
    password = ""

    # Private Attributes


    #
    # __init__
    #
    def __init__(self, *args, filename="", password="", **kwargs):
        ''' Init method for class '''
        super().__init__(*args, **kwargs)

        self.filename = filename
        self.password = password


    ###########################################################################
    #
    # Access methods for the file
    #
    ###########################################################################
    #
    # read
    #
    def read(self):
        '''
        Read an encrypted file

        Parameters:
            None

        Return Value:
            The unencrypted contents of the file
        '''
        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        with open(self.filename, "rb") as file:
            contents = file.read()
        
        if not (len(contents) > SALT_SIZE):
            return None

        salt = contents[:SALT_SIZE]
        data = contents[SALT_SIZE:]

        print(f"Salt from File on Read: >{salt}<")

        # Generate a key, then decrypt the data
        key = derive_key(password=self.password, salt=salt)        
        return decrypt(data=data, key=key)


    #
    # write
    #
    def write(self, data=None):
        '''
        Write an encrypted file

        Parameters:
            data: The unencrypted file contents to be written

        Return Value:
             None
        '''
        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        # Get a key to use for encryption
        salt = generate_salt(size=SALT_SIZE)
        print(f"Salt: >{salt}<")
        key = derive_key(password=self.password, salt=salt)        

        # Encrypt the data
        contents = salt + encrypt(data=data, key=key)
        print(f"Salt from File on Write: >{contents[:SALT_SIZE]}<")

        with open(self.filename, "wb") as file:
            file.write(contents)


###########################################################################
#
# Cryptographic functions
#
###########################################################################
#
# encrypt
#
def encrypt(data=None, key=None):
    '''
    Encrypt data using the supplied key

    Parameters:
        data: The data to be encryted

    Return Value:
        bytes: The encypted form of the data
    '''
    if not key:
        raise ValueError("'key' argument must be supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Encrypt the data
    fernet = Fernet(key)
    return fernet.encrypt(data)


#
# decrypt
#
def decrypt(data=None, key=None):
    '''
    Decrypt data using the supplied key

    Parameters:
        data: The encrypted data

    Return Value:
        bytes: The unencrypted form of the data
    '''
    if not key:
        raise ValueError("'key' argument must be supplied")

    # Check type of data
    if not isinstance(data, bytes):
        # Assume everything else is a string...
        data = str(data).encode(ENCODE_METHOD)

    # Decrypt the data
    unencrypted_data = b""
    fernet = Fernet(key)
    try:
        unencrypted_data = fernet.decrypt(data)
    except cryptography.fernet.InvalidToken:
        raise RuntimeError("Invalid encryption key")

    return unencrypted_data.decode(ENCODE_METHOD)


#
# salt
#
def generate_salt(size=SALT_SIZE):
    '''
    Generate a salt value

    Parameters:
        None

    Return Value:
        bytes: The salt value
    '''
    return secrets.token_bytes(size)


#
# key
#
def derive_key(password="", salt=None):
    '''
    Generate an encryption key 

    Parameters:
        password: The password used to generate the key
        salt: The salt used to generate the key

    Return Value:
        bytes: The key
    '''
    if not salt:
        raise ValueError("'salt' argument must be supplied")

    # Check type of the password
    if not isinstance(password, bytes):
        # Assume everything else is a string...
        password = str(password).encode(ENCODE_METHOD)

    # Derive the key from the password/salt
    kdf = Scrypt(salt=salt, length=SCRYPT_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return base64.urlsafe_b64encode(kdf.derive(password))


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
