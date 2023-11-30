#!/usr/bin/env python3
'''
* crypto_tools.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Implement basic encryption functionality
*
'''

# System Imports
import cryptography
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

import secrets
import base64

import os.path


# Our Module Imports
from encrypted_file.base import EncryptedFileBase

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
# EncryptedFile - Fernet
#
###########################################################################
class EncryptedFile_Fernet(EncryptedFileBase):
    ''' Encrypt file using Fernet '''
    # Attributes

    # Private Attributes
    __salt = None
    __key = None
    __password = ""

    # Properties
    @property
    def salt(self):
        return self.__salt
    
    @salt.setter
    def salt(self, value):
        # Generate a key using the salt
        self.__salt = value
        self.__key = self._derive_key()   


    @property
    def password(self):
        # Return nothing (it's a password!)
        return None
    
    @password.setter
    def password(self, value):
        # Generate a key using the password
        self.__password = value
        self.__key = self._derive_key()   


    #
    # __init__
    #
    def __init__(self, *args, password="", salt=None, **kwargs):
        ''' Init method for class '''
        super().__init__(*args, **kwargs)

        self.__password = password
        self.__salt = salt
        self.__key = self._derive_key()


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
        
        self.__read()

        # Decrypt the data
        return self.decrypt()


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

        # Encrypt the data
        self.__header = self.salt
        self.__data = self.encrypt(data)
        self.__write()


    #
    # decrypt
    #
    def decrypt(self):
        '''
        Decrypt data using the key in the class

        Parameters:
            None

        Return Value:
            bytes: The unencrypted form of the data
        '''
        if not self.__key:
            raise RuntimeError("Encryption key empty")

        # Check type of data
        if not isinstance(self.__data, bytes):
            # Assume everything else is a string...
            self.__data = str(self.__data).encode(ENCODE_METHOD)

        # Decrypt the data
        unencrypted_data = b""
        fernet = Fernet(self.__key)
        try:
            unencrypted_data = fernet.decrypt(self.__data)
        except InvalidToken:
            raise RuntimeError("Invalid encryption key")

        try:
            # Try to decode the data (eg just a string)
            return unencrypted_data.decode(ENCODE_METHOD)
        except UnicodeDecodeError:
            return unencrypted_data


    #
    # encrypt
    #
    def encrypt(self, data=None):
        '''
        Encrypt data using the supplied key

        Parameters:
            data: The data to be encryted

        Return Value:
            bytes: The encypted form of the data
        '''
        if not self.__key:
            raise ValueError("'key' argument must be supplied")

        # Check type of data
        if not isinstance(data, bytes):
            # Assume everything else is a string...
            data = str(data).encode(ENCODE_METHOD)

        # Encrypt the data
        fernet = Fernet(self.__key)
        return fernet.encrypt(data)


    #
    # _derive_key
    #
    def _derive_key(self):
        '''
        Generate an encryption key 

        Parameters:
            None

        Return Value:
            bytes: The key
        '''
        if not self.salt:
            # Generate a salt
            self.salt = secrets.token_bytes(SALT_SIZE)

        # Check type of the password
        if not isinstance(self.__password, bytes):
            # Assume everything else is a string...
            self.__password = str(self.__password).encode(ENCODE_METHOD)

        # Derive the key from the password/salt
        kdf = Scrypt(salt=self.salt, length=SCRYPT_LENGTH, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
        return base64.urlsafe_b64encode(kdf.derive(self.__password))


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
