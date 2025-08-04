#!/usr/bin/env python3
'''
* fernet.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Base class for an encrypted file
*
'''

# System Imports
import os.path

# Our Module Imports
import crypto_tools.fernet
from crypto_tools.constants import *

#
# Globals
#


###########################################################################
#
# EncryptedFile - Fernet
#
###########################################################################
class EncryptedFile_Fernet():
    ''' Encrypted file using Fernet '''
    #
    # __init__
    #
    def __init__(self, filename="", key="", salt=b"", password="",
                security="high", salt_in_file=True):
        ''' Init method for class '''
        self._security = security
        self.filename = filename
        self.salt_in_file = salt_in_file
        self._header_size = 0

        if key:
            # If a key was provided, use that
            self._key = key
        
        else:
            # Write salt directly so it doesn;t generate a key
            self._salt = salt

            # Use the property to generate a key
            self.password = password

        # Set the key / salt
        self.key = key


    ###########################################################################
    #
    # Properties
    #
    ###########################################################################
    @property
    def salt(self):
        return self._salt
    
    @salt.setter
    def salt(self, value):
        # Generate a key using the salt
        self._salt = value

        # Generate a key using the stored password/salt
        self._salt, self._key = crypto_tools.fernet.derive_key(
            salt=self._salt,
            password=self._password,
            security=self._security
        )


    @property
    def password(self):
        # Return nothing (it's a password!)
        return None
    
    @password.setter
    def password(self, value):
        # Generate a key using the password
        self._password = value

        # Generate a key using the stored password/salt
        self._salt, self._key = crypto_tools.fernet.derive_key(
            salt=self._salt,
            password=self._password,
            security=self._security
        )


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
        Read from the encrypted file

        Parameters:
            None

        Return Value:
            The unencrypted contents
        '''
        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        # Read in the contents
        if not os.path.isfile(self.filename):
            raise RuntimeWarning("'filename' not found")

        if self.salt_in_file:
            self._header_size = SALT_SIZE
        else:
            self._header_size = 0

        with open(self.filename, "rb") as file:
            _contents = file.read()
        
        if not (len(_contents) > self._header_size):
            return None

        if self._header_size > 0:
            # Use the salt to generate a new key
            self.salt = _contents[:self._header_size]
            _enc_data = _contents[self._header_size:]
        else:
            _enc_data = _contents

        return crypto_tools.fernet.decrypt(data=_enc_data, key=self._key)


    #
    # write
    #
    def write(self, data=""):
        '''
        Write an encrypted file

        Parameters:
            data: The data to be encrypted and written

        Return Value:
            None
        '''
        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        # Create a header if the salt is to be stored in the file
        if self.salt_in_file:
            self._header_size = SALT_SIZE
            _header = self._salt
        else:
            self._header_size = 0
            _header = b""
    
        # Encrypt the data
        _enc_data = crypto_tools.fernet.encrypt(data=data, key=self._key)

        _contents = _header + _enc_data

        with open(self.filename, "wb") as file:
            file.write(_contents)


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
