#!/usr/bin/env python3
'''
Encrypted File Class using Fernet encrpytion

Copyright (C) 2025 Jason Piszcyk
Email: Jason.Piszcyk@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (See file: COPYING). If not, see
<https://www.gnu.org/licenses/>.
'''
##########################################################################
#
# Imports
#
###########################################################################
from __future__ import annotations

# Shared variables, constants, etc

# System Modules
import os.path

# Local app modules
import crypto_tools.fernet
from crypto_tools.constants import SALT_SIZE

# Imports for python variable type hints


###########################################################################
#
# Module Specific Items
#
###########################################################################
#
# Types
#

#
# Constants
#

#
# Global Variables
#


#
# Globals
#


###########################################################################
#
# EncryptedFile_Fernet Class Definition
#
###########################################################################
class EncryptedFile_Fernet():
    '''
    Encrypted file using Fernet

    Attributes:
        filename (str): Name of the file
        key (bytes): The encryption key
        salt (bytes): The salt
    '''
    #
    # __init__
    #
    def __init__(
            self,
            filename: str = "",
            key: bytes = b"",
            salt: bytes = b"",
            password: str = "",
            security: str = "high",
            salt_in_file: bool = True
    ):
        '''
        Initialises the instance.

        Args:
            filename (str): Name of the file
            key (bytes): The encryption key
            salt (bytes): The salt
            password (str): Password used to derive a key if one not provided
            security (str): Determines the computation time of the key.  Must
                be one of "low", "medium", or "high"
            salt_in_file (bool): If tru store the salt in the file header

        Returns:
            None

        Raises:
            None
        '''
        # Private Attributes
        self.__security = security
        self.__header_size = 0
        self.__key = b""
        self.__salt = b""
        self.__password = ""

        # Attributes
        self.filename = filename
        self.salt_in_file = salt_in_file

        if key:
            # If a key was provided, use that
            self.__key = key
        
        else:
            # Write salt directly so it doesn't generate a key
            self.__salt = salt

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
        ''' The salt '''
        return self.__salt
    
    @salt.setter
    def salt(self, value):
        ''' When the salt changes, derive a new key '''
        # Generate a key using the salt
        self.__salt = value

        # Generate a key using the stored password/salt
        self.__salt, self.__key = crypto_tools.fernet.derive_key(
            salt=self.__salt,
            password=self.__password,
            security=self.__security
        )


    @property
    def password(self):
        ''' The password '''
        # Return nothing (it's a password!)
        return None
    
    @password.setter
    def password(self, value):
        ''' When the password changes, derive a new key '''
        # Generate a key using the password
        self.__password = value

        # Generate a key using the stored password/salt
        self.__salt, self.__key = crypto_tools.fernet.derive_key(
            salt=self.__salt,
            password=self.__password,
            security=self.__security
        )


    ###########################################################################
    #
    # Access methods for the file
    #
    ###########################################################################
    #
    # read
    #
    def read(self) -> bytes:
        '''
        Read from the encrypted file

        Args:
            None

        Returns:
            bytes: The unencrypted contents

        Raises:
            AssertionError
                when filename not set
            ValueError
                when file cannot be found
        '''
        assert self.filename, "filename attribute must be set"

        # Read in the contents
        if not os.path.isfile(self.filename):
            raise ValueError("'filename' not found")

        if self.salt_in_file:
            self.__header_size = SALT_SIZE
        else:
            self.__header_size = 0

        with open(self.filename, "rb") as file:
            _contents = file.read()
        
        if not (len(_contents) > self.__header_size):
            return b""

        if self.__header_size > 0:
            # Use the salt to generate a new key
            self.salt = _contents[:self.__header_size]
            _enc_data = _contents[self.__header_size:]
        else:
            _enc_data = _contents

        return crypto_tools.fernet.decrypt(data=_enc_data, key=self.__key)


    #
    # write
    #
    def write(
            self,
            data: bytes = b""
    ):
        '''
        Write an encrypted file

        Args:
            data (bytes): The data to be encrypted and written

        Returns:
            None

        Raises:
            AssertionError
                when filename not set
            ValueError
                when file cannot be found
        '''
        assert self.filename, "filename attribute must be set"
        assert isinstance(data, bytes), "Data must be in byte format"

        # Create a header if the salt is to be stored in the file
        if self.salt_in_file:
            self.__header_size = SALT_SIZE
            _header = self.__salt
        else:
            self.__header_size = 0
            _header = b""
    
        # Encrypt the data
        _enc_data = crypto_tools.fernet.encrypt(data=data, key=self.__key)

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
