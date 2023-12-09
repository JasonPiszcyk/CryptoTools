#!/usr/bin/env python3
'''
* fernet_tmp.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Encrypted temp file using Fernet
*
'''

# System Imports
import tempfile

# Our Module Imports
import crypto_tools.fernet




# Our Module Imports

#
# Globals
#


###########################################################################
#
# Fernet_TempFile  Class
#
###########################################################################
class Fernet_TempFile():
    '''
    Temporary file encrypted with Fernet

    File disappears when closed or when file pointer is no longer used
    '''
    #
    # __init__
    #
    def __init__(self, *args, **kwargs):
        ''' Init method for class '''
        super().__init__(*args, **kwargs)

        self._fp = tempfile.TemporaryFile()
        self.filename = self._fp.name
        self.key = crypto_tools.fernet.generate_key()


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
        Read a Fernet encrypted file

        Parameters:
            None

        Return Value:
            The unencrypted contents of the file
        '''
        encrypted_contents = self._fp.read()
        return crypto_tools.fernet.decrypt(data=encrypted_contents, key=self.key)


    #
    # write
    #
    def write(self, contents):
        '''
        Read a Fernet encrypted file

        Parameters:
            None

        Return Value:
            None
        '''
        encrypted_contents = crypto_tools.fernet.encrypt(data=contents, key=self.key)
        self._fp.write(encrypted_contents)


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
