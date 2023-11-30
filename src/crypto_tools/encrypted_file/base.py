#!/usr/bin/env python3
'''
* base.py
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

#
# Globals
#


###########################################################################
#
# EncryptedFile Base Class
#
###########################################################################
class EncryptedFileBase():
    ''' Base class for encrypted files '''
    #
    # __init__
    #
    def __init__(self, *args, filename="", key="", header_size=0, **kwargs):
        ''' Init method for class '''
        super().__init__(*args, **kwargs)

        self.filename = filename
        self.key = key
        self.header_size = header_size

        self._header = b""
        self._data = b""
        self._file_read = False


    ###########################################################################
    #
    # Access methods for the file
    #
    ###########################################################################
    #
    # _read
    #
    def _read(self):
        '''
        Read an encrypted file into the class

        Parameters:
            None

        Return Value:
            None
        '''
        # Have we already read in the contents?
        if self.file_read:
            return

        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        # Read in the contents
        if not os.path.isfile(self.filename):
            return

        with open(self.filename, "rb") as file:
            contents = file.read()
        
        if not (len(contents) > self.header_size):
            return None

        if self.header_size > 0:
            self._header = contents[:self.header_size]
            self._data = contents[self.header_size:]
        else:
            self._data = contents

        self._file_read = True


    #
    # _write
    #
    def _write(self):
        '''
        Write an encrypted file

        Parameters:
            None

        Return Value:
            None
        '''
        if not self.filename:
            raise ValueError("'filename' attribute must be set")

        # Encrypt the data
        contents = self._header + self._data

        with open(self.filename, "wb") as file:
            file.write(contents)


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
