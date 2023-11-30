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

# Our Module Imports
from encrypted_file.fernet import EncryptedFile_Fernet


#
# Globals
#


###########################################################################
#
# Make the Encrypted File Class use 'Fernet' as default
#
###########################################################################
class EncryptedFile(EncryptedFile_Fernet):
    ''' Encrypted file class  '''
    pass


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
