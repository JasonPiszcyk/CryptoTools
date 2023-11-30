#!/usr/bin/env python3
'''
* fernet_data.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Test for fernet on data objects
*
'''

# System Imports

# Our Module Imports
import crypto_tools
# import crypto_tools.fernet
# from crypto_tools import fernet


#
# Globals
#

FILE_CONTENTS = '''
This is a file
It has some stuff in it

And some more stuff

End of the file...

JP
'''

key = crypto_tools.fernet.generate_key()

# Data Encryption
x = "This is a string"
ex = crypto_tools.fernet.encrypt(data=x, key=key)
dex = crypto_tools.fernet.decrypt(data=ex, key=key)
print(f"Unencrypted: >{x}<")
print(f"Encrypted: >{ex}<")
print(f"Decrypted: >{dex}<")


# encfile = crypto_tools.EncryptedFile(filename="/tmp/jpp.enc", password="jason")
# # encfile.write(data=file_contents)
# print(f"Contents: {encfile.read()}")
