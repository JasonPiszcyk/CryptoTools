#!/usr/bin/env python3
'''
* test_fernet_data.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Test for fernet on data objects
*
'''

# System Imports
import pytest
import json

# Our Module Imports
import crypto_tools


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
###########################################################################
#
# Start the tests...
#
###########################################################################
key = crypto_tools.fernet.generate_key()
wrong_key = crypto_tools.fernet.generate_key()
password = "test_password_1234"
wrong_password = "wrong_password"

#
# Test encrypting/decrypting a file
#
def test_file():
    assert key is not None

    # Encrypt a simple string
    simple_string = "This is a string"
    encrypted_string = crypto_tools.fernet.encrypt(data=simple_string, key=key)
    assert encrypted_string is not None
    assert str(encrypted_string) != str(simple_string)

    # Encrypt the file
    file = crypto_tools.EncryptedFile(filename="/tmp/jpp.enc", password=password, security="low")
    file.write(data=FILE_CONTENTS)

    # Read the file
    with open("/tmp/jpp.enc", "rb") as f:
        new_contents = f.read()

    assert str(FILE_CONTENTS) != str(new_contents)

    # Decrypt the file
    new_contents = file.read()
    assert str(FILE_CONTENTS) == str(new_contents)

    # Wrong password
    wrong_pwd = crypto_tools.EncryptedFile(filename="/tmp/jpp.enc", password=wrong_password, security="low")
    with pytest.raises(RuntimeWarning):
        wrong_pwd.read()

    # Wrong file
    wrong_pwd = crypto_tools.EncryptedFile(filename="/tmp/made_some_name_up.txt", password=password, security="low")
    with pytest.raises(RuntimeWarning):
        wrong_pwd.read()



