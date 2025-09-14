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
from crypto_tools import fernet
from crypto_tools.encrypted_file.fernet import EncryptedFile_Fernet


#
# Globals
#

FILE_CONTENTS = b'''
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
key = fernet.generate_key()
wrong_key = fernet.generate_key()
password = "test_password_1234"
wrong_password = "wrong_password"

#
# Test encrypting/decrypting a file
#
def test_file():
    assert key

    # Encrypt a simple string
    _simple_bytes = b"This is a string"
    _encrypted_bytes = fernet.encrypt(data=_simple_bytes, key=key)
    assert _encrypted_bytes
    assert _encrypted_bytes != _simple_bytes

    # Encrypt the file
    _file = EncryptedFile_Fernet(
        filename="/tmp/jpp.enc",
        password=password,
        security="low"
    )
    _file.write(data=FILE_CONTENTS)

    # Read the file
    with open("/tmp/jpp.enc", "rb") as f:
        _encrypted_contents = f.read()

    assert FILE_CONTENTS != _encrypted_contents

    # Decrypt the file
    _decrypted_contents = _file.read()
    assert FILE_CONTENTS == _decrypted_contents

    # Wrong password
    _wrong_pw_f = EncryptedFile_Fernet(
        filename="/tmp/jpp.enc",
        password=wrong_password,
        security="low"
    )
    with pytest.raises(ValueError):
        _wrong_pw_f.read()

    # Wrong file
    _wrong_pw_f = EncryptedFile_Fernet(
        filename="/tmp/made_some_name_up.txt",
        password=password,
        security="low"
    )

    with pytest.raises(ValueError):
        _wrong_pw_f.read()



