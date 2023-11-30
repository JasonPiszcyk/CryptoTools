#!/usr/bin/env python3
'''
*
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

###########################################################################
#
# Start the tests...
#
###########################################################################
key = crypto_tools.fernet.generate_key()
wrong_key = crypto_tools.fernet.generate_key()

#
# Test encrypting/decrypting a simple string
#
def test_string():
    assert key is not None

    # Encrypt a simple string
    simple_string = "This is a string"
    encrypted_string = crypto_tools.fernet.encrypt(data=simple_string, key=key)
    assert encrypted_string is not None
    assert str(encrypted_string) != str(simple_string)

    # Decrypt the right string with the right key
    decrypted_string = crypto_tools.fernet.decrypt(data=encrypted_string, key=key)
    assert encrypted_string is not None
    assert str(decrypted_string) == str(simple_string)

    # Decrypt the wrong string with the right key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data="random string", key=key)

    # Decrypt the right string with the wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data=encrypted_string, key=wrong_key)

    # Decrypt the wrong string with the wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data="random string", key=wrong_key)


#
# Test encrypting/decrypting a simple string
#
def test_list():
    assert key is not None

    # Encrypt 
    simple_list = [ "a", "b", "c", "d" ]
    list_json = json.dumps(simple_list)
    encrypted_string = crypto_tools.fernet.encrypt(data=list_json, key=key)
    assert encrypted_string is not None

    # Decrypt
    decrypted_string = crypto_tools.fernet.decrypt(data=encrypted_string, key=key)
    assert encrypted_string is not None
    assert json.loads(decrypted_string) == simple_list

    # Decrypt - wrong data
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data=json.dumps(["1", "2"]), key=key)

    # Decrypt - wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data=encrypted_string, key=wrong_key)

    # Decrypt - wrong data, wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.fernet.decrypt(data=json.dumps(["1", "2"]), key=wrong_key)


