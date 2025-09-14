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
from crypto_tools import fernet
from crypto_tools.constants import ENCODE_METHOD

#
# Globals
#

###########################################################################
#
# Start the tests...
#
###########################################################################
key = fernet.generate_key()
wrong_key = fernet.generate_key()

#
# Test encrypting/decrypting a simple string
#
def test_string():
    assert key is not None

    # Encrypt a simple string
    _simple_bytes = b"This is a string"
    _encrypted_bytes = fernet.encrypt(data=_simple_bytes, key=key)
    assert _encrypted_bytes
    assert _encrypted_bytes != _simple_bytes

    # Decrypt the right string with the right key
    _decrypted_bytes = fernet.decrypt(data=_encrypted_bytes, key=key)
    assert _decrypted_bytes
    assert _decrypted_bytes == _simple_bytes

    # Decrypt the wrong string with the right key
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(data=b"random string", key=key)

    # Decrypt the right string with the wrong key
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(
            data=_encrypted_bytes,
            key=wrong_key
        )

    # Decrypt the wrong string with the wrong key
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(data=b"random string", key=wrong_key)


#
# Test encrypting/decrypting a simple string
#
def test_list():
    assert key is not None

    # Encrypt 
    _simple_list = [ "a", "b", "c", "d" ]
    _list_json = json.dumps(_simple_list).encode(ENCODE_METHOD)
    _wrong_json = json.dumps(["1", "2"]).encode(ENCODE_METHOD)
    _encrypted_bytes = fernet.encrypt(data=_list_json, key=key)
    assert _encrypted_bytes

    # Decrypt
    _decrypted_bytes = fernet.decrypt(data=_encrypted_bytes, key=key)
    assert _decrypted_bytes
    assert json.loads(_decrypted_bytes.decode(ENCODE_METHOD)) == _simple_list

    # Decrypt - wrong data
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(
            data=_wrong_json,
            key=key
        )

    # Decrypt - wrong key
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(data=_encrypted_bytes, key=wrong_key)

    # Decrypt - wrong data, wrong key
    with pytest.raises(ValueError):
        _decrypted_bytes = fernet.decrypt(
            data=_wrong_json,
            key=wrong_key
        )


