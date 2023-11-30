#!/usr/bin/env python3
'''
*
* test_rsa_data.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Test for RSA on data objects
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
priv_key = crypto_tools.rsa.generate_keys()
wrong_key = crypto_tools.rsa.generate_keys()

simple_string = "This is a simple string"
wrong_string = "This is not the string you are looking for"
empty_string=b""


#
# Test signing/verifying a simple string
#
def test_sign_string():
    assert priv_key is not None
    assert wrong_key is not None

    # Sign a string
    signature = crypto_tools.rsa.sign(data=simple_string, private_key=priv_key)
    assert signature is not None

    # Verify with correct key
    crypto_tools.rsa.verify(data=simple_string, signature=signature, public_key=priv_key.public_key())

    # Verify with incorrect string
    with pytest.raises(RuntimeWarning):
        crypto_tools.rsa.verify(data=wrong_string, signature=signature, public_key=priv_key.public_key())

    with pytest.raises(RuntimeWarning):
        crypto_tools.rsa.verify(data=empty_string, signature=signature, public_key=priv_key.public_key())

    # Verify with incorrect key
    with pytest.raises(RuntimeWarning):
        crypto_tools.rsa.verify(data=simple_string, signature=signature, public_key=wrong_key.public_key())

    # Verify with incorrect signature
    with pytest.raises(RuntimeWarning):
        crypto_tools.rsa.verify(data=simple_string, signature=b"wrong_sig".hex(), public_key=priv_key.public_key())




def test_encrypt_string():
    encrypted_string = crypto_tools.rsa.encrypt(data=simple_string, public_key=priv_key.public_key())
    assert encrypted_string is not None
    assert str(encrypted_string) != str(simple_string)

    # Decrypt the right string with the right key
    decrypted_string = crypto_tools.rsa.decrypt(data=encrypted_string, private_key=priv_key)
    assert decrypted_string is not None
    assert str(decrypted_string) == str(simple_string)

    # Decrypt the wrong string with the right key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.rsa.decrypt(data=wrong_string, private_key=priv_key)

    # Decrypt the right string with the wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.rsa.decrypt(data=encrypted_string, private_key=wrong_key)

    # Decrypt the wrong string with the wrong key
    with pytest.raises(RuntimeWarning):
        decrypted_string = crypto_tools.rsa.decrypt(data=wrong_string, private_key=wrong_key)

