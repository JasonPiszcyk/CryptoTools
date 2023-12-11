#!/usr/bin/env python3
'''
*
* test_ed25519_data.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Test for Ed25519 on data objects
*
'''

# System Imports
import pytest

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
priv_key = crypto_tools.ed25519.generate_keys()
wrong_key = crypto_tools.ed25519.generate_keys()

simple_string = "This is a simple string"
wrong_string = "This is not the string you are looking for"
empty_string = b""


#
# Test signing/verifying a simple string
#
def test_sign_string_ed25519():
    assert priv_key is not None
    assert wrong_key is not None

    # Sign a string
    signature = crypto_tools.ed25519.sign(data=simple_string, private_key=priv_key)
    print(f"Signature: {signature}")

    # Verify with correct key
    crypto_tools.ed25519.verify(data=simple_string, signature=signature, public_key=priv_key.public_key())

    # Verify with incorrect string
    with pytest.raises(RuntimeWarning):
        crypto_tools.ed25519.verify(data=wrong_string, signature=signature, public_key=priv_key.public_key())

    with pytest.raises(RuntimeWarning):
        crypto_tools.ed25519.verify(data=empty_string, signature=signature, public_key=priv_key.public_key())

    # Verify with incorrect key
    with pytest.raises(RuntimeWarning):
        crypto_tools.ed25519.verify(data=simple_string, signature=signature, public_key=wrong_key.public_key())

    # Verify with incorrect signature
    with pytest.raises(RuntimeWarning):
        crypto_tools.ed25519.verify(data=simple_string, signature=b"wrong_sig", public_key=priv_key.public_key())

