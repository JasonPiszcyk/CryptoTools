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
from crypto_tools import ed25519

#
# Globals
#

###########################################################################
#
# Start the tests...
#
###########################################################################
priv_key = ed25519.generate_keys()
wrong_key = ed25519.generate_keys()

simple_byte_data = b"This is a simple string"
wrong_byte_data = b"This is not the string you are looking for"
empty = b""


#
# Test signing/verifying a simple string
#
def test_sign_string_ed25519():
    assert priv_key is not None
    assert wrong_key is not None

    # Sign a string
    _signature = ed25519.sign(
        data=simple_byte_data,
        private_key=priv_key
    )
    print(f"Signature: {_signature}")

    # Verify with correct key
    assert ed25519.verify(
        data=simple_byte_data,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    # Verify with incorrect string
    assert not ed25519.verify(
        data=wrong_byte_data,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    assert not ed25519.verify(
        data=empty,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    # Verify with incorrect key
    assert not ed25519.verify(
        data=simple_byte_data,
        signature=_signature,
        public_key=wrong_key.public_key()
    )

    # Verify with incorrect signature
    assert not ed25519.verify(
        data=simple_byte_data,
        signature=b"wrong_sig",
        public_key=priv_key.public_key()
    )
