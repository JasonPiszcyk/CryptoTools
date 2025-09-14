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
from crypto_tools import rsa

#
# Globals
#

###########################################################################
#
# Start the tests...
#
###########################################################################
priv_key = rsa.generate_keys()
wrong_key = rsa.generate_keys()

simple_bytes = b"This is a simple string"
wrong_bytes = b"This is not the string you are looking for"
empty_bytes=b""


#
# Test signing/verifying a simple string
#
def test_sign_string():
    assert priv_key

    # Sign a string
    _signature = rsa.sign(data=simple_bytes, private_key=priv_key)
    assert _signature

    # Verify with correct key
    rsa.verify(
        data=simple_bytes,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    # Verify with incorrect string
    assert not rsa.verify(
        data=wrong_bytes,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    assert not rsa.verify(
        data=empty_bytes,
        signature=_signature,
        public_key=priv_key.public_key()
    )

    # Verify with incorrect key
    assert not rsa.verify(
        data=simple_bytes,
        signature=_signature,
        public_key=wrong_key.public_key()
    )

    # Verify with incorrect signature
    assert not rsa.verify(
        data=simple_bytes,
        signature=b"wrong_sig",
        public_key=priv_key.public_key()
    )


def test_encrypt_string():
    _encrypted_string = rsa.encrypt(
        data=simple_bytes,
        public_key=priv_key.public_key()
    )
    assert _encrypted_string
    assert _encrypted_string != simple_bytes

    # Decrypt the right string with the right key
    decrypted_string = rsa.decrypt(
        data=_encrypted_string, private_key=priv_key)
    assert decrypted_string is not None
    assert str(decrypted_string) == str(simple_bytes)

    # Decrypt the wrong string with the right key
    with pytest.raises(ValueError):
        decrypted_string = rsa.decrypt(
            data=wrong_bytes,
            private_key=priv_key
    )

    # Decrypt the right string with the wrong key
    with pytest.raises(ValueError):
        decrypted_string = rsa.decrypt(
            data=_encrypted_string,
            private_key=wrong_key
        )

    # Decrypt the wrong string with the wrong key
    with pytest.raises(ValueError):
        decrypted_string = rsa.decrypt(
            data=wrong_bytes,
            private_key=wrong_key
        )

