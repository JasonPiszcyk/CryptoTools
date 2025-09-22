#!/usr/bin/env python3
'''
ED25519 (Eliptic Curve Signing)

Copyright (C) 2025 Jason Piszcyk
Email: Jason.Piszcyk@gmail.com

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (See file: COPYING). If not, see
<https://www.gnu.org/licenses/>.
'''
###########################################################################
#
# Imports
#
###########################################################################
from __future__ import annotations

# Shared variables, constants, etc

# System Modules
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.exceptions import InvalidSignature

# Local app modules
from crypto_tools.constants import ENCODE_METHOD

# Imports for python variable type hints


###########################################################################
#
# Module Specific Items
#
###########################################################################
#
# Types
#

#
# Constants
#

#
# Global Variables
#


###########################################################################
#
# Keys
#
###########################################################################
#
# generate_keys
#
def generate_keys() -> ed25519.Ed25519PrivateKey:
    '''
    Generate an ed25519 Key Pair

    Args:
        None

    Returns:
        ed25519.Ed25519PrivateKey - The generated key

    Raises:
        None
    '''
    # Generate the keys
    return ed25519.Ed25519PrivateKey.generate()


###########################################################################
#
# Encryption
#
###########################################################################
#
# encrypt
#
def encrypt():
    '''
    Encryption not Suppport by ED25519

    Args:
        None

    Returns:
        None

    Raises:
        NotImplementedError
            Always
    '''
    raise NotImplementedError(
        "Ed25519 cannot be used for encryption/decryption"
    )


#
# decrypt
#
def decrypt():
    '''
    Decryption not Suppport by ED25519

    Args:
        None

    Returns:
        None

    Raises:
        NotImplementedError
            Always
    '''
    raise NotImplementedError(
        "Ed25519 cannot be used for encryption/decryption"
    )


###########################################################################
#
# Signing / Verification
#
###########################################################################
#
# sign
#
def sign(
        data: bytes = b"",
        private_key: ed25519.Ed25519PrivateKey | None = None
) -> bytes:
    '''
    Sign data using the specified private key

    Args:
        data (bytes): The data to be signed
        private_key (ed25519.Ed25519PrivateKey): The private key used to sign
            the data

    Returns:
        bytes: The signature

    Raises:
        AssertionError:
            When data is not in byte format
            when a private key is not supplied
    '''
    assert isinstance(data, bytes), "Data must be in byte format"
    assert isinstance(private_key, ed25519.Ed25519PrivateKey), \
            "Private key must be of type Ed25519PrivateKey" 

    # Sign the data and return the signature
    return private_key.sign(data)


#
# verify
#
def verify(
        data: bytes = b"",
        signature: bytes = b"",
        public_key: ed25519.Ed25519PublicKey | None = None
) -> bool:
    '''
    Verify data using the specified signature and public key

    Args:
        data (bytes): The data to be verified
        signature (bytes): The signature to be used to verify the data
        public_key (ed25519.Ed25519PublicKey): The public key used to verify
            the data

    Returns:
        bool: True if successful - False if signature or key invalid

    Raises:
        AssertionError:
            When data is not in byte format
            when a signature is not supplied
            when a publc key is not supplied
    '''
    assert isinstance(data, bytes), "Data must be in byte format"
    assert isinstance(signature, bytes), "Signature must be in byte format"
    assert isinstance(public_key, ed25519.Ed25519PublicKey), \
            "Private key must be of type Ed25519PrivateKey" 
    if not signature: raise AssertionError("Signature not supplied")

    # Verify the signature
    try:
        public_key.verify(signature, data)
    except InvalidSignature:
        return False

    # Signature has been verified
    return True


###########################################################################
#
# Serialisation
#
###########################################################################
#
# serialise_private_key
#
def serialise_private_key(
        private_key: ed25519.Ed25519PrivateKey | None = None
) -> str:
    '''
    Serialise a Private Key (eg PEM format)

    Args:
        private_key (ed25519.Ed25519PrivateKey): The private key to serialise

    Returns:
        str: The serialised key (blank if failed)

    Raises:
        AssertionError:
            when a private key is not supplied
    '''
    assert isinstance(private_key, ed25519.Ed25519PrivateKey), \
            "Private key must be of type Ed25519PrivateKey" 

    # Serialise the key
    _serial_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    try:
        # Try to decode the data
        return _serial_key.decode(ENCODE_METHOD)
    except UnicodeDecodeError:
        return ""


#
# serialise_public_key
#
def serialise_public_key(
        public_key: ed25519.Ed25519PublicKey | None = None
) -> str:
    '''
    Serialise a Public Key (eg PEM format)

    Args:
        public_key (ed25519.Ed25519PrivateKey): The public key to serialise

    Returns:
        str: The serialised key (blank if failed)

    Raises:
        AssertionError:
            when a public key is not supplied
    '''
    assert isinstance(public_key, ed25519.Ed25519PublicKey), \
            "Private key must be of type Ed25519PublicKey" 

    # Serialise the key
    _serial_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        # Try to decode the data (eg just a string)
        return _serial_key.decode(ENCODE_METHOD)
    except UnicodeDecodeError:
        return ""


#
# deserialise_private_key
#
def deserialise_private_key(
        key_pem: str | bytes = b""
) -> ed25519.Ed25519PrivateKey | None:
    '''
    Deserialise a Private Key (eg PEM format back into Ed25519PrivateKey class)

    Args:
        key_pem (str | bytes): The private key to deserialise

    Returns:
        ed25519.Ed25519PrivateKey | None: The private key (none if Failed)

    Raises:
        None
    '''
    if not key_pem: return None

    # Make sure the key_pem is in bytes
    if isinstance(key_pem, str):
        try:
            key_pem = key_pem.encode(ENCODE_METHOD)
        except UnicodeEncodeError:
            # key_pem is most likely invalid
            return None
 
    if not isinstance(key_pem, bytes):
        # key_pem is invalid
        return None

    # Deserialise the key
    _key = load_pem_private_key(key_pem, password=None)

    # Make sure the key is the correct type
    if not isinstance(_key, ed25519.Ed25519PrivateKey):
        return None
    
    return _key


#
# deserialise_public_key
#
def deserialise_public_key(
        key_pem: str | bytes = b""
) -> ed25519.Ed25519PublicKey | None:
    '''
    Deserialise a Public Key (eg PEM format back into Ed25519PublicKey class)

    Args:
        key_pem (str): The public key to deserialise

    Returns:
        ed25519.Ed25519PublicKey | None: The public key (none if Failed)

    Raises:
        None
    '''
    if not key_pem: return None

    # Make sure the key_pem is in bytes
    if isinstance(key_pem, str):
        try:
            key_pem = key_pem.encode(ENCODE_METHOD)
        except UnicodeEncodeError:
            # key_pem is most likely invalid
            return None
 
    if not isinstance(key_pem, bytes):
        # key_pem is invalid
        return None

    # Deserialise the key
    _key = load_pem_public_key(key_pem)

    # Make sure the key is the correct type
    if not isinstance(_key, ed25519.Ed25519PublicKey):
        return None
    
    return _key


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
