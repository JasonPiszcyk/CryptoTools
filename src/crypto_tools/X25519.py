#!/usr/bin/env python3
'''
X25519 Key exchange

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
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
import base64

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
def generate_keys() -> X25519PrivateKey:
    '''
    Generate an X25519 Key Pair

    Args:
        None

    Returns:
        X25519PrivateKey - The generated key

    Raises:
        None
    '''
    # Generate the keys
    return X25519PrivateKey.generate()


#
# derive_key
#
def derive_key(
        local_private_key: X25519PrivateKey | None = None,
        remote_public_key: X25519PublicKey | None = None,
        info: bytes = b"",
        key_length: int = 32
) -> bytes:
    '''
    Derive the shared key

    Args:
        local_private_key (X25519PrivateKey): The private key generated
            locally
        remote_public_key (X25519PrivateKey): The public key shared by the
            remote peer
        info: Additional key info (must be same on both ends)
        key_length (int): Length of the key

    Returns:
        bytes: The derived encryption key

    Raises:
        AssertionError
            when local_private_key is not of type X25519PrivateKey
            when remote_public_key is not of type X25519PublicKey
            when info is not in byte format
            when key_length not an integer or not > 0

    '''
    assert isinstance(local_private_key, X25519PrivateKey), \
         "Local private key must be of type X25519PrivateKey" 
    assert isinstance(remote_public_key, X25519PublicKey), \
         "Remote public key must be of type X25519PublicKey" 
    assert isinstance(info, bytes), "Info must be in byte format"
    assert isinstance(key_length, int), "Key Length must be an integer"
    assert key_length > 0, "Key length must be greater than 0"

    # Derive a key from the combination of public/private keys
    _shared_key = local_private_key.exchange(remote_public_key)
    _derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=None,
        info=info
    ).derive(_shared_key)

    return _derived_key


###########################################################################
#
# Serialisation
#
###########################################################################
#
# serialise_private_key
#
def serialise_private_key(
        private_key: X25519PrivateKey | None = None
) -> str:
    '''
    Serialise a Private Key (eg PEM format)

    Args:
        private_key (X25519PrivateKey): The private key to serialise

    Returns:
        str: The serialised key (blank if failed)

    Raises:
        AssertionError:
            when a private key is not supplied
    '''
    assert isinstance(private_key, X25519PrivateKey), \
            "Private key must be of type X25519PrivateKey" 

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
        public_key: X25519PublicKey | None = None
) -> str:
    '''
    Serialise a Public Key (eg PEM format)

    Args:
        public_key (X25519PublicKey)): The public key to serialise

    Returns:
        str: The serialised key (blank if failed)

    Raises:
        AssertionError:
            when a public key is not supplied
    '''
    assert isinstance(public_key, X25519PublicKey), \
            "Private key must be of type X25519PublicKey" 

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
) -> X25519PrivateKey | None:
    '''
    Deserialise a Private Key (eg PEM format back into X25519PrivateKey class)

    Args:
        key_pem (str | bytes): The private key to deserialise

    Returns:
        X25519PrivateKey | None: The private key (none if Failed)

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
    if not isinstance(_key, X25519PrivateKey):
        return None
    
    return _key


#
# deserialise_public_key
#
def deserialise_public_key(
        key_pem: str | bytes = b""
) -> X25519PublicKey | None:
    '''
    Deserialise a Public Key (eg PEM format back into Ed25519PublicKey class)

    Args:
        key_pem (str): The public key to deserialise

    Returns:
        X25519PublicKey | None: The public key (none if Failed)

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
    if not isinstance(_key, X25519PublicKey):
        return None
    
    return _key


###########################################################################
#
# Format
#
###########################################################################
#
# format_fernet
#
def format_fernet(
        key: bytes = b""
) -> bytes:
    '''
    Format the key for use with Fernet

    Args:
        key (bytes): The key to format

    Returns:
        bytes: The key in a format suitable for Fernet

    Raises:
        AssertionError:
            when key is not in byte format
    '''
    assert isinstance(key, bytes), "key must be in byte format"

    if len(key) < 32: return b""

    return base64.urlsafe_b64encode(key[:32])


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
