#!/usr/bin/env python3
'''
Fernet (Symmetric Encryption)

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
# Shared variables, constants, etc

# System Modules
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from typing import get_args

import base64
import secrets

# Local app modules
from crypto_tools.constants import (
    ENCODE_METHOD,
    SALT_SIZE,
    SECURITY_LEVELS,
    SCRYPT_LENGTH,
    SCRYPT_N_LOW,
    SCRYPT_N_MEDIUM,
    SCRYPT_N_HIGH,
    SCRYPT_R,
    SCRYPT_P,
)

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
# generate_key
#
def generate_key() -> bytes:
    '''
    Generate an encryption key

    Args:
        None

    Returns:
        bytes - The generated key

    Raises:
        None
    '''
    return Fernet.generate_key()


#
# derive_key
#
def derive_key(
        salt: bytes = b"",
        password: str = "",
        security: str = "high"
) -> tuple[bytes, bytes]:
    '''
    Derive a key from a password

    Args:
        salt (bytes): The salt used in the derivation of the password
            (or a new one will be generated)
        password (str): The password used to derive the key
        security: Determines the computation time of the key.  Must be one of
            "low", "medium", or "high"

    Returns:
        bytes: The salt
        bytes: The key

    Raises:
        AssertionError
            when key is not in byte format
    '''
    assert isinstance(salt, bytes), "Salt must be in byte format"
    assert isinstance(password, str), "Password must be in string format"

    # Determine the computational cost for the key
    security_options = get_args(SECURITY_LEVELS)
    assert security in security_options, \
            f"'{security}' is not in {security_options}"

    if security == "low":
        _computation_cost = SCRYPT_N_LOW
    elif security == "medium":
        _computation_cost = SCRYPT_N_MEDIUM
    else:
        _computation_cost = SCRYPT_N_HIGH

    if not salt:
        # Generate a salt
        salt = generate_salt()

    # Convert the password to a byte array
    try:
        _pw_bytes = password.encode(ENCODE_METHOD)
    except UnicodeEncodeError:
        # password is most likely invalid
        return b"", b""
 
    if not isinstance(_pw_bytes, bytes):
        # password is invalid
        return b"", b""

    # Derive the key from the password/salt
    _kdf = Scrypt(
        salt=salt,
        length=SCRYPT_LENGTH,
        n=_computation_cost,
        r=SCRYPT_R,
        p=SCRYPT_P
    )
    
    _key = base64.urlsafe_b64encode(_kdf.derive(_pw_bytes))

    return ( salt, _key )


#
# generate_salt
#
def generate_salt() -> bytes:
    '''
    Generate a salt

    Args:
        None

    Returns:
        bytes - The generated salt

    Raises:
        None
    '''
    return secrets.token_bytes(SALT_SIZE)


#
# use_key
#
def use_key(
        key: bytes = b""
) -> Fernet | None:
    '''
    Use a key derived elsewhere

    Args:
        key: A URL-safe base64-encoded 32-byte key

    Returns:
        Fernet | None - A Fernet instance from the key

    Raises:
        AssertionError
            when key is not in byte format
    '''
    assert isinstance(key, bytes), "Key must be in byte format"
    if not key: return None

    return Fernet(key)


###########################################################################
#
# Encryption / Decryption
#
###########################################################################
#
# encrypt
#
def encrypt(
        data: bytes = b"",
        key: bytes = b""
) -> bytes:
    '''
    Encrypt data

    Args:
        data (bytes): The data to be encrypted
        key (bytes): The encryption key

    Returns:
        bytes: The encrypted data

    Raises:
        AssertionError
            when key is not in byte format, or is empty
            when data is not in byte format
    '''
    assert isinstance(key, bytes), "Key must be in byte format"
    assert key, "Encryption key must be supplied"
    assert isinstance(data, bytes), "data must be in byte format"

    _fernet = Fernet(key)

    return _fernet.encrypt(data)


#
# decrypt
#
def decrypt(
        data: bytes = b"",
        key: bytes = b""
):
    '''
    Decrypt data

    Args:
        data (bytes): The data to be decrypted
        key (bytes): The encryption key

    Returns:
        bytes: The decrypted data (raise ValueError on failure)

    Raises:
        AssertionError
            when key is not in byte format, or is empty
            when data is not in byte format
        ValueError
            when decryption fails
    '''
    assert isinstance(key, bytes), "Key must be in byte format"
    assert key, "Encryption key must be supplied"
    assert isinstance(data, bytes), "data must be in byte format"

    _fernet = Fernet(key)
    try:
        _decrypted_data = _fernet.decrypt(data)
    except InvalidToken:
        raise ValueError("Invalid encryption key")

    # Return the decrypted data
    return _decrypted_data


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
