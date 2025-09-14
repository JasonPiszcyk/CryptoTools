#!/usr/bin/env python3
'''
RSA (Asymmetric Encryption)

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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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
def generate_keys() -> rsa.RSAPrivateKey:
    '''
    Generate an RSA Key Pair

    Args:
        None

    Returns:
        rsa.RSAPrivateKey - The generated key

    Raises:
        None
    '''
    # Generate the keys
    return rsa.generate_private_key(public_exponent=65537, key_size=4096)


###########################################################################
#
# Encryption
#
###########################################################################
#
# encrypt
#
def encrypt(
        data: bytes = b"",
        public_key: rsa.RSAPublicKey | None = None
) -> bytes:
    '''
    Encrypt data

    Args:
        data (bytes): The data to be encrypted
        public_key (rsa.RSAPublicKey): The encryption key

    Returns:
        bytes: The encrypted data

    Raises:
        AssertionError
            when public_key is not in instance of rsa.RSAPublicKey
            when data is not in byte format
    '''
    assert isinstance(public_key, rsa.RSAPublicKey), \
            "Public Key must be an instance of rsa.RSAPublicKey"
    assert isinstance(data, bytes), "data must be in byte format"

    return public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


#
# decrypt
#
def decrypt(
        data: bytes = b"",
        private_key: rsa.RSAPrivateKey | None = None
) -> bytes:
    '''
    Decrypt data

    Args:
        data (bytes): The data to be encrypted
        private_key (rsa.RSAPrivateKey): The private key

    Returns:
        bytes: The decrypted data

    Raises:
        AssertionError
            when private_key is not in instance of rsa.RSAPrivateKey
            when data is not in byte format
        ValueError
            when decryption fails
    '''
    assert isinstance(private_key, rsa.RSAPrivateKey), \
            "Private Key must be an instance of rsa.RSAPrivateKey"
    assert isinstance(data, bytes), "data must be in byte format"
    
    try:
        _decrypted_data = private_key.decrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except ValueError:
        raise ValueError("Decryption Failed")

    return _decrypted_data


###########################################################################
#
# Signing
#
###########################################################################
#
# sign
#
def sign(
        data: bytes = b"",
        private_key: rsa.RSAPrivateKey | None = None
) -> bytes:
    '''
    Sign data using the specified private key

    Args:
        data (bytes): The data to be signed
        private_key (rsa.RSAPrivateKey): The private key used to sign
            the data

    Returns:
        bytes: The signature

    Raises:
        AssertionError:
            When data is not in byte format
            when a private key is not supplied
    '''
    assert isinstance(data, bytes), "Data must be in byte format"
    assert isinstance(private_key, rsa.RSAPrivateKey), \
            "Private key must be an instance of rsa.RSAPrivateKeyy" 

    # Sign the data and return the signature
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


#
# verify
#
def verify(
        data: bytes = b"",
        signature: bytes = b"",
        public_key: rsa.RSAPublicKey | None = None
) -> bool:
    '''
    Verify data using the specified signature and public key

    Args:
        data (bytes): The data to be verified
        signature (bytes): The signature to be used to verify the data
        public_key (rsa.RSAPublicKey): The public key used to verify
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
    assert isinstance(public_key, rsa.RSAPublicKey), \
            "Private key must be of type rsa.RSAPublicKey" 
    if not signature: raise AssertionError("Signature not supplied")

    # Verify the signature
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
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
        private_key: rsa.RSAPrivateKey | None = None
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
    assert isinstance(private_key, rsa.RSAPrivateKey), \
            "Private key must be of type rsa.RSAPrivateKey" 

    # Serialise the key
    _serial_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    try:
        # Try to decode the data (eg just a string)
        return _serial_key.decode()
    except UnicodeDecodeError:
        return ""


#
# serialise_public_key
#
def serialise_public_key(
        public_key: rsa.RSAPublicKey | None = None
) -> str:
    '''
    Serialise a Public Key (eg PEM format)

    Args:
        public_key (rsa.RSAPublicKey): The public key to serialise

    Returns:
        str: The serialised key (blank if failed)

    Raises:
        AssertionError:
            when a public key is not supplied
    '''
    assert isinstance(public_key, rsa.RSAPublicKey), \
            "Private key must be of type rsa.RSAPublicKey" 

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
) -> rsa.RSAPrivateKey | None:
    '''
    Deserialise a Private Key (eg PEM format back into RSAPrivateKey class)

    Args:
        key_pem (str | bytes): The private key to deserialise

    Returns:
        rsa.RSAPrivateKey | None: The private key (none if Failed)

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
    _key = serialization.load_pem_private_key(data=key_pem, password=None)

    # Make sure the key is the correct type
    if not isinstance(_key, rsa.RSAPrivateKey):
        return None

    return _key


#
# deserialise_public_key
#
def deserialise_public_key(
        key_pem: str | bytes = b""
) -> rsa.RSAPublicKey | None:
    '''
    Deserialise a Public Key (eg PEM format back into RSAPublicKey class)

    Args:
        key_pem (str): The public key to deserialise

    Returns:
        rsa.RSAPublicKey | None: The public key (none if Failed)

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
    _key = serialization.load_pem_public_key(data=key_pem)

    # Make sure the key is the correct type
    if not isinstance(_key, rsa.RSAPublicKey):
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
