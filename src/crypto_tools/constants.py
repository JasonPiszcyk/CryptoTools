#!/usr/bin/env python3
'''
* constants.py
*
* Copyright (c) 2023 Iocane Pty Ltd
*
* @author: Jason Piszcyk
* 
* Constants used within Iocane StackStorm packs
*
'''
from typing import Literal

# Unicode encoding Method
ENCODE_METHOD = "utf-8"

# Size of SALT for password/key derived encryption
SALT_SIZE = 16

SECURITY_LEVELS = Literal["low", "medium", "high"]

# Scrypt parameters when deriving key from password
SCRYPT_LENGTH = 32
SCRYPT_N_LOW = 2**14
SCRYPT_N_MEDIUM = 2**17
SCRYPT_N_HIGH = 2**20
SCRYPT_R = 8
SCRYPT_P = 1
