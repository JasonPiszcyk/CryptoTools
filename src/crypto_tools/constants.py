#!/usr/bin/env python3
'''
Constants

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

# Local app modules

# Imports for python variable type hints
from typing import Any, Literal


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


#
# Global Variables
#


###########################################################################
#
# Module
#
###########################################################################



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

