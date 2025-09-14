# CryptoTools
Copyright (c) 2025 Jason Piszcyk

Tools to be used for cryptographic functions.

<!-- 
Not yet Published to PyPi
[![PyPI version](https://badge.fury.io/py/cryptotools.svg)](https://pypi.org/project/cryptotools/)
[![Build Status](https://github.com/JasonPiszcyk/CryptoTools/actions/workflows/python-app.yml/badge.svg)](https://github.com/JasonPiszcyk/CryptoTools/actions)
 -->

## Overview

**CryptoTools** provides a wrapper to Python cryptographic functions, to implement an opinionated version of verious crpytographic functions

## Features

**CryptoTools** consists of a number of sub-modules, being:
- ed25519
  - An eliptic curve signing algorithm (used to sign/verify data)
- ferrnet
  - A symmetric encryption algortihm (used for encrypting/decrypting data)
- rsa
  - An older assymmetric encryption algortihm (included for compatability)
- X25519
  - A key exchange algorithm
- encrypted_file.fernet
  - An implementation of an encrypted file using Fernet encryption with a password derived key

## Installation

Module has not been published to PyPi yet.  Install via:
```bash
pip install "CryptoTools @ git+https://github.com/JasonPiszcyk/CryptoTools"
```

## Requirements

- Python >= 3.12

## Dependencies

- cryptography

## Usage

```python
import CryptoTools
# Example usage of CryptoTools components
```

## Development

1. Clone the repository:
    ```bash
    git clone https://github.com/JasonPiszcyk/CryptoTools.git
    cd CryptoTools
    ```
2. Install dependencies:
    ```bash
    pip install -e .[dev]
    ```

## Running Tests

```bash
pytest
```

## Contributing

Contributions are welcome! Please submit issues or pull requests via [GitHub Issues](https://github.com/JasonPiszcyk/CryptoTools/issues).

## License

GNU General Public License

## Author

Jason Piszcyk  
[Jason.Piszcyk@gmail.com](mailto:Jason.Piszcyk@gmail.com)

## Links

- [Homepage](https://github.com/JasonPiszcyk/CryptoTools)
- [Bug Tracker](https://github.com/JasonPiszcyk/CryptoTools/issues)
