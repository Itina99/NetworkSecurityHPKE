# NetworkSecurityHPKE

## Overview

This repository contains a simple implementation of a message encryption and decryption system as an exercise for the Network Security course. The project consists of a sender file (`sender.py`), responsible for encrypting the message and generating JSON files for testing various supported modes, and a receiver file (`receiver.py`), responsible for decrypting messages created by the sender in the form of JSON files. Additionally, there is a folder named `Test Vectors` that contains the JSON files created by the sender during encryption.

## Files

- **sender.py**: This file contains the code for encrypting messages before transmission and generation of the JSON files. In particular it generates 4 files, one for each encription/decription mode.

- **receiver.py**: This file contains the code for decrypting received messages.

- **Test Vectors/**: This directory contains test cases to validate the functionality of the encryption and decryption processes.

## Encryption Library

The encryption and decryption process uses the **pyhpke** library, which implements the Hybrid Public Key Encryption (HPKE) protocol. I chose this library because, in discussions with the expert group, it appeared to be the most comprehensive and straightforward to use. In particular, it supports all the algorithms used for Key Encapsulation Mechanism (KEM), Key Derivation Function (KDS), and Authenticated Encryption with Associated Data (AEAD). Additionally, it covers all four modes of encryption and decryption, namely Base, PSK, AUTH, and PSK AUTH.
### Pyhpke Library Information

- **GitHub Repository**: [pyhpke on GitHub](https://github.com/dajiaji/pyhpke)

- **Documentation**: [Pyhpke Documentation](https://pypi.org/project/pyhpke/)

## Getting Started

1. Clone the repository:

   ```bash
   git clone https://github.com/Itina99/NetworkSecurityHPKE
