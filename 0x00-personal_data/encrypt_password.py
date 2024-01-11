#!/usr/bin/env python3
"""
Encrypting Password
"""
import bcrypt


def hash_password(password: str) -> bytes:
    """ Returns a salted, hashed password aka byte string """
    encoded = password.encode()
    hashed = bcrypt.hashpw(encoded, bcrypt.gensalt())

    return hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ Validates the provided password matches the hashed password """
    valid = False
    encoded = password.encode()
    if bcrypt.checkpw(encoded, hash_password):
        valid = True
    return valid
