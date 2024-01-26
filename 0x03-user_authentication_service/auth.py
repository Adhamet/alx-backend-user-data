#!/usr/bin/env python3
"""Module for authentication"""

import logging
from typing import Union
from uuid import uuid4

import bcrypt
from sqlalchemy.orm.exc import NoResultFound

from db import DB
from user import User

logging.disable(logging.WARNING)


def _hash_password(password: str) -> bytes:
    """Hashes a password and returns bytes.

    Args:
        password (str): The password to be hashed.

    Returns:
        bytes: The hashed password.
    """
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


def _generate_uuid() -> str:
    """Generates a uuid.

    Returns:
        str: string representation of a new UUID.
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with authentication database
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> User:
        """Registers a new user with given email & password

        Args:
            email (str): Email of a new user.
            password (str): Password of a new user.

        Returns:
            User: A user object representing the newly created user.

        Raises:
            ValueError: User with a given email already exists.
        """
        try:
            self._db.find_user_by(email=email)
            raise ValueError(f"User {email} already exists")
        except NoResultFound:
            pass
        hashed_password = _hash_password(password)
        user = self._db.add_user(email, hashed_password)
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """Checks if a user's email and password are valid.

        Args:
            email (str): The email of the user.
            password (str): The password of the user.

        Returns:
            bool: True if the email and password match a registered user,
            False otherwise.
        """
        try:
            user = self._db.find_user_by(email=email)
            if user is not None:
                password_bytes = password.encode('utf-8')
                hashed_password = user.hashed_password
                if bcrypt.checkpw(password_bytes, hashed_password):
                    return True
        except NoResultFound:
            return False
        return False

    def create_session(self, email: str) -> str:
        """Creates a session and returns its ID as string.

        Args:
            email (str): Email of user to create session for.

        Return:
            str: sessions ID
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            return None

        if user is None:
            return None

        session_id = _generate_uuid()
        self._db.update_user(user.id, session_id=session_id)
        return session_id

    def get_user_from_session_id(self, session_id: str) -> Union[User, None]:
        """Retrieve a User object from a session ID

        Args:
            session_id (str): The ID of the session to retrieve the user from.

        Returns:
            Union[User, None]: A user object corresponding to the session ID if
            one exists, otherwise None.
        """
        if session_id is None:
            return None
        try:
            user = self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None
        return user

    def destory_session(self, user_id: int) -> None:
        """Method to destory the session associated with a user

        Args:
            user_id (int): The ID of the user whose session is to be destroyed.

        Returns:
            None
        """
        try:
            self._db.update_user(user_id, session_id=None)
        except ValueError:
            return None
        return None

    def get_reset_password_token(self, email: str) -> str:
        """Generates a password reset token for a user.

        Args:
            email (str): A string representating the email address
            of the user to generate a password reset token for.

        Raises:
            ValueError: If no user with specified email address is found.

        Returns:
            str: A string representing the password reset token generated
            for the user.
        """
        try:
            user = self._db.find_user_by(email=email)
        except NoResultFound:
            user = None

        if user is None:
            raise ValueError()
        reset_token = _generate_uuid()
        self._db.update_user(user.id, reset_token=reset_token)
        return reset_token

    def update_password(self, reset_token: str, password: str) -> None:
        """Updates a user's password using a reset token.

        Args:
            reset_token (str): The reset token associated with the user.
            password (str): The new password to set.

        Raises:
            ValueError: If the reset token is invalid (i.e., not associated
            with a user)..

        Returns:
            None
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
        except NoResultFound:
            raise ValueError("Invalid reset token")
        new_hashed_passwd = _hash_password(password)
        self._db.update_user(
            user.id,
            hashed_password=new_hashed_passwd,
            reset_token=None
        )
