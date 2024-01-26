#!/usr/bin/env python3
"""
Making a model named user
"""
from sqlalchemy import Column, String, Integer
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class User(Base):
    """A class representing a user in the system

    Attributes:
        __tablename__ (str): The name of the table in the database
        id (int): Unique identifier of user.
        email (str): Email address of user.
        hashed_password (str): Hashed password of user.
        session_id (str): Session ID of user, used to maintain user sessions.
        reset_token (str): Reset token of user for password resets.
    """
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True)
    email = Column(String(250), nullable=False)
    hashed_password = Column(String(250), nullable=False)
    session_id = Column(String(250), nullable=True)
    reset_token = Column(String(250), nullable=True)
