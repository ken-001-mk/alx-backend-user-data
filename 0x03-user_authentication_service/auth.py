#!/usr/bin/env python3

import bcrypt
from typing import Union
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound
import uuid
import logging

logging.disable(logging.WARNING)


def hash_password(self, password: str) -> str:
    """Method that takes in a password string arguments and returns bytes
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

def generate_uuid(self) -> str:
    """Method that returns a string representation of a new UUID
    """
    new_uuid = uuid.uuid4()
    return str(new_uuid)
class Auth:
  """Auth class to interact with the authentication database.
  """

  def __init__(self):
    self._db = DB()

  
  def register_user(self, email: str, password: str) -> User:
    """Method that takes mandatory email and password string arguments
    and returns a User object
    """
    try:
      self._db.find_user_by(email=email)
      raise ValueError(f'User {email} already exists')
    except NoResultFound:
      return self._db.add_user(email, self.hash_password(password))
  
  def valid_login(self, email: str, password: str) -> bool:
    """Method that takes mandatory email and password string arguments
    and returns a boolean
    """
    try:
      user = self._db.find_user_by(email=email)
      return bcrypt.checkpw(password.encode(), user.hashed_password)
    except NoResultFound:
      return False
  
  
  
  def create_session(self, email: str) -> str:
    """Method that takes an email string argument and returns
    the session ID as a string
    """
    try:
      user = self._db.find_user_by(email=email)
      session_id = self.generate_uuid()
      self._db.update_user(user.id, session_id=session_id)
      return session_id
    except NoResultFound:
      return None
  
  def get_user_from_session_id(self, session_id: str) -> Union[str, None]:
    """Method that takes a single session_id string argument
    and returns the corresponding User or None
    """
    if session_id is None:
      return None
    try:
      return self._db.find_user_by(session_id=session_id)
    except NoResultFound:
      return None
  
  def destroy_session(self, user_id: int) -> None:
    """Method that takes a single user_id integer argument
    and returns None
    """
    try:
      self._db.update_user(user_id, session_id=None)
    except ValueError:
      return None
  
  def get_reset_password_token(self, email: str) -> str:
    """Method that takes an email string argument and returns
    the reset token as a string
    """
    try:
      user = self._db.find_user_by(email=email)
      reset_token = self.generate_uuid()
      self._db.update_user(user.id, reset_token=reset_token)
      return reset_token
    except NoResultFound:
      raise ValueError
  
  def update_password(self, reset_token: str, password: str) -> None:
    """Method that takes reset token string argument and a password string
    argument and returns None
    """
    try:
      user = self._db.find_user_by(reset_token=reset_token)
      hashed_password = self.hash_password(password)
      self._db.update_user(user.id, hashed_password=hashed_password,
                            reset_token=None)
      return None
    except NoResultFound:
      raise ValueError