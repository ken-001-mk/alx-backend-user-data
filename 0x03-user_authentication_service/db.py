#!/usr/bin/env python3
"""DB module
"""
import logging
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError
from user import Base, User

logging.disable(logging.WARNING)

Base = declarative_base()
class DB:
  """DB class
  """

  def __init__(self) -> None:
    """Initialize a new DB instance
    """
    self._engine = create_engine("sqlite:///a.db", echo=True)
    Base.metadata.drop_all(self._engine)
    Base.metadata.create_all(self._engine)
    self.__session = None

  @property
  def _session(self) -> Session:
    """Memoized session object
    """
    if self.__session is None:
      DBSession = sessionmaker(bind=self._engine)
      self.__session = DBSession()
    return self.__session
  
  def add_user(self, email: str, hashed_password: str) -> User:
    """Method that saves a new user to the database
    """
    new_user = User(email=email, hashed_password=hashed_password)
    self._session.add(new_user)
    self._session.commit()
    return new_user
  
  def find_user_by(self, **kwargs) -> User:
    """Method that returns the first row found in the users table
    as filtered by the methods input arguments
    """
    if not kwargs:
      raise InvalidRequestError
    user = self._session.query(User).filter_by(**kwargs).first()
    if not user:
      raise NoResultFound
    return user
  
  def update_user(self, user_id: int, **kwargs) -> None:
    """Method that takes as argument a required user_id integer
    and arbitrary keyword arguments, and returns None
    """
    user = self.find_user_by(id=user_id)
    for key, value in kwargs.items():
      if key not in user.__dict__:
        raise ValueError
      setattr(user, key, value)
    self._session.commit()
    return None