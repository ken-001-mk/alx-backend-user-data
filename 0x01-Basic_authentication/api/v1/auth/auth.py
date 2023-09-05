#!/usr/bin/env python3

"""API authentication"""

from flask import request
from typing import List, TypeVar
import fnmatch

class auth:
    """Authentication class"""
    def require_auth(self, path: str,
                     excluded_paths: List[str]) -> bool:
        """ Method to check if auth is required.
        """
        if path is None:
            return True

        if excluded_paths is None or not excluded_paths:
            return True

        for excluded_path in excluded_paths:
            if fnmatch.fnmatch(path, excluded_path):
                return False

        return True

    def authorization_header(self, request=None) -> str:
        """ Method to get authorization header.
        """
        if request is not None:
            return request.headers.get('Authorization', None)
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Method to get user from request.
        """
        return None
    
    def require_auth(self, path, excluded_paths):
        """Check if the path matches any of the excluded paths
        """
        for excluded_path in excluded_paths:
            if excluded_path.endswith("*"):
                """If the excluded path ends with "*", check if
                it's a prefix of the path
                """
                if path.startswith(excluded_path[:-1]):
                    return False
            elif path == excluded_path:
                return False
        return True