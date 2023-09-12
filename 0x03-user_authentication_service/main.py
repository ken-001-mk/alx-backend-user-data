#!/usr/bin/env python3

import requests

URL = 'http://localhost:5000'

def register_user(email: str, password: str) -> None:
    """Method that registers the user
    """
    data = {'email': email, 'password': password}
    response = requests.post(f'{URL}/users', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'user created'}

def log_in_wrong_password(email: str, password: str) -> None:
    """Method that tests the login with a wrong password
    """
    data = {'email': email, 'password': password}
    response = requests.post(f'{URL}/sessions', data=data)
    assert response.status_code == 401

def log_in(email: str, password: str) -> str:
    """Method that tests the login
    """
    data = {'email': email, 'password': password}
    response = requests.post(f'{URL}/sessions', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'logged in'}
    return response.cookies.get('session_id')

def profile_unlogged() -> None:
    """Method that tests the profile when the user is not logged in
    """
    response = requests.get(f'{URL}/profile')
    assert response.status_code == 403

def profile_logged(session_id: str) -> None:
    """Method that tests the profile when the user is logged in
    """
    cookies = {'session_id': session_id}
    response = requests.get(f'{URL}/profile', cookies=cookies)
    assert response.status_code == 200
    assert response.json() == {'email': ''}
    assert response.headers['Content-Type'] == 'application/json'

def log_out(session_id: str) -> None:
    """Method that tests the logout
    """
    cookies = {'session_id': session_id}
    response = requests.delete(f'{URL}/sessions', cookies=cookies)
    assert response.status_code == 200
    assert response.headers['Location'] == 'http://localhost:5000/'
    assert response.json() == {}
    assert response.cookies.get('session_id') is None

def reset_password_token(email: str) -> str:
    """Method that tests the reset password token
    """
    cookies = {'session_id': ''}
    data = {'email': email}
    response = requests.post(f'{URL}/reset_password', cookies=cookies, data=data)
    assert response.status_code == 200

def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Method that tests the update password
    """
    data = {'email': email, 'reset_token': reset_token, 'new_password': new_password}
    response = requests.put(f'{URL}/reset_password', data=data)
    assert response.status_code == 200
    assert response.json() == {'email': email, 'message': 'Password updated'}


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)