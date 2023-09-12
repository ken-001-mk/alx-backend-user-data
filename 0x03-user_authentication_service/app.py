#!/usr/bin/env python3

from flask import Flask, jsonify, request, abort, redirect
from auth import Auth

AUTH = Auth()

app = Flask(__name__)

@app.route('/', strict_salshes=False)
def hello_world() -> str:
    """Method that returns a JSON payload
    """
    return jsonify({"message": "Bienvenue"}), 200

@app.route('/users', methods=['POST'], strict_slashes=False)
def users() -> str:
    """Method that registers the user
    """
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"}), 200
    except ValueError:
        return jsonify({"message": "email already registered"}), 400
    
@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login() -> str:
    """Method that creates a session for the user
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = jsonify({"email": email, "message": "logged in"})
        response.set_cookie('session_id', session_id)
        return response
    else:
        abort(401)

@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout() -> None:
    """Method that deletes the user session / logout
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        AUTH.destroy_session(user.id)
        return redirect('/')
    else:
        abort(403)

@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile() -> str:
    """Method that finds the user corresponding to the session ID
    """
    session_id = request.cookies.get('session_id')
    user = AUTH.get_user_from_session_id(session_id)
    if user:
        return jsonify({"email": user.email}), 200
    else:
        abort(403)

@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token() -> str:
    """Method that generates a token and responds with a JSON payload
    """
    email = request.form.get('email')
    try:
        reset_token = AUTH.get_reset_password_token(email)
        return jsonify({"email": email, "reset_token": reset_token}), 200
    except ValueError:
        abort(403)

@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password() -> str:
    """Method that updates the user password and responds with a JSON payload
    """
    email = request.form.get('email')
    reset_token = request.form.get('reset_token')
    new_password = request.form.get('new_password')
    try:
        AUTH.update_password(reset_token, new_password)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        abort(403)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")