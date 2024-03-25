from flask import Flask, render_template, request, make_response, redirect, url_for
from pymongo import MongoClient
import bcrypt

import misc
import secrets
import hashlib

app = Flask(__name__)

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
user_collection = db['users']
post_collection = db['posts']


@app.after_request
def header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/')
def index():
    user_token = request.cookies.get('user_token')
    if user_token:
        user = user_collection.find_one({'authentication_token': hashlib.sha256(user_token.encode()).hexdigest()})
        if user:
            return render_template('forum.html')
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    user_token = request.cookies.get('user_token')
    if user_token:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = user_collection.find_one({'username': username})

        if user:
            if bcrypt.checkpw(password.encode(), user['password']):
                userToken = secrets.token_hex(15)
                hashedToken = (hashlib.sha256(userToken.encode())).hexdigest()
                user_collection.update_one({"username": username}, {"$set": {"authentication_token": hashedToken}})
                loginResponse = make_response(render_template('forum.html'), 302)
                loginResponse.set_cookie("user_token", userToken, httponly=True)

                return loginResponse
            else:
                return "Invalid password", 401
        else:
            return "Username does not exist", 404
    if request.method == 'GET':
        return render_template('login.html')
        

@app.route('/register', methods=['GET', 'POST'])
def register():
    user_token = request.cookies.get('user_token')
    if user_token:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        password_confirm = request.form['confirm-password']

        if password != password_confirm:
            return 'Two Entered Passwords not the same', 400

        if user_collection.find_one({'username': username}):
            return 'Username already exists', 400

        if not misc.is_valid_password(password):
            return "Password must be 8 characters long, one uppercase letter, one lowercase letter, one digit, " \
                   "and one special character", 400

        salt = bcrypt.gensalt()

        hashed_pwd = bcrypt.hashpw(password.encode(), salt)

        user_collection.insert_one({'username': username, 'password': hashed_pwd, 'email': email})

        return render_template('login.html')
    else:
        return render_template('register.html')


@app.route('/logout', methods=['POST'])
def logout():
    user_token = request.cookies.get('user_token')
    if user_token:
        user_collection.update_one({"authentication_token": hashlib.sha256(user_token.encode()).hexdigest()}, {"$unset": {"authentication_token": ""}})
        response = make_response(render_template('login.html'), 302)
        response.set_cookie('user_token', '', expires=0, httponly=True)
        return response


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
