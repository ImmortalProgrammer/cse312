from flask import Flask, render_template, request
from pymongo import MongoClient
import bcrypt

import misc

app = Flask(__name__)

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
user_collection = db['users']

@app.after_request
def header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/')
def index():
    return render_template('login.html')


@app.route('/login', methods=['POST'])
def login():
    return 'Login'

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']

        if password != password_confirm:
            return 'Two Entered Passwords not the same', 400

        if user_collection.find_one({'username': username}):
            return 'Username already exists', 400

        if not misc.is_valid_password(password):
            return "Password must be 8 characters long, one uppercase letter, one lowercase letter, one digit, " \
                   "and one special character", 400

        salt = bcrypt.gensalt()

        hashed_pwd = bcrypt.hashpw(password.encode(), salt)

        user_collection.insert_one({'username': username, 'password': hashed_pwd, 'salt': salt})

        return render_template('login.html')


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)
