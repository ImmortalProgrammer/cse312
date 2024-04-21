import os
import uuid
import time
import flask
from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify, send_from_directory
from pymongo import MongoClient
import bcrypt
from werkzeug.utils import secure_filename
import misc
import secrets
import hashlib
from io import BytesIO

from flask_socketio import SocketIO, emit

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = "/app/uploads"
socket = SocketIO(app)

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
user_collection = db['users']
post_collection = db['posts']
chat_id = db['count']


@app.after_request
def header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/')
def index():
    user_token = request.cookies.get('user_token')
    if user_token:
        user = user_collection.find_one({'authentication_token': hashlib.sha256(user_token.encode()).hexdigest()})
        if user:
            xsrf_token = user['xsrf_token']
            return render_template('forum.html', xsrf=xsrf_token), 302
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
                xsrf_token = secrets.token_urlsafe(15)
                user_collection.update_one({"username": username},
                                           {"$set": {"authentication_token": hashedToken, "xsrf_token": xsrf_token}})
                loginResponse = make_response(render_template('forum.html', xsrf=xsrf_token), 302)
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
        user_collection.update_one({"authentication_token": hashlib.sha256(user_token.encode()).hexdigest()},
                                   {"$unset": {"authentication_token": "", "xsrf_token": ""}})
        response = make_response(render_template('login.html'), 302)
        response.set_cookie('user_token', '', expires=0, httponly=True)
        return response

@socket.on("post_data")
def handle_post_request(data):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]

    # https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
    if image_bytes:
        image_file = BytesIO(image_bytes)
        image_file.filename = "image.jpg"
        filename = secure_filename(image_file.filename)
        filename = str(uuid.uuid4()) + "-_-_-_-" + filename
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(image_path, 'wb') as image:
            image.write(image_bytes)
    else:
        image_path = None


    if chat_id.count_documents({}) == 0:
        chat_id.insert_one({'id': 0})
    idplusone = list(chat_id.find({}, {'_id': 0}))
    idplusone.reverse()
    idplusone[0]["id"] = idplusone[0]["id"] + 1
    chat_id.insert_one({'id': idplusone[0]['id']})
    usernameFound = ""
    if 'user_token' in request.cookies:
        userToken = request.cookies['user_token'].encode('utf-8')
        hashedToken = hashlib.sha256(userToken).hexdigest()
        user = user_collection.find_one({"authentication_token": hashedToken})
        if user:
            if user['xsrf_token'] == xsrf_token:
                username = user['username']
            else:
                return "Forbidden", 403
        else:
            return "Forbidden", 403
        myPost = {
            'title': title.replace('&', "&amp;").replace('<', '&lt;').replace('>', '&gt;'),
            'description': description.replace('&', "&amp;").replace('<', '&lt;').replace('>', '&gt;'),
            'username': username,
            'id': str(idplusone[0]['id']),
            'likes': 0,
            'image_path': image_path
        }
        post_collection.insert_one(myPost)

        socket.emit('create_post_event')

@app.route('/forum/<post_id>/like', methods=['POST'])
def like_post(post_id):
    post = post_collection.find_one({'id': post_id})
    if not post:
        return jsonify({"error": "Post not found"}), 404

    user_token = request.cookies.get('user_token')
    if not user_token:
        return jsonify({"error": "User not authenticated"}), 401

    user_token_hash = hashlib.sha256(user_token.encode()).hexdigest()
    user = user_collection.find_one({"authentication_token": user_token_hash})
    if not user:
        return jsonify({"error": "User not found"}), 404

    liked_by = post.get("liked_by", [])
    if user["username"] in liked_by:
        return jsonify({"error": "You have already liked this post"}), 400

    post_collection.update_one({'id': post_id}, {'$inc': {'likes': 1}, '$push': {'liked_by': user["username"]}})
    return jsonify({"message": "Like count updated successfully"}), 200

@socket.on('create_post_event')
def handle_new_post(post_data):
    emit('create_post', post_data, broadcast=True)

@socket.on('forum_update_request')
def handle_forum_update_request():
    chat_history = list(post_collection.find({}, {'_id': 0}))
    for post in chat_history:
        if post.get("image_path"):
            post["image_path"] = url_for("uploaded_file", filename=post["image_path"][len("/app/uploads/"):])

    socket.emit("update_forum", chat_history)



if __name__ == "__main__":
    socket.run(app, host='0.0.0.0', port=8080, debug=True)