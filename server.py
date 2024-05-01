import datetime
import os
import time
import uuid
from functools import wraps

from pytz import timezone
from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify, send_from_directory
from pymongo import MongoClient
import bcrypt
from werkzeug.utils import secure_filename
import misc
import secrets
import imghdr
import hashlib
from io import BytesIO
from flask_socketio import SocketIO, emit
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = "/app/uploads"

ip_addresses_and_requests = {}
blacklisted_IPS = {}

REQUESTS_LIMIT = 50
BLOCKING_LENGTH = 30


def ip_status(IP_addr):
    if IP_addr in blacklisted_IPS:
        if time.time() - blacklisted_IPS[IP_addr] > BLOCKING_LENGTH:
            del blacklisted_IPS[IP_addr]
            ip_addresses_and_requests[IP_addr] = 0
            return False
        else:
            return True
    return False


def check_ip(IP):
    if ip_status(IP):
        return "429 ERROR! You have sent too many requests in a short period of time!", 429

    if IP in ip_addresses_and_requests:
        ip_addresses_and_requests[IP] += 1
    else:
        ip_addresses_and_requests[IP] = 1

    if ip_addresses_and_requests[IP] > REQUESTS_LIMIT:
        blacklisted_IPS[IP] = time.time()
        return "429 ERROR! You have sent too many requests in a short period of time!", 429


socket = SocketIO(app)
# https://apscheduler.readthedocs.io/en/3.x/
scheduler = BackgroundScheduler()
scheduler.start()

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]
user_collection = db['users']
post_collection = db['posts']
chat_id = db['count']
scheduled_posts = db["scheduled_posts"]


@app.after_request
def header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)


@app.route('/')
def index():
    ip = request.remote_addr
    ip_check_msg = check_ip(ip)

    if ip_check_msg:
        return ip_check_msg

    user_token = request.cookies.get('user_token')
    if user_token:
        user = user_collection.find_one({'authentication_token': hashlib.sha256(user_token.encode()).hexdigest()})
        if user:
            xsrf_token = user['xsrf_token']
            return render_template('forum.html', xsrf=xsrf_token, username=user.get('username')), 302
    return render_template('login.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    ip = request.remote_addr
    ip_check_msg = check_ip(ip)

    if ip_check_msg:
        return ip_check_msg

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
                forum_template = render_template('forum.html', xsrf=xsrf_token, username=user.get('username'))
                loginResponse = make_response(forum_template)
                loginResponse.set_cookie("user_token", userToken, httponly=True)
                loginResponse.status_code = 302
                loginResponse.headers['Location'] = url_for('index')
                return loginResponse
            else:
                return "Invalid password", 401
        else:
            return "Username does not exist", 404
    if request.method == 'GET':
        response = make_response(render_template('login.html'))
        response.status_code = 302
        return response


@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = request.remote_addr
    ip_check_msg = check_ip(ip)

    if ip_check_msg:
        return ip_check_msg
    user_token = request.cookies.get('user_token')
    if user_token and user_token != '':
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
        response = make_response(render_template('login.html'))
        response.headers['Location'] = url_for('login')
        response.status_code = 302
        return response
    if request.method == "GET":
        response = make_response(render_template('register.html'))
        response.status_code = 302
        return response


@app.route('/logout', methods=['POST'])
def logout():
    user_token = request.cookies.get('user_token')
    if user_token:
        user_collection.update_one({"authentication_token": hashlib.sha256(user_token.encode()).hexdigest()},
                                   {"$unset": {"authentication_token": "", "xsrf_token": ""}})
        response = make_response(render_template('login.html'))
        response.set_cookie('user_token', '', expires=0, httponly=True)
        response.headers['Location'] = url_for('login')
        response.status_code = 302
        return response


@socket.on("post_data")
def handle_post_request(data):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]

    file_ext = imghdr.what(None, h=image_bytes)
    if not file_ext:
        file_ext = "jpg"

    # https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
    if image_bytes:
        image_file = BytesIO(image_bytes)
        image_file.filename = "image." + file_ext
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
            'image_path': image_path,
            'scheduled_post': False,
            'created_when': datetime.now()
        }
        post_collection.insert_one(myPost)

        emit('create_post_event')


@socket.on("like_post")
def like_post(data):
    post_id = data["postId"]
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

    new_like_count = post.get('likes', 0) + 1
    post_collection.update_one({'id': post_id},
                               {'$set': {'likes': new_like_count}, '$push': {'liked_by': user["username"]}})

    socket.emit('update_like_count', {'postId': post_id, 'likeCount': new_like_count})

    return jsonify({"message": "Like count updated successfully"}), 200


@socket.on('forum_update_request')
def handle_forum_update_request():
    if 'user_token' in request.cookies:
        userToken = request.cookies['user_token'].encode('utf-8')
        hashedToken = hashlib.sha256(userToken).hexdigest()
        user = user_collection.find_one({"authentication_token": hashedToken})
        if user:
            username = user['username']
            post_history = list(post_collection.find({}, {'_id': 0}))
            scheduled_posts_data = list(scheduled_posts.find({'username': username}, {'_id': 0}))
            total_posts = scheduled_posts_data + post_history
            total_posts = sorted(total_posts, key=lambda x: x.get('created_when', datetime.min))

            for post in total_posts:
                post.pop('created_when', None)
                if post.get("image_path"):
                    post["image_path"] = url_for("uploaded_file", filename=post["image_path"][len("/app/uploads/"):])

            emit("update_forum", total_posts)
        else:
            return "Forbidden", 403


def schedule_post_data(data, userToken, gen_id):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]

    file_ext = imghdr.what(None, h=image_bytes)
    if not file_ext:
        file_ext = "jpg"

    # https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
    if image_bytes:
        image_file = BytesIO(image_bytes)
        image_file.filename = "image." + file_ext
        filename = secure_filename(image_file.filename)
        filename = str(uuid.uuid4()) + "-_-_-_-" + filename
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(image_path, 'wb') as image:
            image.write(image_bytes)
    else:
        image_path = None

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
        'id': gen_id,
        'likes': 0,
        'image_path': image_path,
        'scheduled_post': True,
        'created_when': datetime.now()
    }
    post_collection.insert_one(myPost)

    scheduled_posts.delete_one({'id': gen_id})


def show_user_scheduled_posts_before_posting(data, gen_id):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]

    # Authenticate
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

    file_ext = imghdr.what(None, h=image_bytes)
    if not file_ext:
        file_ext = "jpg"

    # https://flask.palletsprojects.com/en/2.3.x/patterns/fileuploads/
    if image_bytes:
        image_file = BytesIO(image_bytes)
        image_file.filename = "image." + file_ext
        filename = secure_filename(image_file.filename)
        filename = str(uuid.uuid4()) + "-_-_-_-" + filename
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(image_path, 'wb') as image:
            image.write(image_bytes)
    else:
        image_path = None

    myPost = {
        'title': title.replace('&', "&amp;").replace('<', '&lt;').replace('>', '&gt;'),
        'description': description.replace('&', "&amp;").replace('<', '&lt;').replace('>', '&gt;'),
        'username': username,
        'id': gen_id,
        'likes': 0,
        'image_path': image_path,
        'scheduled_post': True,
        'created_when': datetime.now()
    }

    scheduled_posts.insert_one(myPost)


@socket.on("schedule_post")
def schedule_post(data):
    schedule_time = data["scheduleTime"]
    schedule_time = datetime.strptime(schedule_time, "%Y-%m-%dT%H:%M")
    EST_timezone = timezone('US/Eastern')
    schedule_time = EST_timezone.localize(schedule_time)

    post_data = data["formData"]
    if 'user_token' in request.cookies:
        gen_id = str(uuid.uuid4())
        userToken = request.cookies.get('user_token', '').encode('utf-8')
        scheduler.add_job(schedule_post_data, "date", run_date=schedule_time, args=[post_data, userToken, gen_id])
        show_user_scheduled_posts_before_posting(post_data, gen_id)


if __name__ == "__main__":
    socket.run(app, host='0.0.0.0', port=8080)
