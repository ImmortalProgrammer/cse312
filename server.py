import datetime
import time
import uuid
from pytz import timezone
from flask import Flask, render_template, request, make_response, redirect, url_for, jsonify, send_from_directory
from pymongo import MongoClient
import bcrypt
import misc
import secrets
import hashlib
from flask_socketio import SocketIO, emit
from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

DEPLOYMENT = False

mongo_client = MongoClient("mongo")
db = mongo_client["forum_posts_database_system"]
user_collection = db['users']
post_collection = db['posts']
chat_id = db['count']
scheduled_posts = db["scheduled_posts"]

blocked_ips = {}

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
app.config['UPLOAD_FOLDER'] = "/app/uploads"

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["50 per 10 seconds"],
    storage_uri="memory://",
)

socket = SocketIO(app, max_http_buffer_size=32 * 1024 * 1024)
scheduler = BackgroundScheduler()
scheduler.start()


@app.errorhandler(429)
def handle_error(e):
    ip = request.remote_addr

    if ip not in blocked_ips:
        blocked_ips[ip] = time.time()
        return "429 ERROR! Please stop spamming our website with requests :(", 429

    ip_check = misc.ip_status(blocked_ips, ip)

    if ip_check:
        return "429 ERROR! Please stop spamming our website with requests :(", 429

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
    ip_check = misc.ip_status(blocked_ips, ip)

    if ip_check:
        return "429 ERROR! Please stop spamming our website with requests :(", 429

    user_token = request.cookies.get('user_token')
    if user_token:
        user = user_collection.find_one({'authentication_token': hashlib.sha256(user_token.encode()).hexdigest()})
        if user:
            theme = user.get('theme', 'light')
            xsrf_token = user['xsrf_token']
            return render_template('forum.html', xsrf=xsrf_token, username=user.get('username'), theme=theme), 302
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    ip = request.remote_addr
    ip_check = misc.ip_status(blocked_ips, ip)

    if ip_check:
        return "429 ERROR! Please stop spamming our website with requests :(", 429

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
                forum_template = render_template('forum.html', xsrf=xsrf_token, username=user.get('username'))
                loginResponse = make_response(forum_template)
                loginResponse.set_cookie("user_token", userToken, httponly=True, max_age=3600, secure=DEPLOYMENT)
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


@socket.on('forum_update_request')
def handle_forum_update_request():
    if 'user_token' in request.cookies:
        userToken = request.cookies['user_token'].encode()
        hashedToken = hashlib.sha256(userToken).hexdigest()
        user = user_collection.find_one({"authentication_token": hashedToken})

        if user:
            username = user['username']
            post_history = list(post_collection.find({}, {'_id': 0}))
            scheduled_posts_data = list(scheduled_posts.find({'username': username}, {'_id': 0}))
            total_posts = scheduled_posts_data + post_history
            total_posts = sorted(total_posts, key=lambda x: x.get('created_when', datetime.min), reverse=True)
            for post in total_posts:
                if post.get("image_path"):
                    post["image_path"] = url_for("uploaded_file", filename=post["image_path"][len("/app/uploads/"):])

                if post.get("scheduled_when"):
                    check_whether_scheduled = post.get("scheduled_post")
                    if check_whether_scheduled:
                        est_timezone = timezone('US/Eastern')
                        present_time = datetime.now(est_timezone)
                        scheduled_time = est_timezone.localize(
                            datetime.strptime(post["scheduled_when"], "%Y-%m-%dT%H:%M"))
                        time_remaining = scheduled_time - present_time
                        post[
                            "time_remaining"] = time_remaining.total_seconds() if time_remaining.total_seconds() > 0 else 0
                    post.pop("scheduled_when", None)
                post.pop("created_when", None)

            emit("update_forum", total_posts)
        else:
            return "Forbidden", 403


@socket.on("post_data")
def handle_post_request(data):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]
    image_path = misc.find_image_path(image_bytes, app)

    if chat_id.count_documents({}) == 0:
        chat_id.insert_one({'id': 0})
    idplusone = list(chat_id.find({}, {'_id': 0}))
    idplusone.reverse()
    idplusone[0]["id"] = idplusone[0]["id"] + 1
    chat_id.insert_one({'id': idplusone[0]['id']})

    if 'user_token' in request.cookies:
        userToken = request.cookies['user_token'].encode()
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

        handle_forum_update_request()


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


def process_post_data(data, user_token, gen_id, scheduled_post):
    xsrf_token = data["xsrf"]
    title = data["title"]
    description = data["description"]
    image_bytes = data["image"]

    image_path = misc.find_image_path(image_bytes, app)

    hashedToken = hashlib.sha256(user_token).hexdigest()

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
        'scheduled_post': scheduled_post,
        'created_when': datetime.now(),
        'scheduled_when': data["scheduled_when"]
    }

    if scheduled_post:
        scheduled_posts.insert_one(myPost)
    else:
        post_collection.insert_one(myPost)
        scheduled_post = scheduled_posts.find_one({'id': gen_id})
        if scheduled_post:
            scheduled_posts.delete_one({'id': gen_id})


def schedule_post_data(data, user_token, gen_id):
    process_post_data(data, user_token=user_token, gen_id=gen_id, scheduled_post=False)


def show_user_scheduled_posts_before_posting(data, gen_id):
    process_post_data(data, user_token=request.cookies.get('user_token', '').encode(), gen_id=gen_id,
                      scheduled_post=True)
    handle_forum_update_request()


@socket.on("schedule_post")
def schedule_post(data):
    schedule_time = data["scheduleTime"]

    schedule_time = datetime.strptime(schedule_time, "%Y-%m-%dT%H:%M")
    EST_timezone = timezone('US/Eastern')
    schedule_time = EST_timezone.localize(schedule_time)

    current_time = datetime.now(EST_timezone)
    if schedule_time <= current_time:
        emit("ERROR_IN_POSTING_SCHEDULED_MSG_TIMING_ISSUE")
        return

    if (schedule_time - current_time).total_seconds() > 72 * 3600:
        emit("72_HOUR_RULE")
        return

    post_data = data["formData"]
    post_data["scheduled_when"] = data["scheduleTime"]
    if 'user_token' in request.cookies:
        gen_id = str(uuid.uuid4())
        user_token = request.cookies.get('user_token', '').encode()
        hashedToken = hashlib.sha256(user_token).hexdigest()
        user = user_collection.find_one({"authentication_token": hashedToken})
        try:
            scheduler.add_job(schedule_post_data, "date", run_date=schedule_time,
                              args=[post_data, user_token, gen_id])
            show_user_scheduled_posts_before_posting(post_data, gen_id)
        except Exception as e:
            pass


@limiter.exempt
@app.route('/set_theme', methods=['POST'])
def set_theme():
    theme = request.json.get('theme')
    user_token = request.cookies.get('user_token')
    if user_token:
        user = user_collection.find_one({'authentication_token': hashlib.sha256(user_token.encode()).hexdigest()})
        if user:
            user_collection.update_one({"authentication_token": hashlib.sha256(user_token.encode()).hexdigest()},
                                       {"$set": {"theme": theme}})
            return jsonify({'message': 'Theme updated successfully'}), 200
    return jsonify({'error': 'Unauthorized'}), 401


limiter.init_app(app)

if __name__ == "__main__":
    socket.run(app, host='0.0.0.0', port=8080)
