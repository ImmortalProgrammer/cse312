from flask import Flask, render_template, request

app = Flask(__name__)


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
    return 'Register'


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=8080)