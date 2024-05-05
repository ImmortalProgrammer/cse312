import imghdr
import os
import re
import time
import uuid
from io import BytesIO
from werkzeug.utils import secure_filename

BLOCKING_LENGTH = 30


def ip_status(blocked_ips, ip_addr):
    if ip_addr in blocked_ips:
        if time.time() - blocked_ips[ip_addr] > BLOCKING_LENGTH:
            del blocked_ips[ip_addr]
            return False
        else:
            return True

    return False


def find_image_path(image_bytes, app):
    file_ext = imghdr.what(None, h=image_bytes)

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

    return image_path


def is_valid_password(password):
    if len(password) < 8:
        return False

    if not re.search("[A-Z]", password):
        return False

    if not re.search("[a-z]", password):
        return False

    if not re.search("[0-9]", password):
        return False

    if not re.search("[!@#$%^&*()-_+=]", password):
        return False

    return True
