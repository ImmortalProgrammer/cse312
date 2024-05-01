import re
import time

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
