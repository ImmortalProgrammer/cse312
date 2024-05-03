import time
ip_addresses_and_requests = {}
blacklisted_IPS = {}


REQUESTS_LIMIT = 50
BLOCKING_LENGTH = 30


def ip_status(ip_addr):
    if ip_addr in blacklisted_IPS:
        if time.time() - blacklisted_IPS[ip_addr] > BLOCKING_LENGTH:
            del blacklisted_IPS[ip_addr]
            ip_addresses_and_requests[ip_addr] = 0
            return False
        else:
            return True
    return False


def check_ip(ip):
    if ip_status(ip):
        return "429 ERROR! You have sent too many requests in a short period of time!", 429

    if ip in ip_addresses_and_requests:
        ip_addresses_and_requests[ip] += 1
    else:
        ip_addresses_and_requests[ip] = 1

    if ip_addresses_and_requests[ip] > REQUESTS_LIMIT:
        blacklisted_IPS[ip] = time.time()
        return "429 ERROR! You have sent too many requests in a short period of time!", 429
