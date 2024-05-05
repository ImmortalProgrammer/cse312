import time

ip_addresses_and_requests = {}
blacklisted_IPs = {}

REQUESTS_LIMIT = 50
SECONDS_UNTIL_BLOCK = 10
BLOCKING_LENGTH = 30


def ip_status(ip_addr):
    if ip_addr in blacklisted_IPs:
        if time.time() - blacklisted_IPs[ip_addr] > BLOCKING_LENGTH:
            del blacklisted_IPs[ip_addr]
            ip_addresses_and_requests[ip_addr] = []
            return False
        else:
            return True
    return False


def check_ip(ip):
    if ip_status(ip):
        return "429 ERROR! You have been blocked due to sending too many requests in a short period of time.", 429

    current_time = time.time()
    if ip in ip_addresses_and_requests:
        ip_addresses_and_requests[ip] = [timestamp for timestamp in ip_addresses_and_requests[ip] if current_time - timestamp <= SECONDS_UNTIL_BLOCK]
        ip_addresses_and_requests[ip].append(current_time)
    else:
        ip_addresses_and_requests[ip] = [current_time]


    if len(ip_addresses_and_requests[ip]) > REQUESTS_LIMIT:
        blacklisted_IPs[ip] = current_time
        return "429 ERROR! You have sent too many requests in a short period of time. Please try again later.", 429
