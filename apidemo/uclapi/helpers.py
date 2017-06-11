from binascii import hexlify

import os


def generate_state():
    client_secret = hexlify(os.urandom(32)).decode()
    return client_secret
