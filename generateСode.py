import struct
import time
import hmac
import base64
from hashlib import sha1
import json

def generate_code(shared_secret: str, timestamp: int = None) -> str:
    if timestamp is None:
        timestamp = int(time.time())
    time_buffer = struct.pack('>Q', timestamp // 30)  # pack as Big endian, uint64
    time_hmac = hmac.new(base64.b64decode(shared_secret), time_buffer, digestmod=sha1).digest()
    begin = ord(time_hmac[19:20]) & 0xf
    full_code = struct.unpack('>I', time_hmac[begin:begin + 4])[0] & 0x7fffffff  # unpack as Big endian uint32
    chars = '23456789BCDFGHJKMNPQRTVWXY'
    code = ''

    for _ in range(5):
        full_code, i = divmod(full_code, len(chars))
        code += chars[i]

    return code

try:
    with open('maFiles', 'r', encoding='utf-8') as f:
        shared_secret = json.load(f)['shared_secret']
        print(generate_code(shared_secret))
except json.decoder.JSONDecodeError:
    print('Error: Wrong data format in maFiles')
except FileNotFoundError:
    print('Error: No such maFiles')
