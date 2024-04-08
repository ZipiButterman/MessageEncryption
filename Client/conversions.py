from base64 import b64decode
import base64
import json



def dict_to_bytes(value: dict) -> bytes:
    return json.dumps(value).encode('utf-8')


def byte_to_dict(value):
    return byte_to_str(json.loads(value))


def byte_to_int(value):
    return int.from_bytes(value, byteorder='little')


def int_to_byte(value, length):
    return value.to_bytes(length, byteorder='little')


def str_to_byte(value):
    return bytes(value, 'utf-8')


def byte_to_str(value):
    return value.decode('utf-8')


def byte_to_base64(value: bytes) -> str:
    return byte_to_str(base64.b64encode(value))


def base64_to_byte(value):
    return base64.b64decode(value)


