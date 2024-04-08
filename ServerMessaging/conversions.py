import base64
import json

def byte_to_int(value: bytes) -> int:
    return int.from_bytes(value, byteorder='little')


def int_to_byte(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder='little')


def byte_to_base64(value: bytes) -> str:
    return byte_to_str(base64.b64encode(value))


def base64_to_byte(value: base64) -> bytes:
    return base64.b64decode(value)


def dict_to_bytes(value: dict) -> bytes:
    return json.dumps(value).encode('utf-8')


def byte_to_dict(value: bytes) -> str:
    return byte_to_str(json.loads(value))


def str_to_byte(value: str) -> bytes:
    return bytes(value, 'utf-8')


def byte_to_str(value: bytes) -> str:
    return value.decode('utf-8')

