import struct
from const_numbers import *
from conversions import *


def struct_pack(code: int, *payload: tuple) -> bytes:
    version = int_to_byte(VERSION, VERSION_SIZE)
    byte_code = int_to_byte(code, CODE_SIZE)
    size = 0
    for p in payload:
        size += len(p)
    pay_size = int_to_byte(size, PAYLOAD_SIZE_IN_BYTES)
    if code == REGISTRATION_SUCCEED_ANSWER:
        return registration_succeed_answer(version, byte_code, pay_size, payload)
    elif code == REGISTRATION_NOT_SUCCEED_ANSWER:
        return registration_not_succeed_answer(version, byte_code, pay_size)
    else:
        return send_encrypted_symmetric_key_answer(version, byte_code, pay_size, payload)


def registration_succeed_answer(version: bytes, code: bytes, pay_size: bytes, payload: tuple) -> bytes:
    client_id = payload.__getitem__(0)
    struct_fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{len(client_id)}s'
    return struct.pack(struct_fmt, version, code, pay_size, client_id)


def registration_not_succeed_answer(version: bytes, code: bytes, pay_size: bytes) -> bytes:
    struct_fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s'
    return struct.pack(struct_fmt, version, code, pay_size)


def send_encrypted_symmetric_key_answer(version: bytes, code: bytes, pay_size: bytes, payload: tuple) -> bytes:
    encrypted_key_dict = payload.__getitem__(0)
    ticket_dict = payload.__getitem__(1)
    struct_fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{len(encrypted_key_dict)}s{len(ticket_dict)}s'
    return struct.pack(struct_fmt, version, code, pay_size, encrypted_key_dict, ticket_dict)

