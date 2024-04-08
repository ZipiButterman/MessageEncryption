import os
from const_numbers import *
from Crypto.Cipher import AES
from base64 import b64decode
from Crypto.Util.Padding import pad, unpad
import socket
import struct


def start():
    with open('port.info', 'r') as f:
        port_number = f.readlines()
    if port_number == '':
        port_number = DEFAULT_PORT
    return port_number


def get_header(conn: socket, sel, byte_mes: bytes):
    try:
        header = struct.unpack(f'{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s', byte_mes)
        return header
    except:
        print('Finish conversation with current client. close')
        sel.unregister(conn)
        conn.close()
        return


def decrypt(key: bytes, iv: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)  # convert pub_key bytes to key format
    decrypted_value = cipher.decrypt(value)
    return unpad(decrypted_value, AES.block_size)


def read_msg_file() -> str:
    message_server = open('msg.info')
    ip_port = message_server.readline().partition(':')
    server_name = message_server.readline()
    server_key = message_server.readline()
    message_server.close()
    return server_key.strip('\n')

