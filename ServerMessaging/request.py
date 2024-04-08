import os
import struct
import socket
from const_numbers import *
from help_functions import *
from conversions import *


def send_symmetric_key_request(conn, code):
    fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s'
    mes = struct.pack(fmt, 
                      int_to_byte(VERSION, VERSION_SIZE),
                      int_to_byte(GOT_SYMMERIC_KEY_ANSWER, CODE_SIZE),
                      int_to_byte(0, PAYLOAD_SIZE_IN_BYTES))
    conn.sendall(mes)


def send_message_request(conn, client_id, enc_mes, message):
    print(f'client: {client_id.hex()}, sent: {message}')
    fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s'
    mes = struct.pack(fmt,
                      int_to_byte(VERSION, VERSION_SIZE),
                      int_to_byte(GOT_MESSAGE_ANSWER, CODE_SIZE),
                      int_to_byte(0, PAYLOAD_SIZE_IN_BYTES))
    conn.send(mes)
