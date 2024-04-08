import os
import Crypto.Random
import struct
import json
import selectors
import base64
import socket
from Crypto.Cipher import AES
from base64 import b64decode
from Crypto.Util import Padding
from datetime import datetime
from const_numbers import *
from help_functions import *
from request import *
from conversions import *

sel = selectors.DefaultSelector()
aes_key_dict = {}

def accept(sock, mask):
    conn, addr = sock.accept()
    print('accepted. from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)


def read(conn, mask):
    byte_mes = conn.recv(HEADER_SIZE)
    header = get_header(conn, sel, byte_mes)
    if not header:
        return
    client_id = header.__getitem__(0)
    version = byte_to_int(header.__getitem__(1))
    code = byte_to_int(header.__getitem__(2))
    payload_size = byte_to_int(header.__getitem__(3))
    byte_pay = conn.recv(payload_size)
    if code == SEND_SYMMETRIC_KEY_REQUEST:
        payload = struct.unpack('193s240s', byte_pay)
        authenticator = json.loads(payload.__getitem__(0))
        ticket = json.loads(payload.__getitem__(1))
        ticket_iv = base64_to_byte(ticket['Ticket IV'])
        aes_key = base64_to_byte(ticket['AES Key'])
        key = read_msg_file()
        decrypted_aes = decrypt(str_to_byte(key), ticket_iv, aes_key)
        aes_key_dict[client_id] = decrypted_aes
        send_symmetric_key_request(conn, code)
    elif code == SEND_MES_REQUEST:
        mes_size = payload_size - MESSAGE_SIZE - IV_SIZE
        payload = struct.unpack(f'{MESSAGE_SIZE}s{IV_SIZE}s{mes_size}s', byte_pay)
        mes_iv = payload.__getitem__(1)
        enc_mes = payload.__getitem__(2)
        print(f'client: {client_id.hex()}, message before decryption is: {enc_mes}')
        message = byte_to_str(decrypt(aes_key_dict[client_id], mes_iv, enc_mes))
        send_message_request(conn, client_id, enc_mes, message)


if __name__ == "__main__":
    try:
        port_number = start()
        sock = socket.socket()
        sock.bind(('', int("".join(port_number))))
        sock.listen(100)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, accept)
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
    except Exception as e:
        print('Socket closed suddenly. exit.', e)
    #finally:
    #    sock.close()
