import os
import time
import struct
import socket
import json
import Crypto.Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from datetime import datetime
from clients import Client
from const_numbers import *
from help_functions import *
from main import *


def registration_request(conn: socket, code: int, password: str, name: str):
    for c in client_list:
        if c.name == name:
            print('Error: client almost exists. closing', conn)
            mes = struct_pack(REGISTRATION_NOT_SUCCEED_ANSWER, 0)
            conn.sendall(mes)
            sel.unregister(conn)
            conn.close()
    print(f'A new user name: {name}, requests to register to the system. (request code: {code}).')
    hash_pass = SHA256.new(bytes(password, 'utf-8')).digest()
    c = registration(name, hash_pass)
    client_list.append(c)
    mes = struct_pack(REGISTRATION_SUCCEED_ANSWER, c.cid)
    conn.sendall(mes)
    print(f'Answer sent successfully.')


def symmetric_key_request(conn: socket, client_id: bytes, code: int, nonce: bytes):
    flag_found = False
    print(f'Your request to send a public key (request code: {code}) accepted.')
    for c in client_list:
        if c.cid == client_id:
            flag_found = True
            c = update_client(c, nonce)
            encrypted_key_dict = encrypted_key(c)
            ticket_dict = ticket(c)
            mes = struct_pack(SEND_ENCRYPTED_SYMMETRIC_KEY_ANSWER, encrypted_key_dict, ticket_dict)
            conn.sendall(mes)
            print(f'{c.name}, Encrypted Symmetric Key sent successfully.')
    if not flag_found:
        sel.unregister(conn)
        conn.close()
