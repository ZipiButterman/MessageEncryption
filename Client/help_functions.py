from const_numbers import *
from conversions import *
from datetime import datetime
import os
import Crypto.Random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import base64
import time
import json
import socket



def decrypt(key: bytes, iv: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv) # create key
    decrypted_value = cipher.decrypt(value) # decrypt value
    try:
        unpad_value = unpad(decrypted_value, AES.block_size)
        return unpad_value
    except Exception as e:
        print('Password is wrong!')
        exit(1)


def encrypt(key: bytes, iv: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)  # create key
    pad_value = pad(value, AES.block_size) # pad value
    return cipher.encrypt(pad_value)


def generate_rand_bytes(size: int) -> bytes:
    return Crypto.Random.get_random_bytes(size)


def check_code(code: int):
    if code == GENERAL_ERROR:
        print('Got Error Message.')
        exit(1)


def save_id(client_id: bytes):
    f = open('me.info', 'a')
    f.write(client_id.hex())
    f.close()


def create_authenticator_dict(decrypted_aes: bytes, client_id: bytes) -> bytes:
    authenticator_iv = generate_rand_bytes(IV_SIZE)
    encrypted_version = encrypt(decrypted_aes, authenticator_iv, int_to_byte(VERSION, VERSION_SIZE))
    encrypted_id = encrypt(decrypted_aes, authenticator_iv, client_id)
    timestamp = time.time()
    encrypted_time = encrypt(decrypted_aes, authenticator_iv, int_to_byte(int(timestamp), TIMESTAMP_SIZE))
    authenticator_dict = {'Authenticator IV': byte_to_base64(authenticator_iv),
                          'Version': byte_to_base64(encrypted_version),
                          'Client ID': byte_to_base64(encrypted_id),
                          'Creation time': byte_to_base64(encrypted_time)}
    return dict_to_bytes(authenticator_dict)


def is_me_file_exists(client_socket) -> (bool, str, str, bytes):
    flag = False
    try:
        f = open('me.info')
        name = f.readline()
        name = name.strip('\n')
        client_id = bytes.fromhex(f.readline())
        password = input('Insert your password: ')
        print(f'Hello {name}')
        f.close()
        flag = True
    except:
        name = input('You are registering for the first time.\nInsert name: ')
        password = input('Create new password: ')
        client_id = 0
        f = open('me.info', 'w')
        f.write(f'{name}\n')
        f.close()
    return flag, name, password, client_id


def connect(client_socket) -> (str, int):
    srv = open('srv.info')
    server_authentication_ip_port = srv.readline()
    server_message_ip_port = srv.readline()
    srv.close()
    t1 = server_authentication_ip_port.partition(':')
    t2 = server_message_ip_port.partition(':')
    ip = t1.__getitem__(0)
    port = int(t1.__getitem__(2))
    client_socket.connect((ip, port))  # connect to the server
    return t2.__getitem__(0), int(t2.__getitem__(2))
