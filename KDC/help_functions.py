import uuid
import time
from datetime import datetime
import Crypto.Random
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from conversions import *
from clients import Client
from answers import *
import selectors
import socket


client_list = []


def start():
    try:
        f = open('clients.txt')
        for client in f:
            first_part = client.partition(':')
            client_id = first_part.__getitem__(0)
            second_part = first_part.__getitem__(2).partition(':')
            name = second_part.__getitem__(0)
            third_part = second_part.__getitem__(2).partition(':')
            pass_hash = third_part.__getitem__(0)
            last_seen = third_part.__getitem__(2).strip('\n')
            c = Client(bytes.fromhex(client_id), name, last_seen, base64.b64decode(pass_hash))
            client_list.append(c)
        f.close()
    except Exception as e:
        return


def read_msg_file() -> str:
    message_server = open('msg.info')
    ip_port = message_server.readline().partition(':')
    server_name = message_server.readline()
    server_key = message_server.readline()
    message_server.close()
    return server_key.strip('\n')


def get_header(conn: socket, sel, byte_mes: bytes):
    try:
        header = struct.unpack(f'{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s', byte_mes)
        return header
    except:
        print('Finish authentication with current client. close')
        sel.unregister(conn)
        conn.close()
        return


def registration(name: str, pass_hash: bytes) -> Client:
    client_id = uuid.uuid4().bytes
    last_seen = str(datetime.now())
    client_info = f'{client_id.hex()}:{name}:{byte_to_base64(pass_hash)}:{last_seen}'
    f = open('clients.txt', 'a+')
    lines = f.readlines()
    f.write('\n')
    f.write(client_info)
    c = Client(client_id, name, last_seen, pass_hash)
    return c


def update_client(client: Client, nonce: bytes) -> Client:
    client.aes = generate_rand_bytes(AES_KEY_SIZE)
    client.nonce = nonce
    return client


def encrypted_key(client: Client) -> bytes:
    encrypted_key_iv = generate_rand_bytes(IV_SIZE)
    encrypted_nonce = encrypt(client.pass_hash, encrypted_key_iv, client.nonce)
    encrypted_client_aes = encrypt(client.pass_hash, encrypted_key_iv, client.aes)
    encrypted_key_dict = create_dict(('Encrypted Key IV', encrypted_key_iv),
                                     ('Nonce', encrypted_nonce),
                                     ('AES Key', encrypted_client_aes))
    return dict_to_bytes(encrypted_key_dict)


def ticket(client: Client) -> bytes:
    ticket_iv = generate_rand_bytes(IV_SIZE)
    timestamp = time.time()
    key = read_msg_file()
    byte_timestamp = int_to_byte(int(timestamp), TIMESTAMP_SIZE)
    encrypted_timestamp = encrypt(str_to_byte(key), ticket_iv, byte_timestamp)
    encrypted_server_aes = encrypt(str_to_byte(key), ticket_iv, client.aes)
    version = int_to_byte(VERSION, VERSION_SIZE)
    ticket_dict = create_dict(('Version', version),
                              ('Client ID', client.cid),
                              ('Creation time', byte_timestamp),
                              ('Ticket IV', ticket_iv),
                              ('AES Key', encrypted_server_aes),
                              ('Expiration time', encrypted_timestamp))
    return dict_to_bytes(ticket_dict)


def generate_rand_bytes(size: int) -> bytes:
    return Crypto.Random.get_random_bytes(size)


def create_dict(*values: tuple) -> dict:
    new_dict = {}
    for value in values:
        t = tuple(value)
        new_dict.update({str(t.__getitem__(0)): byte_to_base64(t.__getitem__(1))})
    return new_dict


def encrypt(key: bytes, iv: bytes, value: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)  # convert pub_key bytes to key format
    pad_value = pad(value, AES.block_size)
    return cipher.encrypt(pad_value)


