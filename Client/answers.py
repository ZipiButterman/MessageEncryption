import struct
from conversions import *
from const_numbers import *
from help_functions import *
import socket
from Crypto.Hash import SHA256



def get_client_id(client_socket) -> bytes:
    byte_mes = client_socket.recv(HEADER_SIZE)  # get client id
    fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s'
    header = struct.unpack(fmt, byte_mes)  # convert version to int
    code = byte_to_int(header.__getitem__(1))
    check_code(code)
    payload_size = byte_to_int(header.__getitem__(2))
    byte_pay = client_socket.recv(payload_size)
    payload = struct.unpack(f'{CLIENT_ID_SIZE}s', byte_pay)
    client_id = payload.__getitem__(0)
    print(f'You got answer from the server. code answer is: {code}, your UUID is: {client_id.hex()}')
    return client_id


def get_last_answer_from_kdc(client_socket, password: str, client_id: bytes) -> (bytes, bytes):
    byte_mes = client_socket.recv(HEADER_SIZE)  # get client id
    fmt = f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s'
    header = struct.unpack(fmt, byte_mes)  # convert version to int
    code = byte_to_int(header.__getitem__(1))
    check_code(code)
    payload_size = byte_to_int(header.__getitem__(2))
    byte_pay = client_socket.recv(payload_size)
    payload = struct.unpack(f'144s240s', byte_pay)
    encrypted_key = json.loads(byte_to_str(payload.__getitem__(0)))
    iv = base64_to_byte(encrypted_key['Encrypted Key IV'])
    encrypted_nonce = base64_to_byte(encrypted_key['Nonce'])
    encrypted_aes = base64_to_byte(encrypted_key['AES Key'])
    ticket = payload.__getitem__(1)
    hash_pass = SHA256.new(str_to_byte(password)).digest()
    decrypt(hash_pass, iv, encrypted_nonce)
    decrypted_aes = decrypt(hash_pass, iv, encrypted_aes)
    print('Message got successfully')
    return ticket, decrypted_aes


def get_first_answer(client_socket):
    byte_mes = client_socket.recv(HEADER_SIZE)  # get client id
    header = struct.unpack(f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s', byte_mes)  # convert version to int
    code = byte_to_int(header.__getitem__(1))
    check_code(code)


def get_mes_answer(client_socket):
    byte_mes = client_socket.recv(HEADER_SIZE)  # get client id
    header = struct.unpack(f'{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s', byte_mes)  # convert version to int
    code = byte_to_int(header.__getitem__(1))
    check_code(code)

