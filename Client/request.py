from help_functions import *
from conversions import *
import struct
from answers import *
import socket


def send_mes_request(client_socket, client_id: bytes, decrypted_aes: bytes):
    message = input('Insert message to send to the server: ')
    while message != 'bye':
        message_iv = generate_rand_bytes(IV_SIZE)
        encrypt_mes = encrypt(decrypted_aes, message_iv, str_to_byte(message))
        print(f'Your message after encryption is: {encrypt_mes}')
        payload_size = len(encrypt_mes) + len(message_iv) + MESSAGE_SIZE
        struct_fmt = f'{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{MESSAGE_SIZE}s{IV_SIZE}s{len(encrypt_mes)}s'
        mes = struct.pack(struct_fmt,
                          client_id,
                          int_to_byte(VERSION, VERSION_SIZE),
                          int_to_byte(SEND_MES_REQUEST, CODE_SIZE),
                          int_to_byte(payload_size, PAYLOAD_SIZE_IN_BYTES),
                          int_to_byte(len(encrypt_mes), MESSAGE_SIZE),
                          message_iv,
                          encrypt_mes)
        client_socket.send(mes)  # send message
        get_mes_answer(client_socket)
        message = input('Insert message to send to the server: ')
        
        

def regist_to_kdc(name: str, password: str, client_socket):
    name.ljust(NAME_SIZE, '\0')
    password.ljust(PASS_SIZE, '\0')
    payload_size = NAME_SIZE + PASS_SIZE
    struct_fmt = f"{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{NAME_SIZE}s{PASS_SIZE}s"
    mes = struct.pack(struct_fmt,
                      str_to_byte('0000000000000000'),
                      int_to_byte(VERSION, VERSION_SIZE),
                      int_to_byte(REGISTRATION_REQUEST, CODE_SIZE),
                      int_to_byte(payload_size, PAYLOAD_SIZE_IN_BYTES),
                      str_to_byte(name), str_to_byte(password))
    client_socket.send(mes)
    print('Register request sent successfully')
    
    
    
def send_nonce_to_kdc(client_socket, client_id: bytes):
    nonce = generate_rand_bytes(NONCE_SIZE)
    payload_size = len(nonce)
    struct_fmt = f"{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{NONCE_SIZE}s"
    mes = struct.pack(struct_fmt,
                      client_id,
                      int_to_byte(VERSION, VERSION_SIZE),
                      int_to_byte(SYMMETRIC_KEY_REQUEST, CODE_SIZE),
                      int_to_byte(payload_size, PAYLOAD_SIZE_IN_BYTES),
                      nonce)
    client_socket.send(mes)
    print('Nonce sent successfully')


def send_symmetric_key(client_socket, client_id: bytes, ticket: bytes, authenticator_dict_byte: bytes):
    payload_size = len(ticket) + len(authenticator_dict_byte)
    struct_fmt = f"{CLIENT_ID_SIZE}s{VERSION_SIZE}s{CODE_SIZE}s{PAYLOAD_SIZE_IN_BYTES}s{len(authenticator_dict_byte)}s{len(ticket)}s"
    mes = struct.pack(struct_fmt,
                      client_id,
                      int_to_byte(VERSION, VERSION_SIZE),
                      int_to_byte(SEND_SYMMETRIC_KEY_REQUEST, CODE_SIZE),
                      int_to_byte(payload_size, PAYLOAD_SIZE_IN_BYTES),
                      authenticator_dict_byte,
                      ticket)
    client_socket.send(mes)  # send message
    print('Symmetric key sent successfully')


