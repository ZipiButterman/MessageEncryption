import os
import struct
import uuid
import time
from random import randbytes
from Crypto import Random
import base64
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from help_functions import *
from const_numbers import *
import socket
import Crypto
from request import *
from answers import *


if __name__ == "__main__":
    # authentication server
    client_socket = socket.socket()
    ip, port = connect(client_socket) # connect to auth server
    flag, name, password, client_id = is_me_file_exists(client_socket) # check if me.info exists. if not - create one.
    if not flag: # me file didn't exists - need to register from beginning
        regist_to_kdc(name, password, client_socket) #register to auth server
        client_id = get_client_id(client_socket) # get answer from auth - id.
        save_id(client_id) # save id in me.info file
    send_nonce_to_kdc(client_socket, client_id)
    ticket, decrypted_aes = get_last_answer_from_kdc(client_socket, password, client_id)
    authenticator_dict_byte = create_authenticator_dict(decrypted_aes, client_id)
    client_socket.close()  # close the connection
    # message server
    client_socket = socket.socket() 
    client_socket.connect((ip, port))  # connect to the server
    send_symmetric_key(client_socket, client_id, ticket, authenticator_dict_byte) # send authenticator and ticket to message server
    get_first_answer(client_socket)
    send_mes_request(client_socket, client_id, decrypted_aes) # send messages
    client_socket.close()
