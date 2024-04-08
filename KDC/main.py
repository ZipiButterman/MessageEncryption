import selectors
import socket
import struct
from help_functions import *
from const_numbers import *
from request import *

sel = selectors.DefaultSelector()


def accept(sock, mask):
    conn, addr = sock.accept()
    print('accepted. from', addr)
    conn.setblocking(False)
    sel.register(conn, selectors.EVENT_READ, read)


with open('port.info', 'r') as f:
    port_number = f.readlines()
    if port_number == '':
        port_number = DEFAULT_PORT


def read(conn, mask):
    byte_mes = conn.recv(HEADER_SIZE)
    header = get_header(conn, sel, byte_mes)
    if not header:
        return
    client_id = header.__getitem__(0)
    code = byte_to_int(header.__getitem__(2))
    payload_size = byte_to_int(header.__getitem__(3))
    mes = conn.recv(payload_size)
    if code == REGISTRATION_REQUEST:
        payload = struct.unpack(f'{NAME_SIZE}s{PASS_SIZE}s', mes)
        name = payload.__getitem__(0).decode('utf-8').strip('\0')
        password = payload.__getitem__(1).decode('utf-8').strip('\0')
        registration_request(conn, code, password, name)
    elif code == SYMMETRIC_KEY_REQUEST:
        payload = struct.unpack(f'{NONCE_SIZE}s', mes)  # convert version to int
        nonce = payload.__getitem__(0)
        symmetric_key_request(conn, client_id, code, nonce)


if __name__ == "__main__":
    try:
        sock = socket.socket()
        sock.bind(('', int("".join(port_number))))
        sock.listen(100)
        sock.setblocking(False)
        sel.register(sock, selectors.EVENT_READ, accept)
        start()
        while True:
            events = sel.select()
            for key, mask in events:
                callback = key.data
                callback(key.fileobj, mask)
    except Exception as e:
        print('Socket closed suddenly. exit.', e)
    #finally:
    #    sock.close()
