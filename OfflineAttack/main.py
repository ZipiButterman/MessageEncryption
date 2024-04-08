import os
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64
from base64 import b64decode
import json


def decrypt(key, iv, value):
    cipher = AES.new(key, AES.MODE_CBC, iv)  # convert pub_key bytes to key format
    decrypted_value = cipher.decrypt(value)
    unpad_value = unpad(decrypted_value, AES.block_size)
    return unpad_value

def base64_to_byte(value):
    return base64.b64decode(value)

def byte_to_str(value):
    return value.decode('utf-8')

def str_to_byte(value):
    return bytes(value, 'utf-8')



encrypted_key_str = ''
f = open('offline_attack.txt', 'r')
for line in f:
    encrypted_key_str += line
    line = f.readline()
encrypted_key = json.loads(base64_to_byte(encrypted_key_str))
f.close()
iv = base64_to_byte(encrypted_key['Encrypted Key IV'])
encrypted_nonce = base64_to_byte(encrypted_key['Nonce'])
encrypted_aes = base64_to_byte(encrypted_key['AES Key'])

f = open('most_used_passwords.txt', 'r')

for password in f:
    password = password.strip('\n')
    hash_pass = SHA256.new(str_to_byte(password)).digest()
    try:
        dec_nonce = decrypt(hash_pass, iv, encrypted_nonce)
        dec_aes = decrypt(hash_pass, iv, encrypted_aes)
    except Exception as e:
        dec_nonce = ''
        continue
    if dec_nonce != '':
        print(f'Found the real password! Password is: {password}.')
        print('Proof that this is the real password: '
              'we succeeded to decrypt the nonce and the private key of the user.')
        print(f'The decrypted nonce: {dec_nonce}.')
        print(f'The decrypted aes: {dec_aes}.')
        exit(0)
print("Didn't find password :(")

f.close()
