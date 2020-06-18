import hashlib
import json
import random
import socket
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

packet_size = 20

def to_packets(data, packet_size):
    packets = []
    if len(data) > packet_size:
        for i in range(0, len(data), packet_size):
            try:
                packets.append(data[i:i + packet_size].encode())
            except:
                packets.append(data[i:].encode())
    else:
        packets.append(data.encode())
    return packets


def get_message(sock):
    while 1:
        data = sock.recv(1024)
        if data == b'Message begin':
            full_mes = b''
            end = False
            while not end:
                data= sock.recv(packet_size)
                if data == b'Message end':
                    end = True
                    continue
                else:
                    full_mes += data
            break
        else:
            break
    return full_mes


def encrypt(plain_text, password):
    salt = get_random_bytes(AES.block_size)
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    cipher_config = AES.new(private_key, AES.MODE_GCM)
    cipher_text, tag = cipher_config.encrypt_and_digest(bytes(plain_text, 'utf-8'))
    return {
        'cipher_text': base64.b64encode(cipher_text).decode('utf-8'),
        'salt': base64.b64encode(salt).decode('utf-8'),
        'nonce': base64.b64encode(cipher_config.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8')
    }


def decrypt(enc_dict, password):
    salt = base64.b64decode(enc_dict['salt'])
    cipher_text = base64.b64decode(enc_dict['cipher_text'])
    nonce = base64.b64decode(enc_dict['nonce'])
    tag = base64.b64decode(enc_dict['tag'])
    private_key = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    cipher = AES.new(private_key, AES.MODE_GCM, nonce=nonce)
    decrypted = cipher.decrypt_and_verify(cipher_text, tag)
    return decrypted


server = 'localhost', 1234
def key_gen():
    key = input('Введите ключ:')
    with open("key.txt", "w") as file:
        file.write(key)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    data = ['Key_Generation', key]
    data = json.dumps(data)

    sock.sendto(('Message begin').encode('utf-8'), server)
    for packet in to_packets(data, packet_size):
        sock.sendto(packet, server)
    sock.sendto(('Message end').encode('utf-8'), server)
    return_message = get_message(sock)
    return_message = json.loads(return_message)
    print('ret mes', return_message)
    sock.close()

def identify():
    with open("key.txt", "r") as file:
        key = file.read()
    text1 = input('Введите текст 1: ')
    ra = random.randint(1, 100)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('', 0))
    data = ['Step_1', str(ra), text1]
    data = json.dumps(data)

    sock.sendto(('Message begin').encode('utf-8'), server)
    for packet in to_packets(data, packet_size):
        sock.sendto(packet, server)
    sock.sendto(('Message end').encode('utf-8'), server)
    return_message = get_message(sock)
    return_message = json.loads(return_message)
    print('ret mes', return_message)
    text3 = return_message[0]
    decrypted = str(decrypt(return_message[1], key))[2:].split(',')
    print(decrypted)
    ra = decrypted[0]
    rb =  decrypted[1]
    print("Идентификатор пользователя В:", decrypted[2])
    print("Сообщение 2:", decrypted[3])
    print("Сообщение 2:", text3)
    you_id = input("Введите свой идентификатор: ")
    text4 = input("Введите сообщение 4: ")
    text5 = input("Введите сообщение 5: ")
    data = ['Step_2', text4, encrypt(rb + "," + ra + "," + you_id + "," + text5, key)]
    data = json.dumps(data)

    sock.sendto(('Message begin').encode('utf-8'), server)
    for packet in to_packets(data, packet_size):
        sock.sendto(packet, server)
    sock.sendto(('Message end').encode('utf-8'), server)
    return_message = get_message(sock)
    return_message = json.loads(return_message)
    print('ret mes', return_message)
    sock.close()

while True:
    num = input('Сделайте выбор: 1) Сгенерировать ключ 2) Идентифицировать')
    if num == '1':
        key_gen()
    if num == '2':
        identify()
