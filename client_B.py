import hashlib
import json
import random
import socket
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
packet_size = 20

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


def new_pow(x, a, n=None):
    res = 1
    for i in list(bin(a)[2:]):
        res = (res ** 2) * (x ** int(i)) % n
    return res

def data_to_packets(data, packet_size):
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



while True:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('localhost', 1234))
    client = []
    print('work b begin')
    while 1:
        data, addres = sock.recvfrom(packet_size)
        if data == b'Message begin':
            print('Message start')
            full_mes = b''
            end = False
            while not end:
                data, _ = sock.recvfrom(packet_size)
                if data == b'Message end':
                    end = True
                    continue
                else:
                    full_mes += data
        print("Recieved data", full_mes.decode()[:100] + '...')
        break
    print(addres)

    full_mes = json.loads(full_mes.decode('utf-8'))
    print(full_mes)

    if full_mes[0] == "Key_Generation":
        with open('key_B.txt', 'w') as file:
            file.write(full_mes[1])
        data = 'Ключ принят B'
        data = json.dumps(data)
        sock.sendto(('Message begin').encode('utf-8'), addres)
        for packet in data_to_packets(data, packet_size):
            sock.sendto(packet, addres)
        sock.sendto(('Message end').encode('utf-8'), addres)
        break

    if full_mes[0] == "Step_1":
        print('Запрос на идентификацию')
        print('Сообщение', full_mes[2])
        print('Ra', full_mes[1])

        with open('key_B.txt', 'r') as file:
            key = file.read()
        ra = full_mes[1]
        id = input("Введите свой идентификатор: ")
        text2 = input("Введите сообщение 2: ")
        text3 = input("Введите сообщение 3: ")
        rb = random.randint(0,100)

        data = [text3, encrypt((ra + ',' +  str(rb) + ',' + id + ',' + text2), key)]
        data = json.dumps(data)
        sock.sendto(('Message begin').encode('utf-8'), addres)
        for packet in data_to_packets(data, packet_size):
                sock.sendto(packet, addres)
        sock.sendto(('Message end').encode('utf-8'), addres)

    if full_mes[0] == "Step_2":
            decrypted = str(decrypt(full_mes[2], key))[2:].split(',')
            text4 = full_mes[1]
            print("Идентификатор пользователя A:" + decrypted[2])
            print('Сообщение 4: ', text4)
            print('Сообщение 4: ', decrypted[3])
            if str(rb) == decrypted[0] and ra == decrypted[1]:
                print("Идентификация подтверждена")
                data = "Идентификация подтверждена"
            else:
                print("Идентификация не проведена")
                data = "Идентификация не проведена"
            data = json.dumps(data)
            sock.sendto(('Message begin').encode('utf-8'), addres)
            for packet in data_to_packets(data, packet_size):
                    sock.sendto(packet, addres)
            sock.sendto(('Message end').encode('utf-8'), addres)
            break

sock.close()
print("work B ended")
