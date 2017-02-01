import argparse
import asyncore
import base64
import email
import hashlib
import smtpd
import smtplib

import pickle
from email.mime.text import MIMEText
from multiprocessing.pool import ThreadPool

import xtea


class NaiveDH(smtpd.SMTPServer):
    def __init__(self, args):
        self.threadPool = ThreadPool()
        self.DHKE_P = None
        self.DHKE_G = None
        self.private_key = args.key
        self.local_addr = 'localhost'
        self.local_port = args.port
        self.partner_addr = None
        self.partner_port = None
        self.partner_pubkey = None
        self.common_key = None
        self.message = None
        smtpd.SMTPServer.__init__(self, (self.local_addr, self.local_port), None)
        print('SMTP server for localhost listening on port', self.local_port)

        if args.r:  # RECEIVE MODE
            print('BOB: Hi! Waiting for messages...')

        if args.s:  # SEND MODE
            self.DHKE_P = 439351292910452432574786963588089477522344331
            self.DHKE_G = 1747822896920092227343
            self.partner_addr = args.s.split(':')[0]
            self.partner_port = args.s.split(':')[1]
            self.message = args.message
            print('ALICE: Hi! I will now send a message to Bob.')
            A = self.DHKE_G ** self.private_key % self.DHKE_P
            print('ALICE: Calculating g^a mod p:', self.DHKE_G, '**', self.private_key, '%', self.DHKE_P, '=', A,
                  'which will be my public key.')
            self.send_message('INITREQ', (self.local_addr, self.local_port, self.DHKE_G, self.DHKE_P, A))

    def process_message(self, peer, mailfrom, rcpttos, data):
        mail = email.message_from_string(data)
        obj = pickle.loads(base64.b64decode(mail._payload))

        if obj['type'] == 'INITREQ':  # INITREQ
            self.partner_addr = obj['payload'][0]
            self.partner_port = obj['payload'][1]
            self.DHKE_G = obj['payload'][2]
            self.DHKE_P = obj['payload'][3]
            A = obj['payload'][4]
            print('BOB: Received g=', self.DHKE_G, ', p=', self.DHKE_P, ', and public key', A, 'from Alice on ',
                  self.partner_addr, 'port', self.partner_port, '.')
            B = self.DHKE_G ** self.private_key % self.DHKE_P
            print('BOB: Calculating g^b mod p:', self.DHKE_G, '**', self.private_key, '%', self.DHKE_P, '=', B,
                  'which will be my public key.')
            self.send_message('INITRESP', B)
            self.common_key = A ** self.private_key % self.DHKE_P
            print('BOB: Calculating A^b mod p:', A, '**', self.private_key, '%', self.DHKE_P, '=', self.common_key,
                  'which will be our common key.')
            return

        if obj['type'] == 'INITRESP':  # INITRESP
            B = obj['payload']
            print('ALICE: Received public key', B, 'from Bob.')
            self.common_key = B ** self.private_key % self.DHKE_P
            print('ALICE: Calculating B^a mod p:', B, '**', self.private_key, '%', self.DHKE_P, '=', self.common_key,
                  'which will be our common key.')
            print('ALICE: Encrypting message "', self.message, '" and sending it to Bob...', sep='')
            encrypted_message = encrypt_xtea_cbc(self.common_key, string_to_bits(self.message))
            self.send_message('MSG', encrypted_message)
            return

        if obj['type'] == 'MSG':  # MSG
            encrypted_message = obj['payload']
            decrypted_message = bits_to_string(decrypt_xtea_cbc(self.common_key, encrypted_message))
            print('BOB: Got message from Alice :', encrypted_message)
            print('BOB: Decrypted it with our common-key:', decrypted_message)
            return

    def send_message(self, type, payload):
        self.threadPool.apply_async(send_message_thread, [type, payload, self.partner_addr, self.partner_port])

def send_message_thread(type, payload, addr, port):
    b64payload = base64.b64encode(pickle.dumps({'type': type, 'payload': payload}))
    msg = MIMEText(b64payload.decode())
    print('SENDMAIL: TO =', addr, port, ': TYPE =', type, ', PAYLOAD =', payload,
          ', BASE64 =', b64payload)
    _smtp = smtplib.SMTP(addr, port)
    _smtp.sendmail('FROM', 'TO', msg.as_string())
    _smtp.quit()

def string_to_bits(s):
    """
    Converts a String of text into a String of bits (padded to 8 bit per char)
    :param s: String
    :return: String, bits
    """
    bits = []
    for c in s:
        bin_t = bin(ord(c))[2:]  # remove 0b header
        bits.append(bin_t.zfill(8))  # pad to 8 bit
    return "".join(bits)

def bits_to_string(b):
    """
    Converts a String of bits (8 bits per char) into a String of text
    :param s: bit-String
    :return: Text
    """
    chars = []
    for i in range(0, len(b), 8):
        char = chr(int(b[i:i + 8], 2))
        chars.append(char)
    return "".join(chars).rstrip(chr(0))  # remove trailing 0 characters since we don´t know where the message ends


def encrypt_xtea_cbc(key, bits):
    """
    Hashes the key and encrypts with XTEA in CBC mode
    :param key: String, key
    :param bits: String of bits
    :return: String of bits (encrypted)
    """
    key = str(key)
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()[0:16]  # take first 128 bit of hash
    return xtea.encrypt_cbc(key_hash, bits)


def decrypt_xtea_cbc(key, bits):
    """
    Hashes the key and decrypts with XTEA in CBC mode
    :param key: String, key
    :param bits: String of bits
    :return: String of bits (decrypted)
    """
    key = str(key)
    key_hash = hashlib.sha256(key.encode('utf-8')).digest()[0:16]  # take first 128 bit of hash
    return xtea.decrypt_cbc(key_hash, bits)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    parser.add_argument('-p', '--port', help='local port', type=int, required=True)
    parser.add_argument('-k', '--key', help='private key', type=int, required=True)
    mode.add_argument('-s', help='send message to address', action='store')
    mode.add_argument('-r', help='receive', action='store_true')
    parser.add_argument('message', nargs='?')
    args = parser.parse_args()
    naive_dh = NaiveDH(args)
    try:
        asyncore.loop()
    except KeyboardInterrupt:
        naive_dh.close()
