import argparse
import asyncore
import hashlib
import smtpd

import xtea


class NaiveDH(smtpd.SMTPServer):
    def process_message(self, peer, mailfrom, rcpttos, data):
        pass

    def __init__(self, args):
        self.DHKE_P = 23
        self.DHKE_G = 17
        self.private_key = args.key
        smtpd.SMTPServer.__init__(self, ('localhost', args.port), None)
        print('SMTP server for localhost listening on port', args.port)

        if args.r:  # RECEIVE MODE
            try:
                asyncore.loop()
            except KeyboardInterrupt:
                naive_dh.close()

        if args.s:  # SEND MODE
            target_addr = args.s.split(':')[0]
            target_port = args.s.split(':')[1]
            message = args.message

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
        key_hash = hashlib.sha256(key.encode('utf-8')).digest()[0:16]  # take first 128 bit of hash
        return xtea.encrypt_cbc(key_hash, bits)

    def decrypt_xtea_cbc(key, bits):
        """
        Hashes the key and decrypts with XTEA in CBC mode
        :param key: String, key
        :param bits: String of bits
        :return: String of bits (decrypted)
        """
        key_hash = hashlib.sha256(key.encode('utf-8')).digest()[0:16]  # take first 128 bit of hash
        return xtea.decrypt_cbc(key_hash, bits)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group()
    parser.add_argument('-p', '--port', help='local port', type=int, required=True)
    parser.add_argument('-k', '--key', help='private key', required=True)
    mode.add_argument('-s', help='send message to address', action='store')
    mode.add_argument('-r', help='receive', action='store_true')
    parser.add_argument('message', nargs='?')
    args = parser.parse_args()
    naive_dh = NaiveDH(args)
