import random

NUM_CYCLES = 32


def generate_random_iv():
    """
    Generates an 64 bit random IV
    :return: String of bits
    """
    bits = []
    for i in range(0, 64):
        bits.append(str(round(random.random())))
    return ''.join(bits)


def encrypt(key, bits):
    """
    Takes a bit-string and encrypts it via CFB-mode
    :param key: String, key
    :param bits: String of bits
    :return: String of bits
    """
    cypher_blocks = []
    blocks = _split_into_blocks(bits)
    for block in blocks:
        if len(cypher_blocks) == 0:
            iv = generate_random_iv()
            cypher_block = _encrypt_one_block(key, iv)
            cypher_blocks.append(iv)  # set iv as first block in output
        else:
            cypher_block = _encrypt_one_block(key, cypher_blocks[-1:][0])
        cypher_blocks.append(_xor(block, cypher_block))

    return "".join(cypher_blocks)


def decrypt(key, cypherbits):
    """
    Takes a bit-string and decrypts it via CFB-mode
    :param key: String, key
    :param cypherbits: String of bits
    :return: String of bits
    """
    cypher_blocks = _split_into_blocks(cypherbits)
    IV = cypher_blocks[0]
    cypher_blocks = cypher_blocks[1:]
    blocks = []
    last_cypher_block = IV
    for cypher_block in cypher_blocks:
        block = _encrypt_one_block(key, last_cypher_block)
        blocks.append(_xor(block, cypher_block))
        last_cypher_block = cypher_block

    return "".join(blocks)


def _encrypt_one_block(key, block):
    """
    Encrypts one block with XTEA Algorithm
    https://de.wikipedia.org/wiki/Extended_Tiny_Encryption_Algorithm
    :param key: String, key
    :param block: String of bits (64)
    :return: encrypted block
    """
    assert (len(block) == 64)
    v0 = int(block[0:32], 2)
    v1 = int(block[32:64], 2)
    k = [int.from_bytes(key[0:4], byteorder='big', signed=False),
         int.from_bytes(key[4:8], byteorder='big', signed=False),
         int.from_bytes(key[8:12], byteorder='big', signed=False),
         int.from_bytes(key[12:16], byteorder='big', signed=False)]
    delta = 0x9E3779B9
    sum = 0
    for i in range(0, NUM_CYCLES):
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum % 3])
        sum += delta
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum >> 11) % 3])

    block = _int_to_bits(v0) + _int_to_bits(v1)
    return block


def _split_into_blocks(bits):
    """
    Returns a list with bit Strings, padded to 64 bit
    :param bits: String of bits
    :return: list of padded Strings of bits
    """
    blocks = []
    for i in range(0, len(bits), 64):
        block = bits[i:i + 64]
        if len(block) == 64:
            blocks.append(block)
        else:
            pad = '0' * (64 - len(block) % 64)
            block += pad
            blocks.append(block)
    return blocks


def _xor(a, b):
    """
    Binary XOR for Strings of bits
    :param a: left
    :param b: right
    :return: xor
    """
    xor = []
    for bit_a, bit_b in zip(a, b):
        xor.append(str(int(bit_a) ^ int(bit_b)))
    return "".join(xor)


def _int_to_bits(i):
    """
    Int to bit String
    :param i: Integer
    :return: String of bits
    """
    return bin(i)[2:]
