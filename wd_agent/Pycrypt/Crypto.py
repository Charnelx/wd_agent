from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import urandom
from hashlib import sha256
import keyring
import uuid
from io import StringIO

TEMP_FILE_EXTENSION = '.tmp'
HEADER_SIZE = 128
PRIVATE_KEY_NAME = 'privkey.pem'
PUBLIC_KEY_NAME = 'pubkey.der'
MASTER_KEY_NAME = 'master.key'

class RSAcrypt(object):

    def __init__(self, passphrase=''):
        self.passphrase = passphrase

    def generate_key(self):
        private_key = RSA.generate(2048, urandom)
        public_key = private_key.publickey()
        return private_key, public_key

    def export_keys(self, privat_key, public_key):
        with open(PRIVATE_KEY_NAME, 'wb') as priv_key, open(PUBLIC_KEY_NAME, 'wb') as pub_key, open(MASTER_KEY_NAME, 'wb') as m_k:
            priv_key.write(privat_key.exportKey(format='PEM', passphrase=self.passphrase))
            pub_key.write(public_key.exportKey(format='DER'))
            m_k.write(uuid.uuid4().hex.encode())

    def encrypt_psw(self, password, public_key):
        if not isinstance(password, (bytes, bytearray)):
            password = password.encode()

        if not hasattr(public_key, 'read'):
            public_key = public_key.name
            with open(public_key, 'rb') as pub_key:
                key_data = pub_key.read()
        else:
            key_data = public_key.read()

        key = RSA.importKey(key_data)
        cipher = PKCS1_OAEP.new(key)
        return cipher.encrypt(password)

    def decrypt_psw(self, ciphertext, private_key, passphrase):
        if not isinstance(ciphertext, (bytes, bytearray)):
            raise TypeError('Ciphertext should be encoded in bytes.')

        if not hasattr(private_key, 'read'):
            public_key = private_key.name
            with open(public_key, 'rb') as pub_key:
                key_data = pub_key.read()
        else:
            key_data = private_key.read()

        key = RSA.importKey(key_data, passphrase=passphrase)
        cipher = PKCS1_OAEP.new(key)
        return cipher.decrypt(ciphertext)


class AEScrypt(object):

    @staticmethod
    def derive_key_and_iv(password, salt, key_length, iv_length):
        d = d_i = b''
        while len(d) < key_length + iv_length:
            d_i = sha256(d_i + str.encode(password) + salt).digest()
            d += d_i
        return d[:key_length], d[key_length:key_length + iv_length]

    @staticmethod
    def encrypt(in_file, out_file, password, salt_header='', key_length=32):
        bs = AES.block_size
        salt = urandom(bs - len(salt_header))
        key, iv = AEScrypt.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        out_file.write(str.encode(salt_header) + salt)
        finished = False
        while not finished:
            chunk = in_file.read(1024 * bs)
            if len(chunk) == 0 or len(chunk) % bs != 0:
                padding_length = (bs - len(chunk) % bs) or bs
                chunk += str.encode(padding_length * chr(padding_length))
                finished = True
            out_file.write(cipher.encrypt(chunk))

    @staticmethod
    def decrypt(in_file, out_file, password, salt_header='', key_length=32):
        bs = AES.block_size
        salt = in_file.read(bs)[len(salt_header):]
        key, iv = AEScrypt.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(
                in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = chunk[-1]
                chunk = chunk[:-padding_length]
                finished = True
            out_file.write(bytes(x for x in chunk))


    @staticmethod
    def decrypt_to_mem(in_file, password, salt_header='', key_length=32):
        file = StringIO('')
        bs = AES.block_size
        salt = in_file.read(bs)[len(salt_header):]
        key, iv = AEScrypt.derive_key_and_iv(password, salt, key_length, bs)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        next_chunk = ''
        finished = False
        while not finished:
            chunk, next_chunk = next_chunk, cipher.decrypt(
                in_file.read(1024 * bs))
            if len(next_chunk) == 0:
                padding_length = chunk[-1]
                chunk = chunk[:-padding_length]
                finished = True
            block = bytes(x for x in chunk)
            file.write(block.decode())
        return file.getvalue()