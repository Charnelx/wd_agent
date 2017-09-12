from Cryptodome.Cipher import AES
from Cryptodome.Cipher import PKCS1_OAEP
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import urandom
from Pycrypt.Crypto import RSAcrypt, AEScrypt
from hashlib import sha256, md5
import keyring
import uuid
from msvcrt import getch
import getpass
import sys
import os
import python_webdav.client
import requests
import time

try:
    from os import scandir
except ImportError:
    from scandir import scandir  # use scandir PyPI module on Python < 3.5
import pathlib
from colorama import init, Fore



ENCRYPT_FOLDER_NAME = 'encrypted'
TEMP_FILE_EXTENSION = '.tmp'
HEADER_SIZE = 128


# load hash-table for password check
HASHES = set()
with open('pwd_md5.txt', 'r') as file:
    while True:
        hs = file.read(32)
        if not hs:
            break
        HASHES.add(hs)


class FileWrapper(object):

    def __init__(self, path: str):
        self.path = path
        file_path = pathlib.Path(path)
        self.name = file_path.parts[-1:][0]


def password_check(pwd):
    word = pwd.lower()
    word_hs = md5(word.encode()).hexdigest()
    if word_hs in HASHES:
        return True
    return False


def scan_tree(path: str, encrypted_dir=False):
    """
    Recursively yield DirEntry objects for given directory.

    :param path: path to target directory
    :return: generator; list of entries
    """
    if not os.path.exists(path):
        return None
    for entry in scandir(path):
        if entry.is_dir(follow_symlinks=False):
            if not encrypted_dir:
                if not entry.name.lower() == 'encrypted':
                    yield from scan_tree(entry.path)
            else:
                yield from scan_tree(entry.path)
        else:
            yield entry


def hidden_input(prompt='Password: ') -> str:
    """
    Prompt for a password and masks the input.
    Returns: the value entered by the user.
    """

    if sys.stdin is not sys.__stdin__:
        pwd = getpass.getpass(prompt)
        return pwd
    else:
        pwd = ""
        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            key = ord(getch())
            if key == 13:  # Return Key
                sys.stdout.write('\n')
                return pwd
                break
            if key == 8:  # Backspace key
                if len(pwd) > 0:
                    # Erases previous character.
                    sys.stdout.write('\b' + ' ' + '\b')
                    sys.stdout.flush()
                    pwd = pwd[:-1]
            else:
                # Masks user input.
                char = chr(key)
                sys.stdout.write('*')
                sys.stdout.flush()
                pwd = pwd + char

def generate_master_keys():
    passphrase = hidden_input('\nType passphrase for your private key: ')
    r_passphrase = hidden_input('\nType passphrase for your private key (repeat): ')

    if not passphrase == r_passphrase:
        print(Fore.RED + 'Passphrases you typed are not equal.')
        return False

    if password_check(passphrase):
        print(Fore.RED + 'Your password is in 100K most common passwords. Change it and try again.')
        return False

    try:
        crypto = RSAcrypt(passphrase)
        priv_key, pub_key = crypto.generate_key()
        crypto.export_keys(priv_key, pub_key)
    except Exception as err:
        print(Fore.RED + 'Error occurred during key generation process. Aborting')
        return False

    print('Keys are generated.\nPrivate key: privkey.pem\nPublic key: pubkey.der\nMaster key: master.key\n')
    print(Fore.RED + 'IMPORTANT!!!\nPublic key is used to encrypt your credentials data. You can store/copy/exchange '
                     'it freely. PRIVATE KEY is used to decrypt your credentials data so NEVER SHARE, EXCHANGE OR COPY'
                     ' IT. Keep private key safe&protected.')
    return True

def set_encryption_credentials():
    passphrase = hidden_input('\nType encryption password: ')
    r_passphrase = hidden_input('\nType encryption password (repeat): ')

    if not passphrase == r_passphrase:
        print('Passwords you typed are not equal.')
        return False

    if password_check(passphrase):
        print(Fore.RED + 'Your password is in 100K most common passwords. Change it and try again.')
        return False

    if not os.path.exists('master.key'):
        print('Unable to locate master key file.')
        return False

    with open('master.key', 'rb') as ms_key:
        master_psw = ms_key.read().decode()

    keyring.set_password('_agent_e_psw', master_psw, passphrase)

    return True


def set_remote_credentials():
    username = input('\nType remote username: ')
    passphrase = hidden_input('\nType password: ')
    r_passphrase = hidden_input('\nType password (repeat): ')

    if not passphrase == r_passphrase:
        print(Fore.RED + 'Passwords you typed are not equal.')
        return False

    if not username:
        print(Fore.RED + 'Need to type username!')
        return False

    if not os.path.exists('master.key'):
        print(Fore.RED + 'Unable to locate master key file.')
        return False

    # Need refactoring
    try:
        conn = python_webdav.client.Client('http://193.106.27.175:60000/nextcloud/remote.php/webdav/', '/')
        conn.set_connection(username=username, password=passphrase)
        conn.ls('/', display=False)
    except requests.exceptions.ConnectionError:
        print('Connection error.')
        sys.exit(-1)
    except Exception:
        print('Invalid username or password.')
        sys.exit(-1)

    with open('master.key', 'rb') as ms_key:
        master_psw = ms_key.read().decode()

    keyring.set_password('_agent_r_psw', master_psw, passphrase)
    keyring.set_password('_agent_r_usr', master_psw, username)

    return True


def encrypt():
    start_time = time.time()

    if not os.path.exists('master.key'):
        print(Fore.RED + 'Unable to locate master key file.')
        return False
    elif not os.path.exists('pubkey.der'):
        print(Fore.RED + 'Unable to locate public key file.')
        return False

    with open('master.key', 'rb') as ms_key:
        master_psw = ms_key.read().decode()

    encryption_psw = keyring.get_password('_agent_e_psw', master_psw)

    if not encryption_psw:
        print('Encryption password not set - aborting')
        return False

    crypto = RSAcrypt()

    FILES_LOCATION = input('\nType path to file(s) location (you can point to single file or directory with files:\n').rstrip()

    if not os.path.exists(FILES_LOCATION):
        print(Fore.RED + 'Unable to locate file(s) to encrypt.')

    file_path = pathlib.Path(FILES_LOCATION)
    dir_path = os.path.join(*file_path.parts[:-1])

    files = None
    if os.path.isdir(FILES_LOCATION):
        files = sorted([file for file in scan_tree(dir_path)], key=lambda file: file.stat().st_ctime, reverse=True)
    elif os.path.isfile(FILES_LOCATION):
        files = [FileWrapper(FILES_LOCATION)]

    if not files:
        print(Fore.RED + 'Selected directory contain no files.')
        sys.exit(-1)

    encryption_dir = os.path.join(dir_path, ENCRYPT_FOLDER_NAME)

    # Create folder for encrypted files in the root of FILES_LOCATION if not exists
    if not os.path.exists(encryption_dir):
        os.makedirs(encryption_dir)

    for file in files:
        filename, extension = os.path.splitext(os.path.basename(file.name))
        extension = extension[1:]
        # Ignore already encrypted files

        if extension == 'aes':
            continue

        # prepare new files params
        new_filename = '{0}.{1}.aes'.format(filename, extension)
        new_file_path = os.path.join(encryption_dir, new_filename)

        ###################
        # File encryption #
        ###################
        try:
            # Encrypt whole file with AES
            with open(file.path, mode='rb') as in_file_object, open(new_file_path, mode='wb') as out_file_object:
                AEScrypt.encrypt(in_file_object, out_file_object, encryption_psw, key_length=32)

            # Encrypts *HEADER_SIZE bytes of file with RSA public key
            with open(new_file_path, 'rb') as encrypted_file:
                block = encrypted_file.read(HEADER_SIZE)

                with open('pubkey.der', 'rb') as public_key:
                    chipertext = crypto.encrypt_psw(block, public_key)

                # Write HEADER + RSA_ENCRYPTED_BLOCK + AES_ENCRYPTED_PART to file
                size = len(chipertext)
                bias = str(size).ljust(HEADER_SIZE, '0').encode()

                encrypted_file.seek(0)

                with open(new_file_path + TEMP_FILE_EXTENSION, 'ab') as temp_file:
                    temp_file.write(bias + chipertext)

                    encrypted_file.seek(HEADER_SIZE)

                    while True:
                        chunk = encrypted_file.read(16384)
                        if not chunk:
                            break
                        temp_file.write(chunk)

            # Wipe AES encrypted file by random values
            # new_file_size = os.stat(new_file_path).st_size
            # with open(new_file_path, 'wb') as encrypted_file:
            #     for _ in range(new_file_size):
            #         encrypted_file.write(urandom(1))

            os.remove(new_file_path)
            os.rename(new_file_path + TEMP_FILE_EXTENSION, new_file_path)

            end_time = time.time()

            process_time = end_time - start_time

            if process_time > 100:
                process_time /= 60
                print('Finished in {0} minutes'.format(process_time))
            else:
                print('Finished in {0:.2f} seconds'.format(process_time))

            return True
        except Exception as err:
            print(Fore.RED + 'Error occurred during encryption process')
            print(err)
            return False


def decrypt():
    start_time = time.time()
    print('Decryption started. Please wait awhile.')
    if not os.path.exists('master.key'):
        print(Fore.RED + 'Unable to locate master key file.')
        return False

    with open('master.key', 'rb') as ms_key:
        master_psw = ms_key.read().decode()

    encryption_psw = keyring.get_password('_agent_e_psw', master_psw)

    FILES_LOCATION = input('\nType path to file(s) location '
                           '(you can point to single file or directory with files:\n').rstrip()

    rsa_passphrase = hidden_input('\nType your private key passphrase: ')

    crypto = RSAcrypt()

    if not os.path.exists(FILES_LOCATION):
        print(Fore.RED + 'Unable to locate file(s) to encrypt.')

    file_path = pathlib.Path(FILES_LOCATION)
    dir_path = os.path.join(*file_path.parts[:-1])
    print('Destination folder:', dir_path)

    files = None
    if os.path.isdir(FILES_LOCATION):
        files = sorted([file for file in scan_tree(dir_path, True)], key=lambda file: file.stat().st_ctime, reverse=True)
    elif os.path.isfile(FILES_LOCATION):
        files = [FileWrapper(FILES_LOCATION)]

    if not files:
        print(Fore.RED + 'Selected directory contain no files.')
        sys.exit(-1)

    for file in files:
        filename, extension = os.path.splitext(os.path.basename(file.name))
        extension = extension[1:]

        if not extension == 'aes':
            continue

        new_filename = '{0}.{1}'.format(filename, extension)
        new_file_path = os.path.join(dir_path, new_filename).replace('\\', '/')

        try:
            with open(file.path.replace('\\', '/'), 'rb+') as encrypted_file:
                bias = b''
                for i in range(HEADER_SIZE):
                    char = encrypted_file.read(1)
                    if char == b'0':
                        break
                    bias += char

                encrypted_file.seek(HEADER_SIZE)

                encrypted_block_size = int(bias)
                encrypted_block = encrypted_file.read(encrypted_block_size)

                with open('privkey.pem', 'rb') as private_key:
                    try:
                        decrypted_block = crypto.decrypt_psw(encrypted_block, private_key, rsa_passphrase)
                    except Exception as err:
                        print('Unable to decrypt file. Error:\n')
                        print(err)
                        return False

            origin_file_name = new_filename.rsplit('.', 1)[0]
            temp_file_path = os.path.join(dir_path,  origin_file_name + '.tmp')
            orig_file_path = os.path.join(dir_path, origin_file_name)

            with open(temp_file_path, 'ab') as temp_file:
                temp_file.write(decrypted_block)
                with open(new_file_path, 'rb', buffering=HEADER_SIZE*16) as decr_file:
                    decr_file.seek(HEADER_SIZE + encrypted_block_size)
                    while True:
                        chunk = decr_file.read(1024)
                        if not chunk:
                            break
                        temp_file.write(chunk)

            with open(temp_file_path, 'rb') as in_f, open(orig_file_path, 'wb') as out_f:
                AEScrypt.decrypt(in_f, out_f, encryption_psw)

            os.remove(temp_file_path)

            end_time = time.time()
        except Exception as err:
            print(Fore.RED + 'Error occurred during encryption process:\n')
            print(err)
            return False

        process_time = end_time - start_time

        if process_time > 100:
            process_time /= 60
            print('Finished in {0} minutes'.format(process_time))
        else:
            print('Finished in {0:.2f} seconds'.format(process_time))
        return True


MENU_MAPPER = {
    0: sys.exit,
    1: generate_master_keys,
    2: set_encryption_credentials,
    3: set_remote_credentials,
    4: decrypt,
    5: encrypt
}


if __name__ == '__main__':
    init(autoreset=True)

    login_user = 'Unknown'
    try:
        login_user = os.getlogin()
    except Exception:
        pass

    print('Keeper started under <{0}> account. Remember - Each launch must be performed from this account!'.format(login_user))

    while True:
        variant = input('\nChoose operation:\n'
                        '0. Exit\n'
                        '1. Generate master keys\n'
                        '2. Set encryption password\n'
                        '3. Set remote username/password\n'
                        '4. Decrypt file(s)\n'
                        '5. Encrypt file(s)\n\n')

        variants = list()
        for v in variant:
            try:
                v = int(v)
                variants.append(v)
                if v not in MENU_MAPPER.keys():
                    print(Fore.RED + 'Invalid variant {0}. Please retry.'.format(v))
                    variants = None
                    break
            except Exception as err:
                print(Fore.RED + 'You should chose only digits. Please retry')
                variants = None
                break

        if not variants or len(variants) < len(variant):
            continue

        for v in variants:
            block = MENU_MAPPER[v]
            result = block()

            if not result:
                print(Fore.RED + '\nExiting on error.')
                sys.exit(-1)
            print(Fore.GREEN + '\nOperation was successful.')