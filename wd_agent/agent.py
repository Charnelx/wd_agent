import argparse
import configparser
import os
import sys
import datetime
from os.path import join
import re
import shutil
import socket
from urllib.parse import urlparse

try:
    from os import scandir
except ImportError:
    from scandir import scandir  # use scandir PyPI module on Python < 3.5

import pathlib

# from Crypto.Cipher import AES
# from Cryptodome.Cipher import AES
# from Cryptodome.Cipher import PKCS1_OAEP
# from Cryptodome.PublicKey import RSA
# from Cryptodome.Random import urandom
# from hashlib import sha256
# import uuid

from Pycrypt.Crypto import RSAcrypt, AEScrypt
import keyring

import python_webdav.client
from msvcrt import getch
import getpass

LOG_LEVELS = {1: 'INFO', 2: 'DEBUG', 3: 'ERROR'}
BASE_DIR = os.path.dirname(sys.argv[0])
CONFIG_FILE_NAME = '.cfg'
TEMP_FILE_EXTENSION = '.tmp'
ENCRYPT_FOLDER_NAME = 'encrypted'

PATTERN_URL_VALIDATE = re.compile(
        r'(?:^(?:http|ftp|webdav|dav)+s?://)?'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|'  # ...or ipv4
        r'\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

FILES_LOCATION = None
UPLOAD_URI = None
UPLOAD_DIRECTORY = '/'
SAVE_STRUCTURE = False
ONLY_LAST = True
UPLOAD = False
DELETE_ORIGIN = False
DELETE_ENCRYPTED = False
ENCRYPT = True
FORCE_ERRORS = False

HEADER_SIZE = 128
READ_CHUNK_SIZE = 16384


def get_current_dt() -> datetime.datetime:
    """
    Return current datetime
    :return: datetime
    """
    return datetime.datetime.now()


def str_to_bool(value: str) -> bool:
    """
    Helper function that converts string boolean values to bool type.
    Anything except true are false.
    :param value: string of boolean value
    :return: bool type value
    """

    if value.lower() == 'true':
        return True
    return False


def init_log(file_name: str) -> callable:
    """
    Log messages to file in format:
    [datetime]<level>: message

    :param file_name: path to log file
    :return: logger function
    """
    log_file = open(file_name, mode='a', encoding='utf-8')
    def log(level, msg):
        line = '[{dt}]<type: {type}>: {msg}\n'.format(dt=get_current_dt(), type=LOG_LEVELS[level], msg=msg)
        log_file.write(line)
        return True
    return log


def validate_url(url: str) -> bool:
    """
    URL validation.
    Taken from Django validators and slightly modified.

    :param url: URL to validate
    :return: bool value depends on valid URL or not
    """

    if re.search(PATTERN_URL_VALIDATE, UPLOAD_URI):
        return True
    return False


def scan_tree(path: str, encrypted_dir=False):
    """
    Recursively yield DirEntry objects for given directory.

    :param path: path to target directory
    :return: generator; list of entries0
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

def check_connection(url: str) -> bool:
    """
    Check connection to IP:port
    :param url: full URI
    :return: connection ready/not
    """
    parsed = urlparse(url)
    url = parsed.netloc.split(':')[0]
    port = parsed.port
    try:
        socket.create_connection((url, port))
        return True
    except OSError as err:
        log(3, 'Connection to server on address {0}:{1} failed.'.format(url, port))
        print('Connection to server on address {0}:{1} failed.'.format(url, port))
        return False

def response_parse(resp, content):
    status = resp.status_code
    if status == 201:
        return 1, 'file successfully created.'
    if status == 204:
        return 2, 'file already exists.'
    else:
        if isinstance(content, bytes):
            content = content.decode()
        return 3, 'error while uploading file: {0}'.format(content.replace('\n', ' '))

def hide_input(prompt='Password: ') -> str:
    """
    Prompt for a password and masks the input.
    Returns:
        the value entered by the user.
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

if __name__ == '__main__':
    log = init_log(join(BASE_DIR, 'log.log'))
    log(1, 'Agent started.')

    login_user = 'Unknown'
    try:
        login_user = os.getlogin()
    except Exception:
        pass

    log(1, 'Agent started by {0}'.format(login_user))

    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-c', '--config', required=False, nargs=1,
                            help='Config file destination')
    arg_parser.add_argument('-p', '--path', required=False, nargs=1,
                            help='Path to file/folder to upload')
    arg_parser.add_argument('-s', '--save_structure', required=False, nargs=1,
                            help='Save upload structure directory structure')
    arg_parser.add_argument('-l', '--last', required=False, nargs=1,
                            help='Operate with last created file')
    arg_parser.add_argument('-d', '--del_origin', required=False,
                            help='Delete original file(s) after upload')
    arg_parser.add_argument('-D', '--del_encrypted', required=False,
                            help='Delete encrypted file(s) after upload')
    arg_parser.add_argument('-e', '--encrypt', required=False,
                            help='Encrypt file(s)')
    arg_parser.add_argument('-u', '--upload', required=False, nargs='+',
                            help='Upload files to server. Format: agent.ext -u uri remote_dir')
    arg_parser.add_argument('-f', '--force_errors', required=False, nargs=1,
                            help='Try to handle/ignore some errors. Use on own risk!')

    args = arg_parser.parse_args()


    if args.config:
        # load preferences from folder/file
        option_config = args.config[0]
        cfg_path = option_config.rstrip()

        # search config in program root directory
        if cfg_path == '.':
            prg_path = join(BASE_DIR, CONFIG_FILE_NAME)
            print(prg_path)
            prg_path = pathlib.Path(prg_path)
            cfg_path = join(*prg_path.parts[:-2], CONFIG_FILE_NAME)
            if os.path.exists(cfg_path):
                config = configparser.ConfigParser()
                try:
                    config.read(cfg_path)
                except Exception as err:
                    log(3, 'Unable to parse config from "{0}". Error: {1}'.format(cfg_path, err))
                    print('Unable to parse config from "{0}". Error: {1}'.format(cfg_path, err))
                    sys.exit(-1)
            else:
                log(3, 'No config file in "{}" or file is corrupted.'.format(prg_path))
                print('No config file in "{}" or file is corrupted.'.format(prg_path))
                sys.exit(-1)
        # search config in target directory
        elif os.path.isdir(option_config):
            cfg_path = join(option_config, CONFIG_FILE_NAME)
            if os.path.exists(cfg_path):
                config = configparser.ConfigParser()
                try:
                    config.read(cfg_path)
                except Exception as err:
                    log(3, 'Unable to parse config from "{0}". Error: {1}'.format(cfg_path, err))
                    print('Unable to parse config from "{0}". Error: {1}'.format(cfg_path, err))
                    sys.exit(-1)
            else:
                log(3, 'No config file in "{}" or file is corrupted.'.format(option_config))
                print('No config file in "{}" or file is corrupted.'.format(option_config))
                sys.exit(-1)
        # try to load config from target file
        elif os.path.isfile(option_config):
            config = configparser.ConfigParser()
            try:
                config.read(option_config)
            except Exception as err:
                log(3, 'Unable to read config from "{0}". Error: {1}'.format(option_config, err))
                print('Unable to parse config from "{0}". Error: {1}'.format(option_config, err))
                sys.exit(-1)
        else:
            log(3, 'No config file in "{}" or file is corrupted.'.format(option_config))
            print('No config file in "{}" or file is corrupted.'.format(option_config))
            sys.exit(-1)

        try:
            FILES_LOCATION = config.get('PATH', 'files_location')
            UPLOAD_URI = config.get('PATH', 'upload_uri')
            UPLOAD_DIRECTORY = config.get('PATH', 'upload_dir')
            SAVE_STRUCTURE = str_to_bool(config.get('PATH', 'save_structure'))
            ONLY_LAST = str_to_bool(config.get('BEHAVIOUR', 'last'))
            UPLOAD = True if UPLOAD_URI and UPLOAD_DIRECTORY else False
            ENCRYPT = str_to_bool(config.get('BEHAVIOUR', 'encrypt'))
            DELETE_ORIGIN = str_to_bool(config.get('BEHAVIOUR', 'delete_origin'))
            DELETE_ENCRYPTED = str_to_bool(config.get('BEHAVIOUR', 'delete_encrypted'))
            FORCE_ERRORS = str_to_bool(config.get('BEHAVIOUR', 'force_errors'))
        except configparser.NoSectionError as err:
            log(3, 'Unable to find section in config file "{0}". Error: {1}'.format(cfg_path or option_config, err))
            print('Unable to find section in config file "{0}". Error: {1}'.format(cfg_path or option_config, err))
            sys.exit(-1)
        except configparser.NoOptionError as err:
            log(3, 'Unable to find option in config file "{0}". Error: {1}'.format(cfg_path or option_config, err))
            print('Unable to find option in config file "{0}". Error: {1}'.format(cfg_path or option_config, err))
            sys.exit(-1)
        except Exception as err:
            log(3, 'Undefined error raised while parsing config file "{0}". Error: {1}'.format(
                cfg_path or option_config, err))
            print('Undefined error raise while parsing config file "{0}". Error: {1}'.format(
                cfg_path or option_config, err))
            sys.exit(-1)

        log(1, 'Config file "{0}" loaded successfully.'.format(cfg_path or option_config))
    else:
        try:
            FILES_LOCATION = FILES_LOCATION if not args.path else args.path[0]
            if args.upload:
                if len(args.upload) == 2:
                    UPLOAD_URI, UPLOAD_DIRECTORY = args.upload[0], args.upload[1]
                else:
                    UPLOAD_URI = args.upload[0]
            SAVE_STRUCTURE = SAVE_STRUCTURE if not args.save_structure else str_to_bool(args.save_structure[0])
            ONLY_LAST = ONLY_LAST if not args.last else str_to_bool(args.last[0])
            UPLOAD = UPLOAD if not args.upload else True
            ENCRYPT = ENCRYPT if not args.encrypt else str_to_bool(args.encrypt)
            DELETE_ORIGIN = DELETE_ORIGIN if not args.del_origin else str_to_bool(args.del_origin)
            DELETE_ENCRYPTED = DELETE_ENCRYPTED if not args.del_encrypted else str_to_bool(args.del_encrypted)
            FORCE_ERRORS = FORCE_ERRORS if not args.force_errors else str_to_bool(args.force_errors[0])
        except Exception as err:
            log(3, 'Unable to parse config from command line. Arguments: {0}. Error: {1}'.format(args, err))
            print('Unable to parse config from command line. Arguments: {0}. Error: {1}'.format(args, err))
            sys.exit(-1)

        log(1, 'Config from command line accepted')

    log(1, 'Config parameters -> file(s) location: {0}; remote URI: {1}; remote dir: {2}; save structure: {3};'
           'select only last file: {4}; upload file(s): {5}; encrypt file(s): {6}; delete original file(s): {7}; '
           'delete encrypted file(s): {8}.'.format(FILES_LOCATION, UPLOAD_URI, UPLOAD_DIRECTORY, SAVE_STRUCTURE,
                                                   ONLY_LAST, UPLOAD, ENCRYPT, DELETE_ORIGIN, DELETE_ENCRYPTED))

    print('File(s) location:', FILES_LOCATION)
    print('Remote URI:', UPLOAD_URI)
    print('Remote dir:', UPLOAD_DIRECTORY)
    print('Save structure:', SAVE_STRUCTURE)
    print('Select only last file:', ONLY_LAST)
    print('Upload file(s):', UPLOAD)
    print('Encrypt file(s):',ENCRYPT)
    print('Delete original file(s):', DELETE_ORIGIN)
    print('Delete encrypted file(s):', DELETE_ENCRYPTED)
    print('Force errors:', FORCE_ERRORS)

    #######################
    # LOADING CREDENTIALS #
    #######################
    master_key_path = join(BASE_DIR, 'master.key')
    public_key_path = join(BASE_DIR, 'pubkey.der')

    if not os.path.exists(master_key_path):
        print('Unable to locate master key file.')
        log(3, 'Unable to locate master key file.')
    elif not os.path.exists(public_key_path):
        print('Unable to locate public key file.')
        log(3, 'Unable to locate public key file.')

    with open(master_key_path, 'rb') as ms_key:
        master_psw = ms_key.read().decode()

    ENCRYPTION_PASSWORD = keyring.get_password('_agent_e_psw', master_psw)
    REMOTE_USER = keyring.get_password('_agent_r_usr', master_psw)
    REMOTE_USER_PASSWORD = keyring.get_password('_agent_r_psw', master_psw)

    crypto = RSAcrypt()

    if not ENCRYPTION_PASSWORD and ENCRYPT:
        log(2, 'Encryption password not set but ENCRYPT = true. Aborting.')
        print('Encryption password not set. At first start use -i [upload] key to set passwords for encryption')
        sys.exit(-1)

    if not (REMOTE_USER and REMOTE_USER_PASSWORD) and UPLOAD:
        log(2, 'Remote user|password not set but UPLOAD = true. Aborting.')
        print('Remote user/password not set. At first start use -i [upload] key to set passwords for encryption')
        sys.exit(-1)

    # checks
    if FORCE_ERRORS:
        log(2, 'Force errors key used. Risk of uncertain behavior!')
    if not FILES_LOCATION:
        log(2, 'No file(s) selected to operate with. Aborting.')
        print('No file(s) selected to operate with. Use -p [--path] key to select file(s)')
        sys.exit(-1)

    if UPLOAD:
        is_valid_url = validate_url(UPLOAD_URI)
        if not is_valid_url:
            if not FORCE_ERRORS:
                log(2, 'Remote URI failed validation check. Force key set to False. Aborting.')
                print('Unrecognized or invalid remote URI. Use -f [--force_errors] key to overcome this warning.')
            else:
                log(2, 'Remote URI failed validation check. Force key set to True. Continue')
                print('Unrecognized or invalid remote URI. Force errors mode used so this warning skipped.')

    if DELETE_ENCRYPTED and not ENCRYPT:
        if not FORCE_ERRORS:
            log(2, 'Used del_enctypted key without use of encryption. Force key set to False. Aborting.')
            print('No file(s) encryption used so cannot perform delete files of such type. '
                  'Use -f [--force_errors] key to overcome this warning.')
        else:
            log(2, 'Used del_enctypted key without use of encryption. Force key set to True. Cancel delete operations.')
            print('No file(s) encryption used so cannot perform delete files of such type. '
                  'Force errors mode used so this warning skipped - delete operation canceled.')

    # Build files list from FILES_LOCATION (recursive walkthrough)
    files = sorted([file for file in scan_tree(FILES_LOCATION)], key=lambda file: file.stat().st_ctime, reverse=True)
    encrypted_files = None

    if not files:
        log(2, 'Upload directory contain no files. Aborting.')
        print('Upload directory contain no files. Aborting.')
        sys.exit(-1)

    if ONLY_LAST:
        files = files[:1]

    # Encryption stage
    encryption_dir = ''
    if ENCRYPT:
        encryption_dir = join(FILES_LOCATION, ENCRYPT_FOLDER_NAME)
        # Create folder for encrypted files in the root of FILES_LOCATION if not exists
        if not os.path.exists(encryption_dir):
            os.makedirs(encryption_dir)

        for file in files:
            filename, extension = os.path.splitext(os.path.basename(file.name))
            extension = extension[1:]
            # Ignore already encrypted files
            if extension == 'aes':
                continue
            new_filename = '{0}.{1}.aes'.format(filename, extension)
            if SAVE_STRUCTURE:
                file_path = pathlib.Path(file.path)
                path_structure = file_path.parts[1:-1]
                encrypted_path = join(encryption_dir, *path_structure)
                # create dirs structure
                # ignore if already exists
                try:
                    os.makedirs(encrypted_path, mode=0o777)
                except FileExistsError as err:
                    pass
            else:
                encrypted_path = encryption_dir

            full_file_path = join(encrypted_path, new_filename)

            # File encryption
            try:
                # Encrypt whole file with AES
                with open(file.path, mode='rb') as in_file_object, open(full_file_path, mode='wb') as out_file_object:
                    AEScrypt.encrypt(in_file_object, out_file_object, ENCRYPTION_PASSWORD, key_length=32)

                log(1, 'File {0} encrypted with AES'.format(file.path))

                # Encrypts *HEADER_SIZE bytes of file with RSA public key
                with open(full_file_path, 'rb') as encrypted_file:
                    block = encrypted_file.read(HEADER_SIZE)

                    with open(public_key_path, 'rb') as public_key:
                        chipertext = crypto.encrypt_psw(block, public_key)

                    # Write HEADER + RSA_ENCRYPTED_BLOCK + AES_ENCRYPTED_PART to file
                    size = len(chipertext)
                    bias = str(size).ljust(HEADER_SIZE, '0').encode()

                    encrypted_file.seek(0)

                    with open(full_file_path + TEMP_FILE_EXTENSION, 'ab') as temp_file:
                        temp_file.write(bias + chipertext)

                        encrypted_file.seek(HEADER_SIZE)

                        while True:
                            chunk = encrypted_file.read(READ_CHUNK_SIZE)
                            if not chunk:
                                break
                            temp_file.write(chunk)

                        log(1, 'RSA signature added to temp file.'.format(file.path))

                os.remove(full_file_path)
                os.rename(full_file_path + TEMP_FILE_EXTENSION, full_file_path)

                log(1, 'File {0} finally encrypted'.format(file.path))

            except Exception as err:
                log(3, 'Error occurred during encryption process. Error: {0}'.format(err))
                print('Error occurred during encryption process')

    # Upload stage
    if UPLOAD:
        # connect to server
        if not check_connection(UPLOAD_URI):
            log(3, 'Connectivity check on {0} failed.'.format(UPLOAD_URI))
            print('Connectivity check on {0} failed.'.format(UPLOAD_URI))
        conn = python_webdav.client.Client(UPLOAD_URI, UPLOAD_DIRECTORY)
        conn.set_connection(username=REMOTE_USER, password=REMOTE_USER_PASSWORD)

        if ENCRYPT:
            if not os.path.exists(encryption_dir):
                log(3, 'Directory with encrypted files {} does not exists.'.format(encryption_dir))
                sys.exit(-1)
            # look for encrypted files in 'encrypt' folder
            encrypted_files = sorted([file for file in scan_tree(encrypted_path)], key=lambda file: file.stat().st_ctime,
                           reverse=True)
            if ONLY_LAST:
                encrypted_files = encrypted_files[:1]

            for file in encrypted_files:
                if SAVE_STRUCTURE:
                    log(1, 'save_structure set to True. Building directory structure.'.format(UPLOAD_URI))
                    # split file path into parts to cut any part before encrypted folder
                    file_path = pathlib.Path(file.path)
                    file_path_parts = file_path.parts
                    start_idx = file_path_parts.index('encrypted')
                    folders_parts = file_path_parts[start_idx+1:-1]
                    # create directories structure
                    prev_part = ''
                    for part in folders_parts:
                        prev_part = join(prev_part, part).replace('\\', '/')
                        conn.mkdir(prev_part)
                    log(1, 'Directories structure build on server: {0}'.format(prev_part))
                    # build upload path and do upload
                    upload_path = '{0}{1}/{2}'.format('/' if not prev_part.startswith('/') else '', prev_part, file.name)
                    resp, content = conn.upload_file(file.path, path=upload_path)
                    code, operation_info = response_parse(resp, content)
                    log(code, 'Uploading file {0} result: {1}'.format(file.name, operation_info))
                    if code == 3:
                        sys.exit(-1)
                else:
                    upload_path = '/{0}'.format(file.name)
                    resp, content = conn.upload_file(file.path, path=upload_path)
                    code, operation_info = response_parse(resp, content)
                    log(code, 'Uploading file {0} result: {1}'.format(file.name, operation_info))
                    if code == 3:
                        sys.exit(-1)
        else:
            # look for files in upload folder
            for file in files:
                if SAVE_STRUCTURE:
                    log(1, 'save_structure set to True. Building directory structure.'.format(UPLOAD_URI))
                    # split file path into parts to cut any part before encrypted folder
                    file_path = pathlib.Path(file.path)
                    file_path_parts = file_path.parts
                    folders_parts = file_path_parts[1:-1]
                    # create directories structure
                    prev_part = ''
                    for part in folders_parts:
                        prev_part = join(prev_part, part).replace('\\', '/')
                        conn.mkdir(prev_part)
                    log(1, 'Directories structure build on server: {0}'.format(prev_part))
                    # build upload path and do upload
                    upload_path = '{0}{1}/{2}'.format('/' if not prev_part.startswith('/') else '', prev_part, file.name)
                    resp, content = conn.upload_file(file.path, path=upload_path)
                    code, operation_info = response_parse(resp, content)
                    log(code, 'Uploading file {0} result: {1}'.format(file.name, operation_info))
                    if code == 3:
                        sys.exit(-1)
                else:
                    upload_path = '/{0}'.format(file.name)
                    resp, content = conn.upload_file(file.path, path=upload_path)
                    code, operation_info = response_parse(resp, content)
                    log(code, 'Uploading file {0} result: {1}'.format(file.name, operation_info))
                    if code == 3:
                        sys.exit(-1)

        if DELETE_ORIGIN:
            for obj in files:
                if os.path.exists(obj.path):
                    if obj.is_dir:
                        file_path = pathlib.Path(obj.path)
                        file_path_parts = file_path.parts
                        folders_path = join('', *file_path_parts[:-1])
                        try:
                            shutil.rmtree(folders_path)
                        except FileNotFoundError as err:
                            log(3, 'Directory {0} not found. Passing through... Error: '.format(folders_path, err))
                        except FileExistsError as err:
                            log(3, 'Directory {0} not exists. Passing through... Error: '.format(folders_path, err))
                    elif obj.is_file:
                        try:
                            os.remove(obj.path)
                        except Exception as err:
                            log(3, 'File {0} deletion error. Passing through... Error: '.format(obj.path, err))

        if not DELETE_ORIGIN:
            if (DELETE_ENCRYPTED and ENCRYPT) or FORCE_ERRORS:
                for obj in encrypted_files:
                    if os.path.exists(obj.path):
                        if obj.is_dir:
                            file_path = pathlib.Path(obj.path)
                            file_path_parts = file_path.parts
                            folders_path = join('', *file_path_parts[:-1])
                            shutil.rmtree(folders_path)
                        elif obj.is_file:
                            try:
                                os.remove(obj.path)
                            except Exception as err:
                                log(3, 'File {0} deletion error. Passing through... Error: '.format(obj.path, err))
    sys.exit(0)