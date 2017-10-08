import argparse
import configparser
from collections import OrderedDict
import datetime
import logging
import os
from os.path import join
import re
import shutil
import socket
import sys
from urllib.parse import urlparse

# try:
#     from os import scandir
# except ImportError:
#     from scandir import scandir  # use scandir PyPI module on Python < 3.5

try:
    from typing import Any
except ImportError:
    Any = object

import keyring
import pathlib
from msvcrt import getch
import getpass

from agent_base import AgentBase
from agent_base import NoKeyFileException, NoFilesToProcess, EncryptionError
from helpers.utils import scan_tree
import python_webdav.client
from Pycrypt.Crypto import RSAcrypt, AEScrypt

# Basic constants
BASE_DIR = os.path.dirname(sys.argv[0])
CONFIG_FILE_NAME = '.cfg'
CREDENTIALS_FILE_NAME = 'credentials.file'
ENCRYPT_FOLDER_NAME = 'encrypted'
MASTER_KEY_NAME = 'master.key'
PUBLIC_KEY_NAME = 'pubkey.der'
TEMP_FILE_EXTENSION = '.tmp'

# Encryption constants
HEADER_SIZE = 128
READ_CHUNK_SIZE = 16384


class Agent(AgentBase):

    def __init__(self,
                 file_location=None,
                 upload_uri=None,
                 upload_dir=None,
                 structure_save=False,
                 last_only=True,
                 upload=False,
                 delete_origin=False,
                 delete_encrypted=False,
                 encrypt=True,
                 force_errors=False):

        self.file_location = file_location
        self.upload_uri = upload_uri
        self.upload_dir = upload_dir if upload_dir else '/'
        self.structure_save = structure_save
        self.last_only = last_only
        self.upload = upload
        self.delete_origin = delete_origin
        self.delete_encrypted = delete_encrypted
        self.encrypt = encrypt
        self.force_errors = force_errors

        self.STAGES = OrderedDict([ ('credentials', True),
                                    ('encrypt', self.encrypt),
                                    ('upload', self.upload),
                                    ('delete', self.delete_origin or self.delete_encrypted),
        ])

    def run(self) -> (bool, Any):
        """
        This method starts the pipeline of operations specified by Agent configuration.
        Each operation is isolated - all manipulations are performed with i/o or system
        but not between other methods.
        The only way methods can communicate with each other - return values.
        Each stage method must accept previous method evaluation result as first argument.
        No other type of connection is reasonable.
        :return: (bool, Any), True if all stages finished with success, else False; last stage result
        """
        result = None
        for stage, active in self.STAGES.items():
            if active:
                method_name = 'stage_{}'.format(stage)
                try:
                    method = getattr(self, method_name)
                    result = method(result)
                except Exception as err:
                    logger.error('[{}] Program now exit because method "{}" raised error: {}'.format(
                        err.__class__.__name__, method_name, err))
                    sys.exit(-1)
                else:
                    logger.info('stage "{}" completed successfully'.format(stage))
        return True, result

    def stage_credentials(self, *args):
        logger.info('credentials stage started')
        master_key_path = os.path.abspath(join(BASE_DIR, MASTER_KEY_NAME))
        public_key_path = os.path.abspath(join(BASE_DIR, PUBLIC_KEY_NAME))
        credentials_file_path = os.path.abspath(join(BASE_DIR, CREDENTIALS_FILE_NAME))

        if not os.path.exists(master_key_path):
            raise NoKeyFileException ('invalid path to masterkey or file does not exists: {}'.format(
                master_key_path))
        if not os.path.exists(public_key_path):
            raise NoKeyFileException ('invalid path to pubkey or file does not exists: {}'.format(
                public_key_path))
        if not os.path.exists(credentials_file_path):
            raise NoKeyFileException ('invalid path to credentials or file does not exists: {}'.format(
                credentials_file_path))

        with open(master_key_path, 'rb') as master_key_file:
            master_key = master_key_file.read().decode('utf-8')

        with open(public_key_path, 'rb') as public_key_file:
            public_key = public_key_file.read()

        with open(credentials_file_path, 'rb') as credentials_file:
            credentials = AEScrypt.decrypt_to_mem(credentials_file, master_key)

        try:
            remote_user, remote_password = [c.rstrip() for c in credentials.split('\n') if c]
        except ValueError:
            raise ValueError('unable to parse or decrypt credentials file. Wrong master key or file is corrupted')

        return master_key, public_key, remote_user, remote_password

    def stage_encrypt(self, *args):

        try:
            master_key, public_key, remote_user, remote_password = args[0]
        except ValueError:
            raise ValueError('failed to retrieve credentials from credentials stage')

        logger.info('file_location path: {}'.format(self.file_location))
        if not self.file_location:
            raise AttributeError('path to files are not specified for processing. Aborting.')

        files = sorted([file for file in scan_tree(self.file_location)], key=lambda file: file.stat().st_ctime,
                       reverse=True)

        if not files:
            raise NoFilesToProcess('no files to process in {}'.format(self.file_location))

        if self.last_only:
            files = files[:1]

        encryption_dir = os.path.abspath(join(self.file_location, ENCRYPT_FOLDER_NAME))

        if not os.path.exists(encryption_dir):
            logger.debug('encrypted files folder created at: {}'.format(encryption_dir))
            os.makedirs(encryption_dir)

        logger.info('folders structure save: {}'.format(self.structure_save))

        crypto = RSAcrypt()

        for file in files:
            filename, extension = os.path.splitext(os.path.basename(file.name))
            extension = extension[1:]

            if extension == 'aes':
                logger.info('file ignored due to the extension: {}'.format(file))
                continue

            new_filename = '{0}.{1}.aes'.format(filename, extension)

            if self.structure_save:
                file_path = pathlib.Path(file.path)
                path_structure = file_path.parts[1:-1]
                encrypted_file_path = os.path.abspath(join(encryption_dir, *path_structure))

                # create dirs structure; ignore if already exists
                try:
                    os.makedirs(encrypted_file_path, mode=0o777)
                    logger.debug('folder created at: {}'.format(encrypted_file_path))
                except FileExistsError:
                    logger.debug('folders structure for encrypted files already exists - skipping: {}'.format(
                        encrypted_file_path))
            else:
                encrypted_file_path = encryption_dir

            full_file_path = os.path.abspath(join(encrypted_file_path, new_filename))

            ##############################
            # Start of encryption process#
            ##############################

            logger.info('start to encrypt file "{}" with AES'.format(file))

            # encrypt whole file with AES
            try:
                with open(file.path, mode='rb') as in_file_object, open(full_file_path, mode='wb') as out_file_object:
                    AEScrypt.encrypt(in_file_object, out_file_object, master_key, key_length=32)
            except Exception:
                raise EncryptionError('error occurred during full AES file encryption. File - {}'.format(file))

            logger.info('file "{}" successfully encrypted with AES'.format(file))
            logger.info('adding RSA signature to file "{}"'.format(file))

            # Encrypts *HEADER_SIZE bytes of file with RSA public key
            try:
                with open(full_file_path, 'rb') as encrypted_file:
                    block = encrypted_file.read(HEADER_SIZE)

                    logger.debug('adding RSA signature to file {}'.format(file))

                    chipertext = crypto.encrypt_psw(block, public_key)

                    # Write HEADER + RSA_ENCRYPTED_BLOCK + AES_ENCRYPTED_PART to file
                    size = len(chipertext)
                    bias = str(size).ljust(HEADER_SIZE, '0').encode()

                    encrypted_file.seek(0)

                    logger.debug('creating temp file')

                    with open(full_file_path + TEMP_FILE_EXTENSION, 'ab') as temp_file:
                        temp_file.write(bias + chipertext)

                        encrypted_file.seek(HEADER_SIZE)

                        while True:
                            chunk = encrypted_file.read(READ_CHUNK_SIZE)
                            if not chunk:
                                break
                            temp_file.write(chunk)

                logger.debug('deleting AES encrypted file')
                os.remove(full_file_path)

                logger.debug('replacing AES encrypted file by fully encrypted')
                os.rename(full_file_path + TEMP_FILE_EXTENSION, full_file_path)

                logger.info('file "{}" successfully encrypted!'.format(file))
            except Exception:
                raise EncryptionError('error occurred during add of RSA signature')

        logger.info('all files encrypted successfully!')

        return encryption_dir


    def stage_upload(self, *args):
        pass

    def stage_delete(self, *args):
        pass

if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)

    log_formatter = logging.Formatter('[%(asctime)s](App: %(name)s)<Level: %(levelname)s>: %(message)s')

    # log file handler
    file_handler = logging.FileHandler('dev_log.log')
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(log_formatter)

    # console output handler
    con_handler = logging.StreamHandler()
    con_handler.setLevel(logging.INFO)
    con_handler.setFormatter(log_formatter)

    # add the handlers to the logger
    logger.addHandler(file_handler)
    logger.addHandler(con_handler)

    a = Agent(file_location='E:\Photos\Chernivtsi_609', last_only=True)
    a.run()