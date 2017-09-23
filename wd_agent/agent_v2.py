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

try:
    from os import scandir
except ImportError:
    from scandir import scandir  # use scandir PyPI module on Python < 3.5

try:
    from typing import Any
except ImportError:
    Any = object

import keyring
import pathlib
from msvcrt import getch
import getpass

from agent_base import AgentBase
import python_webdav.client
from Pycrypt.Crypto import RSAcrypt, AEScrypt

# Basic constants
BASE_DIR = os.path.dirname(sys.argv[0])
CONFIG_FILE_NAME = '.cfg'
TEMP_FILE_EXTENSION = '.tmp'
ENCRYPT_FOLDER_NAME = 'encrypted'

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
                    logger.error('Program now exit because method "{}" raised error: {}.'.format(method_name, err))
                    sys.exit(-1)
                else:
                    logger.info('stage "{}" completed successfully'.format(stage))
        return True, result

    def stage_credentials(self, *args):
        logger.info('credentials stage started')
        master_key_path = join(BASE_DIR, 'master.key')
        public_key_path = join(BASE_DIR, 'pubkey.der')

        if not os.path.exists(master_key_path):
            logger.warning('unable to locate master key file')
        elif not os.path.exists(public_key_path):
            logger.warning('unable to locate public key file.')

        # TODO: open and decode files containing encryption password and remote credentials

    def stage_encrypt(self, *args):
        pass

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

    a = Agent()
    a.run()