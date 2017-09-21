import argparse
import configparser
from collections import OrderedDict
import datetime
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

import keyring
import pathlib
from msvcrt import getch
import getpass

from agent_base import AgentBase
import python_webdav.client
from Pycrypt.Crypto import RSAcrypt, AEScrypt

BASE_DIR = os.path.dirname(sys.argv[0])
CONFIG_FILE_NAME = '.cfg'
TEMP_FILE_EXTENSION = '.tmp'
ENCRYPT_FOLDER_NAME = 'encrypted'

# FILES_LOCATION = None
# UPLOAD_URI = None
# UPLOAD_DIRECTORY = '/'
# SAVE_STRUCTURE = False
# ONLY_LAST = True
# UPLOAD = False
# DELETE_ORIGIN = False
# DELETE_ENCRYPTED = False
# ENCRYPT = True
# FORCE_ERRORS = False

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
                                    ('delete', self.delete_origin or self.delete_encrypted)
        ])


    def run(self):
        result = None
        for stage, active in self.STAGES.items():
            if active:
                method_name = 'stage_{}'.format(stage)
                try:
                    method = getattr(self, method_name)
                    result = method(result)
                except:
                    assert False, 'Implement proper exception handling'

    def stage_credentials(self, *args):
        pass

    def stage_encrypt(self, *args):
        pass

    def stage_upload(self, *args):
        pass

    def stage_delete(self, *args):
        pass

if __name__ == '__main__':
    a = Agent()
    a.run()