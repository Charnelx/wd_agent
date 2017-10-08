import os

try:
    from os import scandir
except ImportError:
    from scandir import scandir  # use scandir PyPI module on Python < 3.5


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