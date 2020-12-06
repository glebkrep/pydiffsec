import hashlib

import os


# gets sha1 of file... -_-
def get_sha1_of_file(file_path):
    h = hashlib.sha1()
    # чтобы не тратить 1 к 1 физическую:оперативную память будем чанковать файлы
    b = bytearray(128 * 1024)
    # todo ???
    mv = memoryview(b)
    # todo open buffering?
    with open(file_path, 'rb', buffering=0) as f:
        # todo file.readinto(mv)?
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


# creates base file in specified directory which will store current hashes of files in path
# a - append
# w - overwrite
def get_base_file(base_file_name, absolute_file_path='', mode='a'):
    full_file_name = absolute_file_path + base_file_name + ".txt"
    os.makedirs(os.path.dirname(full_file_name), exist_ok=True)
    with open(full_file_name, mode) as f:
        return f
