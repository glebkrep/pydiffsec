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
def get_file(base_file_name, absolute_file_path='', mode='a', ext=".txt"):
    # todo if already contains .txt dont add that
    full_file_name = absolute_file_path + base_file_name
    if ext not in base_file_name:
        full_file_name += ext

    os.makedirs(os.path.dirname(full_file_name), exist_ok=True)
    return open(full_file_name, mode)


def get_all_files_in_directory(directory):
    listOfFile = os.listdir(directory)
    allFiles = list()
    # Iterate over all the entries
    for entry in listOfFile:
        # Create full path
        fullPath = os.path.join(directory, entry)
        # If entry is a directory then get the list of files in this directory
        if os.path.isdir(fullPath):
            allFiles = allFiles + get_all_files_in_directory(fullPath)
        else:
            allFiles.append(fullPath)
    return allFiles
