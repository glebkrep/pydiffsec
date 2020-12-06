import os
import pathlib

import utils


# <filesystem host="mysys" dir="."> 
# <new>./analyze/Project1/fd2.bck</new> 
# <relocated orig="./farm.sh">./analyze/Project1/farm2.sh</relocated> 
# <changed>./caveat.sample.ch</changed> 
# <removed>./x.x</removed> 
# </filesystem>


class FileHash:
    def __init__(self, absolute_file_path, file_hash):
        self.path = absolute_file_path
        self.hash = file_hash


class SysHashOutput:
    def __init__(self, hashing_directory, file_hashes):
        self.file_hashes = file_hashes
        self.hashing_directory = hashing_directory

        # 0 - success
        # 1 - error:different directories were hashed


class OutputDiff:
    def __init__(self, resultCode, unchanged_files, new_files, changed_files, removed_files, moved_files):
        self.result = resultCode
        self.unchanged_files = unchanged_files
        self.new_files = new_files
        self.changed_files = changed_files
        self.removed_files = removed_files
        self.moved_files = moved_files


class Constants:
    TEST_CONST_HASHING_DIRECTORY = r"/Users/gleb/PycharmProjects/pythonProject/"
    CONST_SPLITTER = "  ::  "
    CONST_DEF_BASE_FILE_NAME = 'basefile'
    CONST_DEF_BASE_FILE_DIRECTORY = "/basefile/"
    CONST_DEF_COMPARE_FILE_NAME = 'compare'
    CONST_DEF_COMPARE_FILE_DIRECTORY = "/basefile/"


def create_base_file(hashing_directory,
                     base_file_directory=str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY):
    base_file_name = Constants.CONST_DEF_BASE_FILE_NAME
    file_hash_list = list()
    for file in utils.get_all_files_in_directory(hashing_directory):
        file_hash_list.append(FileHash(file, utils.get_sha1_of_file(file)))
    base_file = utils.get_base_file(base_file_name, base_file_directory, "w")
    base_file.write(hashing_directory + "\n")
    file_hash_list.sort(key=lambda x: x.path)
    for file_hash in file_hash_list:
        base_file.write(file_hash.path + Constants.CONST_SPLITTER + file_hash.hash + "\n")
    base_file.close()


def get_file_hash_from_base_file(base_file_name=Constants.CONST_DEF_BASE_FILE_NAME,
                                 base_file_directory=str(
                                     pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY):
    file_hash_list = list()
    base_file = utils.get_base_file(base_file_name, base_file_directory, "r")
    lines = base_file.readlines()
    hashing_directory = lines[0].strip()
    lines = lines[1:]
    for line in lines:
        file_hash = line.strip().split(Constants.CONST_SPLITTER)
        file_hash_list.append(FileHash(file_hash[0], file_hash[1]))
    return SysHashOutput(hashing_directory, file_hash_list)


def create_compare_file(hashing_directory, base_file_directory=str(
    pathlib.Path().absolute()) + Constants.CONST_DEF_COMPARE_FILE_DIRECTORY):
    compare_file_name = Constants.CONST_DEF_COMPARE_FILE_NAME
    file_hash_list = list()
    for file in utils.get_all_files_in_directory(hashing_directory):
        file_hash_list.append(FileHash(file, utils.get_sha1_of_file(file)))
    base_file = utils.get_base_file(compare_file_name, base_file_directory, "w")
    base_file.write(hashing_directory + "\n")
    file_hash_list.sort(key=lambda x: x.path)
    for file_hash in file_hash_list:
        base_file.write(file_hash.path + Constants.CONST_SPLITTER + file_hash.hash + "\n")
    base_file.close()
    return base_file


def get_dif_sys_output(previous_output, current_output):
    if previous_output.hashing_directory != current_output.hashing_directory:
        return OutputDiff(1, 1, 1, 1, 1)
    unchanged_files = list()
    changed_files = list()
    removed_files = list()
    new_files = list()
    prev_id = 0
    curr_id = 0

    while len(previous_output.file_hashes) - 1 >= prev_id or len(current_output.file_hashes) - 1 >= curr_id:
        if len(previous_output.file_hashes) - 1 < prev_id:
            new_files.append(current_output.file_hashes[curr_id])
            curr_id += 1
            continue
        elif len(current_output.file_hashes) - 1 < curr_id:
            removed_files.append(previous_output.file_hashes[prev_id])
            prev_id += 1
            continue

        prev_item = previous_output.file_hashes[prev_id]
        curr_item = current_output.file_hashes[curr_id]

        if prev_item.path == curr_item.path:
            if prev_item.hash == curr_item.hash:
                unchanged_files.append(prev_item)
            else:
                changed_files.append(prev_item)
            prev_id += 1
            curr_id += 1
            continue
        if min(prev_item.path, curr_item.path) == prev_item.path:
            removed_files.append(prev_item)
            prev_id += 1
            continue
        else:
            new_files.append(curr_item)
            curr_id += 1
            continue

    moved_files = list()
    new_files_dict = dict()
    for new_file in new_files:
        new_files_dict[new_file.hash] = new_file.path
    for file in removed_files:
        if file.hash in new_files_dict:
            moved_files.append((file, new_files_dict[file.hash]))
            removed_files.remove(file)
            #todo remove after testing
            print("TEST")
            print("new files:")
            for new_file in new_files:
                if new_file.path ==new_files_dict[file.hash] and new_file.hash ==file.hash:
                    new_files.remove(new_file)
    return OutputDiff(0, unchanged_files, new_files, changed_files, removed_files, moved_files)


# def form_report(diff_sys_output):


def main():
    # create_base_file(Constants.TEST_CONST_HASHING_DIRECTORY)
    # file_sys_hash = get_file_hash_from_base_file()
    # print(file_sys_hash.hashing_directory)
    # print(file_sys_hash.file_hashes)
    #create_base_file(Constants.TEST_CONST_HASHING_DIRECTORY)
    sys_hash_output = get_file_hash_from_base_file()
    compare_hash_output = get_file_hash_from_base_file(create_compare_file(sys_hash_output.hashing_directory).name, "")
    diff = get_dif_sys_output(sys_hash_output, compare_hash_output)
    print(diff.result)
    print("unchanged:")
    for file in diff.unchanged_files:
        print(file.path)
    print("changed:")
    for file in diff.changed_files:
        print(file.path)
    print("removed:")
    for file in diff.removed_files:
        print(file.path)
    print("new:")
    for file in diff.new_files:
        print(file.path)
    print("moved:")
    for file in diff.moved_files:
        print(file[0].path + " <- old new -> "+ file[1])

if __name__ == '__main__':
    main()
