import os
import pathlib

import utils


def create_base_file(hashingDirectory, base_file_name='basefile', base_file_directory=str(pathlib.Path().absolute())):
    #base_file = utils.get_base_file(base_file_name, base_file_directory)

    file_hash_list = list()

    for file in os.listdir(hashingDirectory):
        full_path = hashingDirectory+file
        print(full_path)
        file_hash_list.append(FileHash(full_path,utils.get_sha1_of_file(full_path)))



def main():
#    file = utils.get_base_file("blahblah", r"/Users/gleb/PycharmProjects/pythonProject/newFolder/")
    create_base_file(r"/Users/gleb/PycharmProjects/pythonProject/")
    #file.close()

class FileHash:
    def __init__(self,absolute_file_path,file_hash):
        self.path = absolute_file_path
        self.hash = file_hash


if __name__ == '__main__':
    main()
