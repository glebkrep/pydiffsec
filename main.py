import hashlib
import os
import pathlib
from xml.dom import minidom
from xml.etree.ElementTree import Element, SubElement, Comment, tostring
import sys


# UTILS:
# gets sha1 of file... -_-
def get_sha1_of_file(file_path):
    print(file_path)
    h = hashlib.sha1()
    # чтобы не тратить 1 к 1 физическую:оперативную память будем чанковать файлы
    b = bytearray(128 * 1024)
    mv = memoryview(b)
    with open(file_path, 'rb', buffering=0) as f:
        for n in iter(lambda: f.readinto(mv), 0):
            h.update(mv[:n])
    return h.hexdigest()


# creates base file in specified directory which will store current hashes of files in path
# a - append
# w - overwrite
def get_file(base_file_name, absolute_file_path='', mode='a', ext=".txt", overwrite=True):
    full_file_name = absolute_file_path + base_file_name
    if ext not in base_file_name:
        full_file_name += ext
    if pathlib.Path(full_file_name).is_file() and overwrite == False:
        if "y" in input(full_file_name + " file already exists, overwrite? [y/n]: ..."):
            return get_file(base_file_name, absolute_file_path, mode, ext, True)
        else:
            return False
    os.makedirs(os.path.dirname(full_file_name), exist_ok=True)
    return open(full_file_name, mode)


def get_all_files_in_directory(directory):
    list_of_file = os.listdir(directory)
    all_files = list()
    # Iterate over all the entries
    for entry in list_of_file:
        # Create full path
        full_path = os.path.join(directory, entry)
        # If entry is a directory then get the list of files in this directory
        if os.path.isdir(full_path):
            all_files = all_files + get_all_files_in_directory(full_path)
        else:
            all_files.append(full_path)
    return all_files


# ----

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
    def __init__(self, result_code, unchanged_files, new_files, changed_files, removed_files, moved_files):
        self.result = result_code
        self.unchanged_files = unchanged_files
        self.new_files = new_files
        self.changed_files = changed_files
        self.removed_files = removed_files
        self.moved_files = moved_files


class Constants:
    # TEST_CONST_HASHING_DIRECTORY = r"/Users/gleb/PycharmProjects/pythonProject/"
    CONST_SPLITTER = "  ::  "
    CONST_DEF_BASE_FILE_NAME = 'basefile'
    CONST_DEF_BASE_FILE_DIRECTORY = "/basefile/"
    CONST_DEF_COMPARE_FILE_NAME = 'compare'
    CONST_DEF_COMPARE_FILE_DIRECTORY = "/basefile/"


def create_base_file(hashing_directory,
                     base_file_directory=str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY):
    base_file_name = Constants.CONST_DEF_BASE_FILE_NAME
    file_hash_list = list()
    for file in get_all_files_in_directory(hashing_directory):
        file_hash_list.append(FileHash(file, get_sha1_of_file(file)))
    base_file = get_file(base_file_name, base_file_directory, "w", overwrite=False)
    if base_file == False:
        print("Execution stopped; can't continue without rewriting file")
        return
    base_file.write(hashing_directory + "\n")
    file_hash_list.sort(key=lambda x: x.path)
    for file_hash in file_hash_list:
        base_file.write(file_hash.path + Constants.CONST_SPLITTER + file_hash.hash + "\n")
    base_file.close()
    print("base file created: " + base_file.name)


def get_file_hash_from_base_file(base_file_name=Constants.CONST_DEF_BASE_FILE_NAME,
                                 base_file_directory=str(
                                     pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY):
    file_hash_list = list()
    try:
        base_file = get_file(base_file_name, base_file_directory, "r")
    except FileNotFoundError:
        print("There is no " + Constants.CONST_DEF_BASE_FILE_NAME + " in " + base_file_directory)
        exit()
        return False
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
    for file in get_all_files_in_directory(hashing_directory):
        file_hash_list.append(FileHash(file, get_sha1_of_file(file)))
    base_file = get_file(compare_file_name, base_file_directory, "w")
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
            for new_file in new_files:
                if new_file.path == new_files_dict[file.hash] and new_file.hash == file.hash:
                    new_files.remove(new_file)
    return OutputDiff(0, unchanged_files, new_files, changed_files, removed_files, moved_files)


def create_report_file(diff_sys_output, mode="xml",
                       report_file_dir=str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY,
                       path_rel_abs='a',
                       hash_dir=pathlib.Path().absolute()):
    if mode == "xml":
        top = Element('report', hash_dir=hash_dir)

        comment = Comment('Generated by pydiffsec')
        comment.tail = "\n"
        top.append(comment)

        unchanged = SubElement(top, 'unchanged_files',
                               count=str(len(diff_sys_output.unchanged_files)))
        for unchanged_file in diff_sys_output.unchanged_files:
            elem = Element("item", path=get_report_path(path_rel_abs, unchanged_file.path, hash_dir))
            unchanged.append(elem)

        changed = SubElement(top, 'changed_files', count=str(len(diff_sys_output.changed_files)))
        for changed_file in diff_sys_output.changed_files:
            changed.append(Element("item", path=get_report_path(path_rel_abs, changed_file.path, hash_dir)))

        removed = SubElement(top, 'removed_files', count=str(len(diff_sys_output.removed_files)))
        for removed_file in diff_sys_output.removed_files:
            removed.append(Element("item", path=get_report_path(path_rel_abs, removed_file.path, hash_dir)))

        new = SubElement(top, 'new_files', count=str(len(diff_sys_output.new_files)))
        for new_file in diff_sys_output.new_files:
            new.append(Element("item", path=get_report_path(path_rel_abs, new_file.path, hash_dir)))

        moved = SubElement(top, 'moved_files', count=str(len(diff_sys_output.moved_files)))
        for moved_file in diff_sys_output.moved_files:
            moved_element = Element("item", old_path=get_report_path(path_rel_abs, moved_file[0].path, hash_dir),
                                    new_path=get_report_path(path_rel_abs, moved_file[1], hash_dir))
            moved.append(moved_element)

        report_file = get_file("report.xml", report_file_dir, "w", ".xml")
        report_file.write(prettify_xml(top))
        report_file.close()
        print("report xml file created: " + report_file.name)

    if mode == "txt":
        report = "Generated by pydiffsec\n"
        report += "Hash directory: " + hash_dir + "\n"
        report += "\tunchanged files:\n"
        for file in diff_sys_output.unchanged_files:
            report += "\t\t" + get_report_path(path_rel_abs, file.path, hash_dir) + "\n"
        report += "\tchanged files:\n"
        for file in diff_sys_output.changed_files:
            report += "\t\t" + get_report_path(path_rel_abs, file.path, hash_dir) + "\n"
        report += "\tremoved files:\n"
        for file in diff_sys_output.removed_files:
            report += "\t\t" + get_report_path(path_rel_abs, file.path, hash_dir) + "\n"
        report += "\tnew files:\n"
        for file in diff_sys_output.new_files:
            report += "\t\t" + get_report_path(path_rel_abs, file.path, hash_dir) + "\n"
        report += "\tmoved files:\n"
        for file in diff_sys_output.moved_files:
            report += "\t\t" + get_report_path(path_rel_abs, file[0].path, hash_dir) + " moved to " + get_report_path(
                path_rel_abs, file[1], hash_dir) + "\n"

        report_file = get_file("report.txt", report_file_dir, "w", ".txt")
        report_file.write(report)
        report_file.close()
        print("report txt file created: " + report_file.name)


def get_report_path(path_rel_abs, path, root_path):
    if path_rel_abs == "a":
        return path
    elif path_rel_abs == "r":
        output_path = path.replace(str(root_path), "")
        return output_path


def prettify_xml(elem):
    rough_string = tostring(elem, 'utf-8')
    reparsed = minidom.parseString(rough_string)
    return reparsed.toprettyxml(indent="  ")


def help_flow():
    print("PyDiffSec - скрипт, для контроля изменений файловой системы\n\n")
    print("Команды:\n\n")
    print("'help' - выводит сообщение с описанием комманд\n\n")
    print("'new [-d fileDir] [-hd hashDir]' - создание нового базового файла (запись sha1 хэшей всех файлов в "
          "выбранной директории)\n")
    print("\t [-d fileDir] - указание директории для создания базового файла (по умолчанию - текущая "
          "директория/basefile/)\n")
    print("\t [-hd hashDir] - указание директории, которую нужно хэшировать (по умолчанию - текущая директория)\n\n")

    print("'report [-rd reportFileDir] [-bd baseFileDir] [-r|-a pathInReport] [-xml|-txt reportFormat]' - создание "
          "нового отчета изменений файлов\n")
    print("\t [-rd reportFileDir] - указание директории для создания отчета (по умолчанию - текущая "
          "директория/basefile/)\n")
    print("\t [-bd baseFileDir] - указание директории, в которой находится базовый файл (по умолчанию - текущая "
          "директория/basefile/)\n\n")
    print("\t [-r|-a pathInReport] - выбор формата путей файлов в отчете (относительный|полный) (по умолчанию - "
          "полный)\n")
    print("\t [-xml|-txt reportFormat] - выбор формата отчета (по умолчанию - xml)\n\n")


def create_basefile_flow(arguments):
    if len(arguments) == 2:
        create_base_file(str(pathlib.Path().absolute()))
    elif len(arguments) > 2:
        file_dir = str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY
        hash_dir = str(pathlib.Path().absolute())
        next_arg = ""
        for argument in arguments[2:]:
            if next_arg == "-d":
                file_dir = argument
                next_arg = ""
                continue

            if next_arg == "-hd":
                hash_dir = argument
                next_arg = ""
                continue

            next_arg = argument
        if next_arg != "":
            if next_arg not in ["-d", "-hd"]:
                print("No argument " + next_arg + " found; type 'help' for help")
                return
            print("You wanted to put " + next_arg + " argument, but did not provide any value; type 'help' for help")
            return
        if file_dir[-1] != "/":
            file_dir += "/"
        create_base_file(hash_dir, file_dir)


def report_flow(arguments):
    report_file_dir = str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY
    base_file_dir = str(pathlib.Path().absolute()) + Constants.CONST_DEF_BASE_FILE_DIRECTORY
    path_rel_abs = "a"
    report_format = "xml"
    hash_dir = str(pathlib.Path().absolute())

    if len(arguments) == 2:
        sys_hash_output = get_file_hash_from_base_file(base_file_directory=base_file_dir)
        compare_hash_output = get_file_hash_from_base_file(create_compare_file(sys_hash_output.hashing_directory).name,
                                                           "")
        diff = get_dif_sys_output(sys_hash_output, compare_hash_output)
        create_report_file(diff, report_format, report_file_dir, path_rel_abs, hash_dir)
        return
    elif len(arguments) > 2:
        next_arg = ""
        for argument in arguments[2:]:
            if next_arg == "-rd":
                report_file_dir = argument
                next_arg = ""
                continue

            if next_arg == "-bd":
                base_file_dir = argument
                next_arg = ""
                continue

            if argument == "-r":
                path_rel_abs = "r"
                continue

            if argument == "-a":
                path_rel_abs = "a"
                continue

            if argument == "-xml":
                report_format = "xml"
                continue

            if argument == "-txt":
                report_format = "txt"
                continue

            next_arg = argument
        if next_arg != "":
            if next_arg not in ["-rd", "-bd"]:
                print("No argument " + next_arg + " found; type 'help' for help")
                return
            print("You wanted to put " + next_arg + " argument, but did not provide any value; type 'help' for help")
            return

        if report_file_dir[-1] != "/":
            report_file_dir += "/"
        if base_file_dir[-1] != "/":
            base_file_dir += "/"

        sys_hash_output = get_file_hash_from_base_file(base_file_directory=base_file_dir)
        compare_hash_output = get_file_hash_from_base_file(create_compare_file(sys_hash_output.hashing_directory).name,
                                                           "")
        diff = get_dif_sys_output(sys_hash_output, compare_hash_output)
        hash_dir = sys_hash_output.hashing_directory
        create_report_file(diff, report_format, report_file_dir, path_rel_abs, hash_dir)


def main():
    arguments = sys.argv
    if len(arguments) == 1 or arguments[1] == "help":
        help_flow()

    if len(arguments) > 1 and arguments[1] == "new":
        create_basefile_flow(arguments)

    if len(arguments) > 1 and arguments[1] == "report":
        report_flow(arguments)


if __name__ == '__main__':
    main()
