import os
import sys

import pefile


def get_apis_from_dlls(dll_path):
    apis = []
    for dll in os.listdir(dll_path):
        print(f'Reading exported symbols from {dll}')
        f_path = os.path.join(dll_path, dll)
        pe = pefile.PE(f_path)
        res = []
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp and exp.name:
                res.append(exp.name.decode().replace('@', '').replace('?',''))
                apis.append(dll + '!' + exp.name.decode().replace('@', '').replace('?',''))
    return apis


def main():
    if len(sys.argv) != 2:
        print('Usage: generate_api_list.py path_to_dlls')
        sys.exit(1)

    apis = get_apis_from_dlls(sys.argv[1])

    with open('custom_apis.txt', 'w') as f:
        for api in apis:
            f.write(api + '\n')


if __name__ == '__main__':
    main()
