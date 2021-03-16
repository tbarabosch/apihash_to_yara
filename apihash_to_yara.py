import argparse

import hash_functions


def read_windows_apis(path_api_names):
    with open(path_api_names) as f:
        tmp = []
        d = [x.strip() for x in f.readlines()]
        for api in d:
            tmp.append((api.split('!')[1], api.split('!')[0]))
            tmp.append((api.split('!')[1] + 'A', api.split('!')[0]))
            tmp.append((api.split('!')[1] + 'W', api.split('!')[0]))

        return tmp


def hash_to_bytes(h):
    t = hex(h)[2:]
    if len(t) < 8:
        t = '0' * (8 - len(t)) + t
    t = t[0:2] + " " + t[2:4] + " " + t[4:6] + " " + t[6:]
    return t


def hash_to_bytes_little(h):
    t = hex(h)[2:]
    if len(t) < 8:
        t = '0' * (8 - len(t)) + t
    t = t[6:] + " " + t[4:6] + " " + t[2:4] + " " + t[0:2]
    return t


def generate_yara_rule(hash_result, yara_condition_match_threshold, yara_condition_filesize_threshold):
    print(f'Generating YARA rule for {hash_result[0]}')
    rule = 'rule api_hashes_' + hash_result[0] + ' {\n'
    rule += '\tmeta:\n\t\tauthor = "Thomas Barabosch"\n\t\treference1 = "https://0xc0decafe.com/apihash-to-yara/"\n'
    rule += '\t\treference2 = "https://github.com/tbarabosch/apihash_to_yara"\n'
    rule += '\t\treference3 = "https://github.com/fireeye/flare-ida/tree/master/shellcode_hashes"\n\t\treference4 = "https://malpedia.caad.fkie.fraunhofer.de/stats/api_usage"\n'
    rule += f'\t\tapi_count = "{len(hash_result[1])}"\n\t\tyara_condition_match_threshold = "{yara_condition_match_threshold}"\n'
    rule += f'\t\tyara_condition_filesize_threshold = "{yara_condition_filesize_threshold}"\n'
    rule += '\tstrings:\n'
    for h in hash_result[1]:
        rule += '\t\t$' + h[1].replace('.', '_') + '_' + h[0].replace('.', '_') + ' = { ' + hash_to_bytes(h[2]) + ' }\n'
        rule += '\t\t$' + h[1].replace('.', '_') + '_' + h[0].replace('.', '_') + '_little_endian = { ' + hash_to_bytes_little(h[2]) + ' }\n'
    rule += '\tcondition:\n\t\t' + str(yara_condition_match_threshold) + ' of them'
    rule += ' and filesize < ' + str(yara_condition_filesize_threshold) + 'KB\n}\n\n'
    return rule


def generate_yara_rules(results, yara_condition_match_threshold, yara_condition_filesize_threshold):
    rules = []
    for hashes in results:
        rules.append(generate_yara_rule(hashes,
                                        yara_condition_match_threshold,
                                        yara_condition_filesize_threshold))
    return rules


def generate_hashes(apis):
    res = []
    for h in hash_functions.HASH_TYPES:
        print(f'Generating hash {h[0]} for {len(apis)} APIs')
        h_res = []
        for api in apis:
            c_hash = h[1](api[0], api[1])
            if c_hash < 0x10000:
                continue
            h_res.append((api[0], api[1], c_hash))
        res.append((h[0], h_res))
    return res


def save_rules(rules, path):
    with open(path, 'w') as f:
        for rule in rules:
            f.write(rule)


def generate_yara(path_api_names, output_path, yara_condition_match_threshold, yara_condition_filesize_threshold):
    windows_apis = read_windows_apis(path_api_names)
    hash_result = generate_hashes(windows_apis)
    yara_rules = generate_yara_rules(hash_result,
                                     yara_condition_match_threshold,
                                     yara_condition_filesize_threshold)
    save_rules(yara_rules, output_path)


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("path_api_names",
                        help="Path to list of API names")
    parser.add_argument("output",
                        help="Path to output")
    parser.add_argument("--yara_condition_match_threshold",
                        help="Threshold of required matches in YARA condition",
                        default=10,
                        type=int)
    parser.add_argument("--yara_condition_filesize_threshold",
                        help="Filesize threshold of required matches in YARA condition",
                        default=1024,
                        type=int)
    args = parser.parse_args()
    return args


def main():
    args = parse_args()
    generate_yara(args.path_api_names,
                  args.output,
                  args.yara_condition_match_threshold,
                  args.yara_condition_filesize_threshold)


if __name__ == '__main__':
    main()
