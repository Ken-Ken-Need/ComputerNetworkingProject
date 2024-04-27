import yaml


def read_file_to_byte(file_path):
    with open(file_path, "r") as f:
        data = f.read()
        data = data.strip().split("\n")
        result = []
        for i in data:
            i = i.split()[1:]
            result.extend(i)
        result = "".join(result)
        result = bytearray.fromhex(result)
    return result


def write_byte_to_file(file_path, data):
    with open(file_path, "w") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False, indent=2)
