import sys
import os


def read_file_to_byte(file_path):
    '''
    Will read a file from the hex_dumps directory and return the byte array.
    Example Input: "939.txt"
    Example Output: byte_array 
    '''
    dir = sys.path[0]
    # print(dir)
    platform = sys.platform
    if platform == 'win32':
        dir = dir + f"\\hex_dumps\\{file_path}"
    else:
        dir = dir + f"/hex_dumps/{file_path}"
    with open(dir, "r") as f:
        data = f.read()
        data = data.strip().split('\n')
        result = []
        for i in data:
            i = i.split()[1:]
            print(i)
            result.extend(i)
        result = ''.join(result)
        result = bytearray.fromhex(result)
    return result

if __name__ == "__main__":
        
    print(read_file_to_byte("939.txt"))

