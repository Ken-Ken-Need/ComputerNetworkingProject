from segmenter import segmentedIPData


def hex2DecIp(hex_str: str):
    if len(hex_str) != 8:
        raise ValueError

    dec_ls = []
    for i in range(0, 8, 2):
        sub = hex_str[i : i + 2]
        dec_ls.append(str(int("0x" + sub, 16)))
    dec = ".".join(dec_ls)

    return dec


def decodeIPData(data: segmentedIPData):
    data["Destination IP"] = hex2DecIp(data["Destination IP"])
    data["Source IP"] = hex2DecIp(data["Source IP"])
    return data
