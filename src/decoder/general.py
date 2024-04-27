from segmenter import segmentedIPData, segmentedEthernetData


def lookUpInDict(lookUpDict: dict, key: object):
    return lookUpDict.get(key, "Unknown")


def hex2DecIp(hex_str: str):
    if len(hex_str) != 8:
        raise ValueError

    dec_ls = []
    for i in range(0, 8, 2):
        sub = hex_str[i : i + 2]
        dec_ls.append(str(int("0x" + sub, 16)))
    dec = ".".join(dec_ls)

    return dec


iPProtocalLookUp = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    58: "ICMPv6",
}

etherTypeLookUp = {
    "0800": "IPv4",
    "0806": "ARP",
    "86dd": "IPv6",
}


def decodeEthernetData(data: segmentedEthernetData):
    decodedData: dict = data.copy()  # type: ignore

    decodedData["Type"] = data["Type"] + " (" + etherTypeLookUp[data["Type"]] + ")"
    decodedData["Destination MAC"] = ":".join(
        [data["Destination MAC"][i : i + 2] for i in range(0, 12, 2)]
    )
    decodedData["Source MAC"] = ":".join(
        [data["Source MAC"][i : i + 2] for i in range(0, 12, 2)]
    )

    return decodedData


def decodeIPData(data: segmentedIPData):
    decodedData: dict = data.copy()  # type: ignore

    decodedData["Destination IP"] = hex2DecIp(data["Destination IP"])
    decodedData["Source IP"] = hex2DecIp(data["Source IP"])
    decodedData["Protocol"] = (
        str(data["Protocol"]) + " (" + iPProtocalLookUp[data["Protocol"]] + ")"
    )

    return decodedData
