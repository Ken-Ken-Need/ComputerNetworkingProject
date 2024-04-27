from typing import TypedDict
from typing import Union
from segmenter import segmentedDNSData
from decoder.general import lookUpInDict, hex2DecIp

dNSQuery = TypedDict(
    "dNSQuery",
    {
        "Query": str,
        "Type": str,
        "Class": str,
    },
)

dNSAnswer = TypedDict(
    "dNSAnswer",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Address": str,
    },
)

dNSAuthority = TypedDict(
    "dNSAuthority",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Primary Name Server": str,
        "Responsible Mail Address": str,
        "Serial Number": int,
        "Refresh Interval": int,
        "Retry Interval": int,
        "Expire Limit": int,
        "Minimum TTL": int,
    },
)

dNSAdditional = TypedDict(
    "dNSAdditional",
    {
        "Name": str,
        "Type": str,
        "Class": str,
        "TTL": int,
        "Data Length": int,
        "Address": str,
    },
)

decodedDNSRecords = (
    TypedDict(
        "decodedDNSRecords",
        {
            "Queries": Union[list[dNSQuery], None],
            "Answers": Union[list[dNSAnswer], None],
            "Authority Servers": Union[list[dNSAuthority], None],
            "Additional Records": Union[list[dNSAdditional], None],
        },
    ),
)


def bytearray_to_string(byte_array: bytearray):
    return byte_array.decode("utf-8")


def hex_to_binary(hex_string):
    binary_string = ""
    hex_to_bin_mapping = {
        "0": "0000",
        "1": "0001",
        "2": "0010",
        "3": "0011",
        "4": "0100",
        "5": "0101",
        "6": "0110",
        "7": "0111",
        "8": "1000",
        "9": "1001",
        "A": "1010",
        "B": "1011",
        "C": "1100",
        "D": "1101",
        "E": "1110",
        "F": "1111",
    }
    hex_string = hex_string.lstrip("0x")
    for char in hex_string:
        char_upper = char.upper()
        binary_string += hex_to_bin_mapping.get(char_upper, "")
    return binary_string


def decodeFlag(binary_representation: str):
    Flags = {}

    if binary_representation[0] == 0:
        Flags["Response"] = "Query"
    else:
        Flags["Response"] = "Response"

    opcode = binary_representation[1:5]
    if opcode == "0000":
        Flags["Opcode"] = "Standard query"
    elif opcode == "0001":
        Flags["Opcode"] = "Inverse query"
    elif opcode == "0010":
        Flags["Opcode"] = "Server status request"
    elif opcode == "0011":
        Flags["Opcode"] = "Status reserved and therefore not used"
    else:
        Flags["Opcode"] = opcode

    if binary_representation[5] == "0":
        Flags["Authoritive"] = "The server is not an authority for the domain"
    else:
        Flags["Authoritive"] = "The server is an authority for the domain"

    if binary_representation[6] == "0":
        Flags["Truncated"] = "The message is not truncated"
    else:
        Flags["Truncated"] = "The message is truncated"

    if binary_representation[7] == "0":
        Flags["Recursion desired"] = "Do not query recursively"
    else:
        Flags["Recursion desired"] = "Do query recursively"

    if binary_representation[8] == "0":
        Flags["Recursion available"] = "Server can do recursive queries"
    else:
        Flags["Recursion available"] = "Server can not do recursive queries"

    if binary_representation[9] == "0":
        Flags["Z"] = "reserved"
    else:
        Flags["Z"] = "reserved"

    if binary_representation[10] == "0":
        Flags["Answer authenticated"] = (
            "Answer/authority portion was not authenticated by the server"
        )
    else:
        Flags["Answer authenticated"] = (
            "Answer/authority portion was authenticated by the server"
        )

    if binary_representation[11] == "0":
        Flags["Non-authenticated data"] = "Unacceptable"
    else:
        Flags["Non-authenticated data"] = "Acceptable"

    rcode: str = binary_representation[12:]

    if rcode == "0000":
        Flags["Reply code"] = "No error"
    elif rcode == "0001":
        Flags["Reply code"] = "Format error"
    elif rcode == "0010":
        Flags["Reply code"] = "Server failure"
    elif rcode == "0011":
        Flags["Reply code"] = "Name error"
    elif rcode == "0100":
        Flags["Reply code"] = "Not implemented"
    elif rcode == "0101":
        Flags["Reply code"] = "Refused"

    return Flags


def dNSDomainNameReaderWithCompression(data: bytearray, offset: int) -> tuple[str, int]:
    pointer = offset
    domain_name = ""
    while data[pointer] != 0:
        if data[pointer] != 192:
            length = data[pointer]
            domain_name += (
                bytearray_to_string(data[pointer + 1 : pointer + 1 + length]) + "."
            )
            pointer += length + 1
        else:
            domain_name += (
                dNSDomainNameReaderWithCompression(data, data[pointer + 1] - 12)[0]
                + "."
            )
            pointer += 1
            break
    return domain_name[:-1], pointer + 1


dNSRecordTypeLookup = {
    "0001": "A",
    "0002": "NS",
    "0005": "CNAME",
    "0006": "SOA",
    "000c": "PTR",
    "000f": "MX",
    "0010": "TXT",
    "001c": "AAAA",
    "00ff": "ANY",
}

dNSRecordClassLookup = {
    "0001": "IN",
    "0002": "CS",
    "0003": "CH",
    "0004": "HS",
    "00ff": "ANY",
}


def decodeDNSQuery(data: bytearray, offset) -> tuple[dNSQuery, int]:
    pointer = offset
    domain_name, pointer = dNSDomainNameReaderWithCompression(data, pointer)
    query_type = lookUpInDict(dNSRecordTypeLookup, data[pointer : pointer + 2].hex())
    query_class = lookUpInDict(
        dNSRecordClassLookup, data[pointer + 2 : pointer + 4].hex()
    )
    return (
        {
            "Query": domain_name,
            "Type": query_type,
            "Class": query_class,
        },
        pointer + 4,
    )


def decodeDNSAnswer(data: bytearray, offset) -> tuple[dNSAnswer, int]:
    pointer = offset
    domain_name, pointer = dNSDomainNameReaderWithCompression(data, pointer)
    query_type = lookUpInDict(dNSRecordTypeLookup, data[pointer : pointer + 2].hex())
    query_class = lookUpInDict(
        dNSRecordClassLookup, data[pointer + 2 : pointer + 4].hex()
    )
    ttl = int.from_bytes(data[pointer + 4 : pointer + 8], byteorder="big")
    data_length = int.from_bytes(data[pointer + 8 : pointer + 10], byteorder="big")
    address = hex2DecIp(data[pointer + 10 : pointer + 10 + data_length].hex())
    return (
        {
            "Name": domain_name,
            "Type": query_type,
            "Class": query_class,
            "TTL": ttl,
            "Data Length": data_length,
            "Address": address,
        },
        pointer + 10 + data_length,
    )


def decodeDNSAuthority(data: bytearray, offset) -> tuple[dNSAuthority, int]:
    pointer = offset
    domain_name, pointer = dNSDomainNameReaderWithCompression(data, pointer)
    query_type = lookUpInDict(dNSRecordTypeLookup, data[pointer : pointer + 2].hex())
    query_class = lookUpInDict(
        dNSRecordClassLookup, data[pointer + 2 : pointer + 4].hex()
    )
    ttl = int.from_bytes(data[pointer + 4 : pointer + 8], byteorder="big")
    data_length = int.from_bytes(data[pointer + 8 : pointer + 10], byteorder="big")
    primary_name_server, pointer = dNSDomainNameReaderWithCompression(
        data, pointer + 10
    )
    responsible_mail_address, pointer = dNSDomainNameReaderWithCompression(
        data, pointer
    )
    serial_number = int.from_bytes(data[pointer : pointer + 4], byteorder="big")
    refresh_interval = int.from_bytes(data[pointer + 4 : pointer + 8], byteorder="big")
    retry_interval = int.from_bytes(data[pointer + 8 : pointer + 12], byteorder="big")
    expire_limit = int.from_bytes(data[pointer + 12 : pointer + 16], byteorder="big")
    minimum_ttl = int.from_bytes(data[pointer + 16 : pointer + 20], byteorder="big")
    return (
        {
            "Name": domain_name,
            "Type": query_type,
            "Class": query_class,
            "TTL": ttl,
            "Data Length": data_length,
            "Primary Name Server": primary_name_server,
            "Responsible Mail Address": responsible_mail_address,
            "Serial Number": serial_number,
            "Refresh Interval": refresh_interval,
            "Retry Interval": retry_interval,
            "Expire Limit": expire_limit,
            "Minimum TTL": minimum_ttl,
        },
        pointer + 20,
    )


def decodeDNSAdditional(data: bytearray, offset) -> tuple[dNSAdditional, int]:
    pointer = offset
    domain_name, pointer = dNSDomainNameReaderWithCompression(data, pointer)
    query_type = lookUpInDict(dNSRecordTypeLookup, data[pointer : pointer + 2].hex())
    query_class = lookUpInDict(
        dNSRecordClassLookup, data[pointer + 2 : pointer + 4].hex()
    )
    ttl = int.from_bytes(data[pointer + 4 : pointer + 8], byteorder="big")
    data_length = int.from_bytes(data[pointer + 8 : pointer + 10], byteorder="big")
    address = hex2DecIp(data[pointer + 10 : pointer + 10 + data_length].hex())
    return (
        {
            "Name": domain_name,
            "Type": query_type,
            "Class": query_class,
            "TTL": ttl,
            "Data Length": data_length,
            "Address": address,
        },
        pointer + 10 + data_length,
    )


def decodeDNSRecords(data: bytearray, que: int, ans: int, auth: int, add: int):
    result = {
        "Queries": [],
        "Answers": [],
        "Authority Servers": [],
        "Additional Records": [],
    }
    pointer = 0

    for i in range(que):
        query, npointer = decodeDNSQuery(data, pointer)
        result["Queries"].append(query)
        pointer = npointer
    for i in range(ans):
        answer, npointer = decodeDNSAnswer(data, pointer)
        result["Answers"].append(answer)
        pointer = npointer
    for i in range(auth):
        authority, npointer = decodeDNSAuthority(data, pointer)
        result["Authority Servers"].append(authority)
        pointer = npointer
    for i in range(add):
        additional, npointer = decodeDNSAdditional(data, pointer)
        result["Additional Records"].append(additional)
        pointer = npointer

    return result


def decodeDNSData(data: segmentedDNSData):
    result = {}
    result["Transaction ID"] = data["Transaction ID"]
    original_hex: str = data["Flags"]
    binary_representation: str = hex_to_binary(original_hex)
    result["Flags"] = decodeFlag(binary_representation)
    result["Questions"] = data["Questions"]
    result["Answer RRs"] = data["Answer RRs"]
    result["Authority RRs"] = data["Authority RRs"]
    result["Additional RRs"] = data["Additional RRs"]
    records = data["Queries/Answers/AServers"]
    result.update(
        decodeDNSRecords(
            records,
            data["Questions"],
            data["Answer RRs"],
            data["Authority RRs"],
            data["Additional RRs"],
        )
    )

    return result
