import sys

sys.path.append("..")

from typing import TypedDict
from typing import Union
from segmenter import segmentedDNSData

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
        "Address": str,
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

decodedDNSData = TypedDict(
    "decodedDNSData",
    {
        "Transaction ID": str,
        "Flags": str,
        "Questions": int,
        "Answer RRs": int,
        "Authority RRs": int,
        "Additional RRs": int,
        "Queries": Union[list[dNSQuery], None],
        "Answers": Union[list[dNSAnswer], None],
        "Authority Servers": Union[list[dNSAuthority], None],
        "Additional Records": Union[list[dNSAdditional], None],
    },
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
    Flags: str = ""

    Flags += "Response: "
    if binary_representation[0] == 0:
        Flags += "Query\n"
    else:
        Flags += "Response\n"

    opcode = binary_representation[1:5]
    Flags += "Opcode: "
    if opcode == "0000":
        Flags += "Standard query\n"
    elif opcode == "0001":
        Flags += "Inverse query\n"
    elif opcode == "0010":
        Flags += "Server status request\n"
    elif opcode == "0011":
        Flags += "Status reserved and therefore not used\n"
    else:
        Flags += opcode
        Flags += "\n"

    Flags += "Authoritive: "
    if binary_representation[5] == "0":
        Flags += "The server is not an authority for the domain\n"
    else:
        Flags += "The server is an authority for the domain\n"

    if binary_representation[6] == "0":
        Flags += "Truncated: The message is not truncated\n"
    else:
        Flags += "Truncated: The message is truncated\n"

    if binary_representation[7] == "0":
        Flags += "Recursion desired: Do not query recursively\n"
    else:
        Flags += "Recursion desired: Do query recursively\n"

    if binary_representation[8] == "0":
        Flags += "Recursion available: Server can do recursive queries\n"
    else:
        Flags += "Recursion available: Server can not do recursive queries\n"

    if binary_representation[9] == "0":
        Flags += "Z: reserved\n"
    else:
        Flags += "Z: reserved\n"

    if binary_representation[10] == "0":
        Flags += "Answer authenticated: Answer/authority portion was not authenticated by the server\n"
    else:
        Flags += "Answer authenticated: Answer/authority portion was authenticated by the server\n"

    if binary_representation[11] == "0":
        Flags += "Non-authenticated data: Unacceptable\n"
    else:
        Flags += "Non-authenticated data: Acceptable\n"

    rcode: str = binary_representation[12:]
    Flags += "Reply code: "
    if rcode == "0000":
        Flags += "No error"
    elif rcode == "0001":
        Flags += "Format error"
    elif rcode == "0010":
        Flags += "Server failure"
    elif rcode == "0011":
        Flags += "Name error"
    elif rcode == "0100":
        Flags += "Not implemented"
    elif rcode == "0101":
        Flags += "Refused"
    return Flags


def decodeDNSData(data: segmentedDNSData) -> decodedDNSData:
    # -----------The part to process Transaction ID -----#
    TransactionID: str = "0x" + data["Transaction ID"]

    # -------Flags------------#
    original_hex: str = data["Flags"]
    binary_representation: str = hex_to_binary(original_hex)
    Flags: str = decodeFlag(binary_representation)

    # ----- Questions ----#
    question = data["Questions"]

    # -----Answer RRS------#
    AnswerRRs = data["Answer RRs"]

    # --------Authority RRs----------#
    AuthorityRRs = data["Authority RRs"]

    # -------Additional RR-----#
    AdditionalRRs = data["Additional RRs"]

    return {
        "Transaction ID": TransactionID,
        "Flags": Flags,
        "Questions": question,
        "Answer RRs": AnswerRRs,
        "Authority RRs": AuthorityRRs,
        "Additional RRs": AdditionalRRs,
        # "Queries": Union[list[dNSQuery], None],
        # "Answers": Union[list[dNSAnswer], None],
        # "Authority Servers": Union[list[dNSAuthority], None],
        # "Additional Records": Union[list[dNSAdditional], None],
    }
    pass


if __name__ == "__main__":
    dataDNS = """8E986B41E064C889F3A858A908004500003DF644000040111840AC140A02AC140A0190CA0035002918D49C38010000010000000000000373736C076773746174696303636F6D00001C0001"""
    dataDNS_lower = dataDNS.lower()
    data = bytearray.fromhex(dataDNS_lower)
    data_proc: segmentedDNSData = {
        "Transaction ID": data[:2].hex(),
        "Flags": data[2:4].hex(),
        "Questions": int(data[4:6].hex(), 16),
        "Answer RRs": int(data[6:8].hex(), 16),
        "Authority RRs": int(data[8:10].hex(), 16),
        "Additional RRs": int(data[10:12].hex(), 16),
        "Queries/Answers/AServers": data[12:],
    }

    decodeDNSData(data_proc)
    pass
