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


def bytearray_to_binary_string(byte_array):
    return (
        int.from_bytes(byte_array, byteorder="big")
        .to_bytes((len(byte_array) + 7) // 8, byteorder="big")
        .decode("utf-8")
    )


def decodeDNSData(data: segmentedDNSData) -> decodedDNSData:
    TransactionID: str = "0x" + data["Transaction ID"]

    original_hex: str = data["Flags"]
    binary_representation: str = bytearray_to_binary_string(original_hex)
    print(binary_representation)

    # return {
    #     "Transaction ID": data["Transaction ID"],
    #     "Flags": data["Flags"],
    #     "Questions": int,
    #     "Answer RRs": int,
    #     "Authority RRs": int,
    #     "Additional RRs": int,
    #     "Queries": Union[list[dNSQuery], None],
    #     "Answers": Union[list[dNSAnswer], None],
    #     "Authority Servers": Union[list[dNSAuthority], None],
    #     "Additional Records": Union[list[dNSAdditional], None],
    # }
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
    # print(data_proc)
    decodeDNSData(data_proc)
    pass
