from typing import TypedDict

data = bytearray.fromhex(
    "8E986B41E064C889F3A858A908004500003DF644000040111840AC140A02AC140A0190CA0035002918D49C38010000010000000000000373736C076773746174696303636F6D00001C0001"
)

segmentedData = TypedDict(
    "segmentedData",
    {"Ethernet": bytearray, "IP": bytearray, "UDP": bytearray, "DNS": bytearray},
)

segmentedEthernetData = TypedDict(
    "segmentedEthernetData",
    {
        "Destination MAC": bytearray,
        "Source MAC": bytearray,
        "Type": bytearray,
    },
)

segmentedIPData = TypedDict(
    "segmentedIPData",
    {
        "Version": bytearray,
        "IHL": bytearray,
        "DSCP": bytearray,
        "ECN": bytearray,
        "Total Length": bytearray,
        "Identification": bytearray,
        "Flags": bytearray,
        "Fragment Offset": bytearray,
        "TTL": bytearray,
        "Protocol": bytearray,
        "Header Checksum": bytearray,
        "Source IP": bytearray,
        "Destination IP": bytearray,
    },
)

segmentedUDPData = TypedDict(
    "segmentedUDPData",
    {
        "Source Port": bytearray,
        "Destination Port": bytearray,
        "Length": bytearray,
        "Checksum": bytearray,
    },
)


def segment(data: bytearray) -> segmentedData:
    return {
        "Ethernet": data[:14],
        "IP": data[14:34],
        "UDP": data[34:42],
        "DNS": data[42:],
    }


print(segment(data))
