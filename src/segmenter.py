from typing import TypedDict

segmentedEthernetData = TypedDict(
    "segmentedEthernetData",
    {
        "Destination MAC": str,
        "Source MAC": str,
        "Type": str,
    },
)

segmentedIPData = TypedDict(
    "segmentedIPData",
    {
        "Version": int,
        "IHL": int,
        "ToS": int,
        "Total Length": str,
        "Identification": str,
        "Flags": int,
        "Fragment Offset": int,
        "TTL": int,
        "Protocol": int,
        "Header Checksum": str,
        "Source IP": str,
        "Destination IP": str,
    },
)

segmentedUDPData = TypedDict(
    "segmentedUDPData",
    {
        "Source Port": str,
        "Destination Port": str,
        "Length": str,
        "Checksum": str,
    },
)

segmentedDNSData = TypedDict(
    "segmentedDNSData",
    {
        "Transaction ID": str,
        "Flags": str,
        "Questions": str,
        "Answer RRs": str,
        "Authority RRs": str,
        "Additional RRs": str,
        "Queries": str,
    },
)

segmentedData = TypedDict(
    "segmentedData",
    {
        "Ethernet": segmentedEthernetData,
        "IP": segmentedIPData,
        "UDP": segmentedUDPData,
        "DNS": segmentedDNSData,
    },
)


def segmentEthernet(data: bytearray) -> segmentedEthernetData:
    return {
        "Destination MAC": data[:6].hex(),
        "Source MAC": data[6:12].hex(),
        "Type": data[12:14].hex(),
    }


def segmentIP(data: bytearray) -> segmentedIPData:
    return {
        "Version": data[0] >> 4,
        "IHL": data[0] & 0x0F,
        "ToS": data[1],
        "Total Length": data[2:4].hex(),
        "Identification": data[4:6].hex(),
        "Flags": data[6] >> 5,
        "Fragment Offset": ((data[6] & 0x1F) << 8) + data[7],
        "TTL": data[8],
        "Protocol": data[9],
        "Header Checksum": data[10:12].hex(),
        "Source IP": data[12:16].hex(),
        "Destination IP": data[16:20].hex(),
    }


def segmentUDP(data: bytearray) -> segmentedUDPData:
    return {
        "Source Port": data[:2].hex(),
        "Destination Port": data[2:4].hex(),
        "Length": data[4:6].hex(),
        "Checksum": data[6:8].hex(),
    }


def segmentDNS(data: bytearray) -> segmentedDNSData:
    return {
        "Transaction ID": data[:2].hex(),
        "Flags": data[2:4].hex(),
        "Questions": data[4:6].hex(),
        "Answer RRs": data[6:8].hex(),
        "Authority RRs": data[8:10].hex(),
        "Additional RRs": data[10:12].hex(),
        "Queries": data[12:].hex(),
    }


def segment(data: bytearray) -> segmentedData:

    return {
        "Ethernet": segmentEthernet(data[:14]),
        "IP": segmentIP(data[14:34]),
        "UDP": segmentUDP(data[34:42]),
        "DNS": segmentDNS(data[42:]),
    }
