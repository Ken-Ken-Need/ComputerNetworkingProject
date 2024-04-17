from typing import TypedDict, Union

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

segmentedDHCPData = TypedDict(
    "segmentedDHCPData",
    {
        "Op": int,
        "Htype": int,
        "Hlen": int,
        "Hops": int,
        "Xid": str,
        "Secs": str,
        "Flags": str,
        "Ciaddr": str,
        "Yiaddr": str,
        "Siaddr": str,
        "Giaddr": str,
        "Chaddr": str,
        "Sname": str,
        "File": str,
        "Magic": str,
        "Options": str,
    },
)

segmentedDataWithDNS = TypedDict(
    "segmentedDataWithDNS",
    {
        "Ethernet": segmentedEthernetData,
        "IP": segmentedIPData,
        "UDP": segmentedUDPData,
        "DNS": segmentedDNSData,
    },
)

segmentedDataWithDHCP = TypedDict(
    "segmentedDataWithDHCP",
    {
        "Ethernet": segmentedEthernetData,
        "IP": segmentedIPData,
        "UDP": segmentedUDPData,
        "DHCP": segmentedDHCPData,
    },
)

segmentedData = Union[segmentedDataWithDNS, segmentedDataWithDHCP]


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


def segmentDHCP(data: bytearray) -> segmentedDHCPData:
    return {
        "Op": data[0],
        "Htype": data[1],
        "Hlen": data[2],
        "Hops": data[3],
        "Xid": data[4:8].hex(),
        "Secs": data[8:10].hex(),
        "Flags": data[10:12].hex(),
        "Ciaddr": data[12:16].hex(),
        "Yiaddr": data[16:20].hex(),
        "Siaddr": data[20:24].hex(),
        "Giaddr": data[24:28].hex(),
        "Chaddr": data[28:44].hex(),
        "Sname": data[44:108].hex(),
        "File": data[108:236].hex(),
        "Magic": data[236:240].hex(),
        "Options": data[240:].hex(),
    }


def segment(data: bytearray) -> segmentedData:
    ethernetData = segmentEthernet(data[:14])
    iPData = segmentIP(data[14:34])
    uDPData = segmentUDP(data[34:42])
    if uDPData["Destination Port"] == "0035" or uDPData["Source Port"] == "0035":
        dnsData = segmentDNS(data[42:])
        return {
            "Ethernet": ethernetData,
            "IP": iPData,
            "UDP": uDPData,
            "DNS": dnsData,
        }
    elif uDPData["Destination Port"] == ("0043" or "0044"):
        dhcpData = segmentDHCP(data[42:])
        return {
            "Ethernet": ethernetData,
            "IP": iPData,
            "UDP": uDPData,
            "DHCP": dhcpData,
        }
    else:
        raise ValueError("Unknown protocol")
