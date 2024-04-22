from typing import TypedDict, Callable
from segmenter import segmentedDHCPData
from decoder.general import hex2DecIp


def decodeSubnetMask(data: bytearray):
    pass


def decodeRouter(data: bytearray):
    return {"key": str(data)}


def decodeDomainNameServer(data: bytearray):
    pass


def decodeHostname(data: bytearray):
    pass


def decodeDomainName(data: bytearray):
    pass


def decodeIPAddressLeaseTime(data: bytearray):
    pass


def decodeDHCPMessageType(data: bytearray):
    lookUpTable = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        4: "Decline",
        5: "Pack",
        6: "Pnak",
        7: "Release",
        8: "Inform",
    }
    id = int.from_bytes(data, "big")
    return lookUpTable[id]


def decodeServerIdentifier(data: bytearray):
    pass


def decodeParameterRequestList(data: bytearray):
    pass


def decodeMaximumDHCPMessageSize(data: bytearray):
    pass


def decodeClientIdentifier(data: bytearray):
    pass


dHCPLookUpItem = TypedDict(
    "dHCPLookUpItem",
    {"name": str, "func": Callable[[bytearray], object]},
)

dHCPLookUp: dict[int, dHCPLookUpItem] = {
    1: {"name": "Subnet Mask", "func": decodeSubnetMask},
    3: {"name": "Router", "func": decodeRouter},
    6: {"name": "Domain Name Server", "func": decodeDomainNameServer},
    12: {"name": "Hostname", "func": decodeHostname},
    15: {"name": "Domain Name", "func": decodeDomainName},
    51: {"name": "IP Address Lease Time", "func": decodeIPAddressLeaseTime},
    53: {"name": "DHCP Message Type", "func": decodeDHCPMessageType},
    54: {"name": "Server Identifier", "func": decodeServerIdentifier},
    55: {"name": "Parameter Request List", "func": decodeParameterRequestList},
    57: {"name": "Maximum DHCP Message Size", "func": decodeMaximumDHCPMessageSize},
    61: {"name": "Client-identifier", "func": decodeClientIdentifier},
    255: {"name": "End", "func": lambda b: {}},
}


def decodeDHCPOptions(data: bytearray) -> list[dict[str, dict[str, str]]]:
    decodedOptionList = []
    while len(data) > 2:
        optionCode = data[0]
        optionLength = data[1]
        optionData = data[2 : 2 + optionLength]
        try:
            dHCPLookUpResult = dHCPLookUp[optionCode]
            decodedOption = dHCPLookUpResult["func"](optionData)
            print(decodedOption)
            if dHCPLookUpResult["name"] == "End":
                break
            decodedOptionList.append({dHCPLookUpResult["name"]: decodedOption})
        except KeyError:
            decodedOptionList.append(
                {"Unknown": {"code": optionCode, "data": optionData}}
            )
        data = data[2 + optionLength :]

    return decodedOptionList


def decodeDHCPData(data: segmentedDHCPData):
    return {
        "Message Type": str(data["Op"]),
        "Hardware Type": str(data["Htype"]),
        "Hardware address length": str(data["Hlen"]),
        "Hops": str(data["Hops"]),
        "Transaction Id": data["Xid"],
        "Seconds Elapsed": data["Secs"],
        "Bootp Flags": data["Flags"],
        "Client IP Sddress": hex2DecIp(data["Ciaddr"]),
        "Your IP Sddress": hex2DecIp(data["Yiaddr"]),
        "Next Server IP Address": hex2DecIp(data["Siaddr"]),
        "Relay Agent IP Address": hex2DecIp(data["Giaddr"]),
        "Client Hardware address": data["Chaddr"],
        "Server Host": data["Sname"],
        "Boot File": data["File"],
        "Magic": data["Magic"],
        "Options": decodeDHCPOptions(data["Options"]),
    }
