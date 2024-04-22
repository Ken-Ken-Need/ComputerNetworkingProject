from typing import TypedDict, Callable
from segmenter import segmentedDHCPData


def decodeSubnetMask(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeRouter(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeDomainNameServer(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeHostname(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeDomainName(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeIPAddressLeaseTime(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeDHCPMessageType(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeServerIdentifier(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeParameterRequestList(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeMaximumDHCPMessageSize(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


def decodeClientIdentifier(data: bytearray) -> dict[str, str]:
    return {"key": str(data)}


dHCPLookUpItem = TypedDict(
    "dHCPLookUpItem",
    {"name": str, "func": Callable[[bytearray], dict[str, str]]},
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
            if dHCPLookUpResult["name"] == "End":
                break
            decodedOptionList.append({dHCPLookUpResult["name"]: decodedOption})
        except KeyError:
            decodedOptionList.append(
                {"Unknown": {"code": optionCode, "data": optionData}}
            )
        data = data[2 + optionLength :]

    return decodedOptionList


decodedDHCPData = TypedDict(
    "decodedDHCPData",
    {
        "Op": str,
        "Htype": str,
        "Hlen": str,
        "Hops": str,
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
        "Options": list[dict[str, dict[str, str]]],
    },
)


def decodeDHCPData(data: segmentedDHCPData) -> decodedDHCPData:
    return {
        "Op": str(data["Op"]),
        "Htype": str(data["Htype"]),
        "Hlen": str(data["Hlen"]),
        "Hops": str(data["Hops"]),
        "Xid": data["Xid"],
        "Secs": data["Secs"],
        "Flags": data["Flags"],
        "Ciaddr": data["Ciaddr"],
        "Yiaddr": data["Yiaddr"],
        "Siaddr": data["Siaddr"],
        "Giaddr": data["Giaddr"],
        "Chaddr": data["Chaddr"],
        "Sname": data["Sname"],
        "File": data["File"],
        "Magic": data["Magic"],
        "Options": decodeDHCPOptions(data["Options"]),
    }
