from typing import TypedDict, Callable
from segmenter import segmentedDHCPData
from decoder.general import hex2DecIp

def byte2address(bytes: bytearray):
    binary_str = ''.join(format(byte, '08b') for byte in bytes)
    if len(binary_str) > 32:
        address = ['.'.join(str(int(binary_str[i:i+8], 2)) for i in range(j, j + 32, 8)) for j in range(0, len(binary_str), 32)]
    else:
        address = '.'.join(str(int(binary_str[i:i+8], 2)) for i in range(0, 32, 8))

    return address


def decodeSubnetMask(data: bytearray):
    subnet_mask = byte2address(data)

    return subnet_mask


def decodeRouter(data: bytearray):
    router = byte2address(data)

    return router


def decodeDomainNameServer(data: bytearray):
    DNS = byte2address(data)

    return DNS


def decodeHostname(data: bytearray):

    return data.decode('utf-8')


def decodeDomainName(data: bytearray):

    return data.decode('utf-8')


def decodeIPAddressLeaseTime(data: bytearray):
    sec = int.from_bytes(data, byteorder='big')
    if sec > 24 * 3600:
        res = '{} days ({})'.format(sec // (24 * 3600), sec)
    else:
        res = '{} hours ({})'.format(sec // (3600), sec)
    return res


def decodeDHCPMessageType(data: bytearray):
    messageTypeTable = {
        1 : "Discover",
        2 : "Offer",
        3 : "Request",
        4 : "Decline",
        5 : "ACK",
        6 : "Nak",
        7 : "Release",
        8 : "Inform",
    }
    id = int.from_bytes(data, "big")
    res = '{} ({})'.format(messageTypeTable[id], id)
    return res


def decodeServerIdentifier(data: bytearray):
    server_identifier = byte2address(data)

    return server_identifier


def decodeParameterRequestList(data: bytearray):
    
    return data


def decodeMaximumDHCPMessageSize(data: bytearray):
    size = int.from_bytes(data, byteorder='big')
    return size


def decodeClientIdentifier(data: bytearray):
    hardwareTable = {
        0  : "Bluetooth",
        1  : "Ethernet",
        6  : "IEEE 802", 
        9  : "Token Ring",
        14 : "IEEE 1394",
        15 : "FDDI",
        32 : "InfiniBand",
    }
    hardware_type = hardwareTable[data[0]]
    MAC_address = ':'.join(format(byte, 'x') for byte in data[1:])
    return {
        "Hardware type" : hardware_type,
        "Client MAC Address" : MAC_address
    }


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
