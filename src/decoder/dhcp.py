from typing import TypedDict, Callable
from segmenter import segmentedDHCPData
from decoder.general import hex2DecIp


def byte2address(bytes: bytearray):
    binary_str = "".join(format(byte, "08b") for byte in bytes)
    if len(binary_str) > 32:
        address = [
            ".".join(str(int(binary_str[i : i + 8], 2)) for i in range(j, j + 32, 8))
            for j in range(0, len(binary_str), 32)
        ]
    else:
        address = ".".join(str(int(binary_str[i : i + 8], 2)) for i in range(0, 32, 8))

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

    return data.decode("utf-8")


def decodeDomainName(data: bytearray):

    return data.decode("utf-8")


def decodeIPAddressLeaseTime(data: bytearray):
    sec = int.from_bytes(data, byteorder="big")
    if sec > 24 * 3600:
        res = "{} days ({})".format(sec // (24 * 3600), sec)
    else:
        res = "{} hours ({})".format(sec // (3600), sec)
    return res


def decodeDHCPMessageType(data: bytearray):
    messageTypeTable = {
        1: "Discover",
        2: "Offer",
        3: "Request",
        4: "Decline",
        5: "ACK",
        6: "Nak",
        7: "Release",
        8: "Inform",
    }
    id = int.from_bytes(data, "big")
    res = "{} ({})".format(messageTypeTable[id], id)
    return res


def decodeServerIdentifier(data: bytearray):
    server_identifier = byte2address(data)
    return server_identifier


def decodeParameterRequestList(data: bytearray):
    dHCPLookUp = {
        0: "Pad",
        1: "Subnet Mask",
        2: "Time Offset",
        3: "Router",
        4: "Time Server",
        5: "Name Server",
        6: "Domain Server",
        7: "Log Server",
        8: "Quotes Server",
        9: "LPR Server",
        10: "Impress Server",
        11: "RLP Server",
        12: "Hostname",
        13: "Boot File Size",
        14: "Merit Dump File",
        15: "Domain Name",
        16: "Swap Server",
        17: "Root Path",
        18: "Extension File",
        19: "Forward On/Off",
        20: "SrcRte On/Off",
        21: "Policy Filter",
        22: "Max DG Assembly",
        23: "Default IP TTL",
        24: "MTU Timeout",
        25: "MTU Plateau",
        26: "MTU Interface",
        27: "MTU Subnet",
        28: "Broadcast Address",
        29: "Mask Discovery",
        30: "Mask Supplier",
        31: "Router Discovery",
        32: "Router Request",
        33: "Static Route",
        34: "Trailers",
        35: "ARP Timeout",
        36: "Ethernet",
        37: "Default TCP TTL",
        38: "Keepalive Time",
        39: "Keepalive Data",
        40: "NIS Domain",
        41: "NIS Servers",
        42: "NTP Servers",
        43: "Vendor Specific",
        44: "NETBIOS Name Srv",
        45: "NETBIOS Dist Srv",
        46: "NETBIOS Node Type",
        47: "NETBIOS Scope",
        48: "X Window Font",
        49: "X Window Manager",
        50: "Address Request",
        51: "Address Time",
        52: "Overload",
        53: "DHCP Msg Type",
        54: "DHCP Server Id",
        55: "Parameter List",
        56: "DHCP Message",
        57: "DHCP Max Msg Size",
        58: "Renewal Time",
        59: "Rebinding Time",
        60: "Class Id",
        61: "Client Id",
        62: "NetWare/IP Domain",
        63: "NetWare/IP Option",
        64: "NIS-Domain-Name",
        65: "NIS-Server-Addr",
        66: "Server-Name",
        67: "Bootfile-Name",
        68: "Home-Agent-Addrs",
        69: "SMTP-Server",
        70: "POP3-Server",
        71: "NNTP-Server",
        72: "WWW-Server",
        73: "Finger-Server",
        74: "IRC-Server",
        75: "StreetTalk-Server",
        76: "STDA-Server",
        77: "User-Class",
        78: "Directory Agent",
        79: "Service Scope",
        80: "Rapid Commit",
        81: "Client FQDN",
        82: "Relay Agent Information",
        83: "iSNS",
        84: "REMOVED/Unassigned",
        85: "NDS Servers",
        86: "NDS Tree Name",
        87: "NDS Context",
        88: "BCMCS Controller Domain Name list",
        89: "BCMCS Controller IPv4 address option",
        90: "Authentication",
        91: "client-last-transaction-time option",
        92: "associated-ip option",
        93: "Client System",
        94: "Client NDI",
        95: "LDAP",
        96: "REMOVED/Unassigned",
        97: "UUID/GUID",
        98: "User-Auth",
        99: "GEOCONF_CIVIC",
        100: "PCode",
        101: "TCode",
        108: "IPv6-Only Preferred",
        109: "OPTION_DHCP4O6_S46_SADDR",
        110: "REMOVED/Unassigned",
        111: "Unassigned",
        112: "Netinfo Address",
        113: "Netinfo Tag",
        114: "DHCP Captive-Portal",
        115: "REMOVED/Unassigned",
        116: "Auto-Config",
        117: "Name Service Search",
        118: "Subnet Selection Option",
        119: "Domain Search",
        120: "SIP Servers DHCP Option",
        121: "Classless Static Route Option",
        122: "CCC",
        123: "GeoConf Option",
        124: "V-I Vendor Class",
        125: "V-I Vendor-Specific Information",
        126: "Removed/Unassigned",
        127: "Removed/Unassigned",
        128: "PXE - undefined (vendor specific)",
        128: "Etherboot signature. 6 bytes: E4:45:74:68:00:00",
        128: "DOCSIS full security server IP address",
        128: "TFTP Server IP address (for IP Phone software load)",
        129: "PXE - undefined (vendor specific)",
        129: "Kernel options. Variable length string",
        129: "Call Server IP address",
        130: "PXE - undefined (vendor specific)",
        130: "Ethernet interface. Variable length string.",
        130: "Discrimination string (to identify vendor)",
        131: "PXE - undefined (vendor specific)",
        131: "Remote statistics server IP address",
        132: "PXE - undefined (vendor specific)",
        132: "IEEE 802.1Q VLAN ID",
        133: "PXE - undefined (vendor specific)",
        133: "IEEE 802.1D/p Layer 2 Priority",
        134: "PXE - undefined (vendor specific)",
        134: "Diffserv Code Point (DSCP) for VoIP signalling and media streams",
        135: "PXE - undefined (vendor specific)",
        135: "HTTP Proxy for phone-specific applications",
        136: "OPTION_PANA_AGENT",
        137: "OPTION_V4_LOST",
        138: "OPTION_CAPWAP_AC_V4",
        139: "OPTION-IPv4_Address-MoS",
        140: "OPTION-IPv4_FQDN-MoS",
        141: "SIP UA Configuration Service Domains",
        142: "OPTION-IPv4_Address-ANDSF",
        143: "OPTION_V4_SZTP_REDIRECT",
        144: "GeoLoc",
        145: "FORCERENEW_NONCE_CAPABLE",
        146: "RDNSS Selection",
        147: "OPTION_V4_DOTS_RI",
        148: "OPTION_V4_DOTS_ADDRESS",
        150: "TFTP server address",
        150: "Etherboot",
        150: "GRUB configuration path name",
        151: "status-code",
        152: "base-time",
        153: "start-time-of-state",
        154: "query-start-time",
        155: "query-end-time",
        156: "dhcp-state",
        157: "data-source",
        158: "OPTION_V4_PCP_SERVER",
        159: "OPTION_V4_PORTPARAMS",
        161: "OPTION_MUD_URL_V4",
        162: "OPTION_V4_DNR",
        208: "PXELINUX Magic",
        209: "Configuration File",
        210: "Path Prefix",
        211: "Reboot Time",
        212: "OPTION_6RD",
        213: "OPTION_V4_ACCESS_DOMAIN",
        220: "Subnet Allocation Option",
        221: "Virtual Subnet Selection (VSS) Option",
        255: "End",
    }

    result = []
    for byte in data:
        if byte in dHCPLookUp:
            result.append(f"({byte}) {dHCPLookUp[byte]}")
        elif byte in range(224, 255):
            result.append(f"({byte}) Private Use")
        else:
            result.append(f"({byte}) Unknown")
    return result


def decodeMaximumDHCPMessageSize(data: bytearray):
    size = int.from_bytes(data, byteorder="big")
    return size


def decodeClientIdentifier(data: bytearray):
    hardwareTable = {
        0: "Bluetooth",
        1: "Ethernet",
        6: "IEEE 802",
        9: "Token Ring",
        14: "IEEE 1394",
        15: "FDDI",
        32: "InfiniBand",
    }
    hardware_type = hardwareTable[data[0]]
    MAC_address = ":".join(format(byte, "x") for byte in data[1:])
    return {"Hardware type": hardware_type, "Client MAC Address": MAC_address}


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
    # ljn ↓
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
