from segmenter import segment
from decoder.dns import decodeDNSData
from decoder.dhcp import decodeDHCPData
from decoder.general import decodeIPData, decodeEthernetData
from renderer import pp


def parse_hex(file_name: str) -> str:
    hex_code = []
    with open(file_name, "r+") as f:
        for line in f.readlines():
            hex_code.extend(line.strip().split(" ")[3:])

    dataDHCP = " ".join(hex_code)
    return dataDHCP


dataDHCP = """
ff ff ff ff ff ff c8 89 f3 a8 58 a9 08 00 45 00
01 48 d9 a3 00 00 ff 11 e1 01 00 00 00 00 ff ff
ff ff 00 44 00 43 01 34 45 06 01 01 06 00 38 b8
5d e5 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 c8 89 f3 a8 58 a9 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 63 82 53 63 35 01 01 37 0c 01
79 03 06 0f 6c 72 77 fc 5f 2c 2e 39 02 05 dc 3d
07 01 c8 89 f3 a8 58 a9 33 04 00 76 a7 00 0c 0f
4d 61 63 69 6e 74 6f 50 6f 72 74 61 62 6c 65 ff
00 00 00 00 00 00
"""

dataDHCP = parse_hex("925.txt")

dataDNS = """8E986B41E064C889F3A858A908004500003DF644000040111840AC140A02AC140A0190CA0035002918D49C38010000010000000000000373736C076773746174696303636F6D00001C0001"""

data = bytearray.fromhex(dataDHCP)


segmentedData = segment(data)
decodedData = {
    "Ethernet": decodeEthernetData(segmentedData["Ethernet"]),
    "IP": decodeIPData(segmentedData["IP"]),
    "UDP": segmentedData["UDP"],
}

if "DNS" in segmentedData:
    decodedData["DNS"] = decodeDNSData(segmentedData["DNS"])

if "DHCP" in segmentedData:
    decodedData["DHCP"] = decodeDHCPData(segmentedData["DHCP"])

pp.pprint(decodedData)
