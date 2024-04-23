from segmenter import segment
from decoder.dns import decodeDNSData
from decoder.dhcp import decodeDHCPData
from decoder.general import decodeIPData, decodeEthernetData
from renderer import pp


def parse_hex(file_name: str) -> str:
    hex_code = []
    with open(file_name, "r+") as f:
        for line in f.readlines():
            hex_code.extend(line.strip().split(' ')[3:])

    dataDHCP = ' '.join(hex_code)
    return dataDHCP

try:
    dataDHCP = parse_hex("hex_dumps/925.txt")
except:
    raise ValueError("hex dump file not found")

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
