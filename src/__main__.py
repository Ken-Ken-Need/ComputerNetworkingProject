from segmenter import segment
from decoder.dns import decodeDNSData
from decoder.dhcp import decodeDHCPData
from decoder.general import decodeIPData, decodeEthernetData
from renderer import pp
from fileIO import read_file_to_byte
import sys

data = read_file_to_byte(sys.argv[1])

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
