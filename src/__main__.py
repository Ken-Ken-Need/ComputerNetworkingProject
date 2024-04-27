from segmenter import segment
from decoder.dns import decodeDNSData
from decoder.dhcp import decodeDHCPData
from decoder.general import decodeIPData, decodeEthernetData
from renderer import pp
from fileIO import read_file_to_byte, write_byte_to_file
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

print("How do you want to output the data?")
choice = input("1. Print to console\n2. Save to file\n")

if choice == "1":
    pp.pprint(decodedData)
elif choice == "2":
    filePath = input("Enter the path to save the file: ")
    write_byte_to_file(filePath, decodedData)
