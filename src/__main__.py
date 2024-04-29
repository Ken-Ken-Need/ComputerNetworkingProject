import argparse
import yaml
import re
import os
from io import TextIOWrapper
from segmenter import segment
from decoder.dns import decodeDNSData
from decoder.dhcp import decodeDHCPData
from decoder.general import decodeIPData, decodeEthernetData

parser = argparse.ArgumentParser(
    prog="DNS/DHCP Packet Analyzer",
    description="Analyze DNS/DHCP packets and display the data in a human-readable format.",
)

parser.add_argument("filename")
parser.add_argument("-O", "--output")
parser.add_argument("-V", "--verbose", action="store_true", default=False)

args = parser.parse_args()


def precessData(data):
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

    return decodedData


def output(d: str, v: bool, o: TextIOWrapper):
    data = bytearray.fromhex(d)
    decodedData = precessData(data)
    if v:
        print(f"Decoded Data Type: {'DNS' if 'DNS' in decodedData else 'DHCP'}")
    yaml.dump(
        {
            f"[{'DNS' if 'DNS' in decodedData else 'DHCP'}] Packet {packetCount}": decodedData
        },
        o,
        default_flow_style=False,
        sort_keys=False,
        indent=2,
    )


with open(args.filename, "r") as f, open(args.output, "w") as o:
    data = ""
    packetCount = 0
    for line in f:
        if line == "\n":
            try:
                output(data, args.verbose, o)
            except Exception as e:
                if args.verbose:
                    print(e)
            data = ""
            packetCount += 1
            continue
        line = re.split(r"\s{2,}", line)
        line = line[1].split()
        data += "".join(line)
    if data:
        try:
            output(data, args.verbose, o)
        except Exception as e:
            if args.verbose:
                print(e)
        data = ""
        packetCount += 1

userIn = input("Would you like to view the output file? (Y/n): ") or "Y"
if userIn.lower() == "y":
    os.system(f'vi -c "set foldmethod=indent | set shiftwidth=1" {args.output}')
