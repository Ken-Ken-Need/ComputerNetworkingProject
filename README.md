# DNS / DHCP Network Capture Parser

This is a project to parse network capture files and extract DNS and DHCP information.

## Sample Output

### DNS

```yaml
Ethernet:
  Destination MAC: c8:89:f3:a8:58:a9
  Source MAC: 64:3a:ea:2e:2f:82
  Type: 0800 (IPv4)
IP:
  Version: 4
  IHL: 5
  ToS: 0
  Total Length: 117
  Identification: 293e
  Flags:
    Reserved: 0
    Don't Fragment: 0
    More Fragments: 0
  Fragment Offset: 0
  TTL: 62
  Protocol: 17 (UDP)
  Header Checksum: c531
  Source IP: 10.214.34.6
  Destination IP: 10.209.86.92
UDP:
  Source Port: 53
  Destination Port: 54497
  Length: 97
  Checksum: 0fdc
DNS:
  Transaction ID: e9ca
  Flags:
    Response: Response
    Opcode: Standard query
    Authoritive: The server is not an authority for the domain
    Truncated: The message is not truncated
    Recursion desired: Do query recursively
    Recursion available: Server can not do recursive queries
    Z: reserved
    Answer authenticated: Answer/authority portion was not authenticated by the
      server
    Non-authenticated data: Unacceptable
    Reply code: No error
  Questions: 1
  Answer RRs: 3
  Authority RRs: 0
  Additional RRs: 0
  Queries:
    - Query: setup.fe2.apple-dns.net
      Type: A
      Class: IN
  Answers:
    - Name: setup.fe2.apple-dns.net
      Type: A
      Class: IN
      TTL: 87
      Data Length: 4
      Address: 17.248.216.65
    - Name: setup.fe2.apple-dns.net
      Type: A
      Class: IN
      TTL: 87
      Data Length: 4
      Address: 17.248.216.66
    - Name: setup.fe2.apple-dns.net
      Type: A
      Class: IN
      TTL: 87
      Data Length: 4
      Address: 17.248.216.64
  Authority Servers: []
  Additional Records: []
```

### DHCP

```yaml
Ethernet:
  Destination MAC: ff:ff:ff:ff:ff:ff
  Source MAC: c8:89:f3:a8:58:a9
  Type: 0800 (IPv4)
IP:
  Version: 4
  IHL: 5
  ToS: 0
  Total Length: 328
  Identification: d9a3
  Flags:
    Reserved: 0
    Don't Fragment: 0
    More Fragments: 0
  Fragment Offset: 0
  TTL: 255
  Protocol: 17 (UDP)
  Header Checksum: e101
  Source IP: 0.0.0.0
  Destination IP: 255.255.255.255
UDP:
  Source Port: 68
  Destination Port: 67
  Length: 308
  Checksum: "4506"
DHCP:
  Message Type: 1 (Discover)
  Hardware Type: 1 (Ethernet)
  Hardware address length: 6
  Hops: 0
  Transaction Id: 38b85de5
  Seconds Elapsed: 0
  Bootp Flags: "0000"
  Client IP Sddress: 0.0.0.0
  Your IP Sddress: 0.0.0.0
  Next Server IP Address: 0.0.0.0
  Relay Agent IP Address: 0.0.0.0
  Client Hardware address: c889f3a858a900000000000000000000
  Server Host: "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  Boot File: "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
  Magic: "63825363"
  Options:
    - DHCP Message Type: Discover (1)
    - Parameter Request List:
        - (1) Subnet Mask
        - (121) Classless Static Route Option
        - (3) Router
        - (6) Domain Server
        - (15) Domain Name
        - (108) IPv6-Only Preferred
        - (114) DHCP Captive-Portal
        - (119) Domain Search
        - (252) Private Use
        - (95) LDAP
        - (44) NETBIOS Name Srv
        - (46) NETBIOS Node Type
    - Maximum DHCP Message Size: 1500
    - Client-identifier:
        Hardware type: Ethernet
        Client MAC Address: c8:89:f3:a8:58:a9
    - IP Address Lease Time: 90 days (7776000)
    - Hostname: MacintoPortable
```

## Compiling on Your Machine

To activate virtual env, run following command

```sh
python -m venv env # Create a new virtual environment (replace 'env' with your desired environment name)
source env/bin/activate # MacOS / Linux
.\env\Scripts\activate # Windows
```

Install the required packages

```sh
pip install -r requirements.txt
```

Run the program with

```sh
python ./src ./hex-dump-file.txt
```

Compile the program with

```sh
pyinstaller --onefile -n dns-dhcp-parser ./src/main.py
```
