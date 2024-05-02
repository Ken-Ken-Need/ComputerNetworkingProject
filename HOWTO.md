# Running The Program

Download the program [`dns-dhcp-parser`](https://github.com/Ken-Ken-Need/ComputerNetworkingProject/releases/tag/v1.2)

Add the binary to your local bin folder:

```sh
mv ./dns-dhcp-parserv1.2_macos-arm64 /usr/local/bin/dns-dhcp-parser
```

How to use:

```txt
dns-dhcp-parser -h
usage: DNS/DHCP Packet Analyzer [-h] [-O OUTPUT] [-V] filename

Analyze DNS/DHCP packets and display the data in a human-readable format.

positional arguments:
  filename

options:
  -h, --help            show this help message and exit
  -O OUTPUT, --output OUTPUT
  -V, --verbose
```

After it finished running, the program will ask if you want to view the output, if you choose yes, it will open the output file in vim with line folding.
