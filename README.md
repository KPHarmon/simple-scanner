# simple-scanner
A simple scanner built in Python to support a variety of loud and stealthy port scans.

## Requirements
``
pip3 install scapy==2.4.5
``

## Usage
```usage: scanner.py [-h] -t TARGET -p PORT -s {SYN,ACK,XMAS}

Program to scan a given port in a variety of ways.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET, --target TARGET
                        the target hostname or IPv4
  -p PORT, --port PORT  port number to connect to
  -s {SYN,ACK,XMAS}, --scan {SYN,ACK,XMAS}
                        perform a specified scan scan
```

### Tested on:
Ubuntu 18.04.3 LTS  
Python 3.6.9
