import sys
import argparse
from scapy.all import sr1,IP,TCP,ICMP

class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def open_message(target, port):
    return(f'%s:%d\t{bcolors.OKGREEN}[OPEN]{bcolors.ENDC}' % (target, port))        

def closed_message(target, port):
    return(f'%s:%d\t{bcolors.FAIL}[CLOSED]{bcolors.ENDC}' % (target, port))        

def filtered_message(target, port):
    return(f'%s:%d\t{bcolors.WARNING}[FILTERED]{bcolors.ENDC}' % (target, port))        

def unfiltered_message(target, port):
    return(f'%s:%d\t{bcolors.WARNING}[UNFILTERED]{bcolors.ENDC}' % (target, port))        

def banner(scan):
    print(f'{bcolors.BOLD}\n--Performing an %s Scan--\n{bcolors.ENDC}' % (scan))

# Syn Scan
def syn_scan(target, port):
    
    # Send a TCP Packet with the SYN flag set
    response = sr1(IP(dst=target)/TCP(dport=port,flags="S"), verbose=False, timeout=2)
    
    # If there is a response, the port is open
    if response:
        return(open_message(target, port))        
        
    # If there is no response, the port is closed
    else:
        return(closed_message(target, port))        

# X-MAS Scan - Information from https://www.plixer.com/blog/understanding-xmas-scans/
def xmas_scan(target, port):

    # Send a TCP Packet with the FIN, PUSH, and URG flags set
    response = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), verbose=False, timeout=2)
    
    # If there is no response, the port is open
    if type(response) == None:
        return(open_message(target, port))

    # If the RST flag is set, the port is closed
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x14:
            return(closed_message(target,port))

    # If the ICMP is type 3 and has a 1,2,3,9,10,13 code, the port is filtered
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return(filtered_message(target, port))

# ACK Scan - Information from https://nmap.org/book/scan-methods-ack-scan.html
def ack_scan(target, port):

    # Send a TCP Packet with the ACK flag set
    response = sr1(IP(dst=target)/TCP(dport=port,flags="A"), verbose=False, timeout=2)
 
    # If there is no response, the port is filtered
    if type(response) == None:
        return(filtered_message(target, port))

    # If the RST flag is set, the port is unfiltered
    elif response.haslayer(TCP):
        if response.getlayer(TCP).flags == 0x4:
            return(unfiltered_message(target, port))

    # If the ICMP is type 3 and has a 1,2,3,9,10,13 code, the port is filtered
    elif response.haslayer(ICMP):
        if int(response.getlayer(ICMP).type)==3 and int(response.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            return(filtered_message(target, port))

# Driver Function
def main():

    # Parse Arguments
    parser = argparse.ArgumentParser(description='Program to scan a given port in a variety of ways.')

    parser.add_argument('-t',
                        '--target',
                        type=str,
                        help='the target hostname or IPv4',
                        required=True)
                        
    parser.add_argument('-p',
                        '--port',
                        help='port number to connect to',
                        default=80,
                        type=int,
                        required=True)

    parser.add_argument('-s',
                        '--scan',
                        help='perform a specified scan',
                        default='SYN',
                        type=str,
                        required=True,
                        choices=['SYN', 'ACK', 'XMAS'])

    args = parser.parse_args()

    # Run Scan and Print Results
    banner(args.scan)

    if args.scan == 'SYN':
        result = syn_scan(args.target, args.port)
        print(result,end='\n\n')

    elif args.scan == 'ACK':
        result = ack_scan(args.target, args.port)
        print(result,end='\n\n')

    elif args.scan == 'XMAS':
        result = xmas_scan(args.target, args.port)
        print(result,end='\n\n')


if __name__ == '__main__':
    main()
