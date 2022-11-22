# Port Scanner using Scapy
# created by AH
# est. 2022

# notes
# sport = source port, dport = dest. port
# timeout parameter specify the time to wait after the last packet has been sent
# print_ports(port, state) -- prints the port and its state [Open/Close/Filtered]

try:
    from scapy.all import *
    from scapy.layers.inet import *

except ImportError:
    print("\nSome libraries seem to be missing, check it back!")

import argparse

# main display
print("******* Port Scanning *******")

# output format
def print_ports(port, state):
    print("Port | State")
    print("%s | %s" % (port,state))

# establish a SYN/Stealth scan, initiating half-open non-complete TCP
def syn_scan(target,ports):
    print("SYN scan is on, %s with ports %s" % (target, ports))
    sport = RandShort()

    for port in ports:
        # sr1() -- send & receive only 1st packet at L3
        packet = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="S"), timeout=1, verbose=0)
        # if packet exists, it'll check if contains layers (like TCP & ICMP)
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print_ports(port, "Closed!")
                elif packet[TCP].flags == 18:
                    print_ports(port, "Open!")
                else:
                    print_ports(ports, "TCP packet is filtered!")
            elif packet.haslayer(ICMP):
                print_ports(port, "ICMP is filtered!")
            else:
                print_ports(port, "Unknown")
                print(packet.summary())

        else:
            print_ports(ports, "Unanswered. Oh no!")

# establish a UDP scan
def udp_scan(target, ports):
    print("UDP scan is on, %s with ports %s" %(target, ports))

    for port in ports:
        # sr1() -- send & receive only 1st packet at L3
        packet = sr1(IP(dst=target)/UDP(sport=port, dport=port),timeout=2,verbose=0)
        if packet == None:
            print_ports(port, "Open or filtered")
        else:
            if packet.haslayer(ICMP):
                print_ports(port, "Closed!")
            elif packet.haslayer(UDP):
                print_ports(port, "Open or filtered")
            else:
                print_ports(port, "Unknown")
                print(packet.summary())

# establish a XMAS scan
def xmas_scan(target, ports):
    print("XMAS scan is on, %s with ports %s" %(target, ports))
    sport = RandShort()

    for port in ports:
        # sr1() -- send & receive only 1st packet at L3
        packet = sr1(IP(dst=target)/TCP(sport=sport, dport=port, flags="FPU"), timeout=1, verbose=0)
        # if packet exists, it'll check if contains layers like TCP & ICMP
        if packet != None:
            if packet.haslayer(TCP):
                if packet[TCP].flags == 20:
                    print_ports(port, "Closed!")
                else:
                    print_ports(port, "TCP flag %s" % packet[TCP].flags)
            elif packet.haslayer(ICMP):
                print_ports(port, "ICMP is filtered!")
            else:
                print_ports(port, "Unknown")
                print(packet.summary())
        else:
            print_ports(port, "Open or filtered")

# setting up the arguments
parser = argparse.ArgumentParser("Port Scanner using Scapy")
parser.add_argument("-t", "--target", help="Specifying target IP", required=True)
parser.add_argument("-p", "--ports", type=int, nargs="+", help="Specifying ports (21 23 80 ...")
parser.add_argument("-s", "--scantype", help="Scan type, SYN/UDP/XMAS", required=True)
args = parser.parse_args()

# argument parsing
target = args.target
scantype = args.scantype

# set ports if passed
if args.ports:
    ports = args.ports
else:
    # back to default range ports
    ports = range(1, 1024)

# scan types
if scantype == "SYN" or scantype == "s":                 # scan type is SYN
    syn_scan(target, ports)
elif scantype == "UDP" or scantype == "u":               # scan type is UDP
    udp_scan(target, ports)
elif scantype == "XMAS" or scantype == "x":               # scan type is XMAS
    xmas_scan(target, ports)
else:
    print("Oops! Scan type is not supported!")
