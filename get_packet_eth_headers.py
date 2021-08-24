import socket as sk
import struct
import binascii as btoh
raw_socket = sk.socket(sk.AF_PACKET, sk.SOCK_RAW, sk.htons(0x003))

def parse_binary_to_hex(bin):
    """ Parsea los headers a hexadecimal

    """
    list_bin = []
    if len(bin)<=3:
        for x in bin:
            list_bin.append(btoh.hexlify(x))
        return list_bin
    elif len(bin)>3:
        for x, y in enumerate(bin):
            if x == 6 or x==8:
                list_bin.append(sk.inet_ntoa(y))
            else:
                list_bin.append(btoh.hexlify(y))
        return list_bin

def get_packets_headers(packet):
    ethernet_header = packet[0:14]
    ethernet_header = struct.unpack("!6s6s2s", ethernet_header)
    arp_header = packet[14:42]
    arp_header = struct.unpack("!2s2s1s1s2s6s4s6s4s",arp_header)
    return (ethernet_header, arp_header)

def map_headers(ethernet_header, arp_header):
    eth = {}
    arp = {}
    for x, y in enumerate(ethernet_header):
        if x == 0:
            eth["mac_destination"]=y
        elif x == 1:
            eth["mac_origin"]=y
        elif x == 2:
            eth["proto"]=y
    for x, y in enumerate(arp_header):
        if x == 0:
            arp["htype"]=y
        elif x == 1:
            arp["ptype"]=y
        elif x == 2:
            arp["hlen"]=y
        elif x == 3:
            arp["plen"]=y
        elif x == 4:
            arp["opcode"]=y
        elif x == 5:
            arp["sha"]=y
        elif x == 6:
            arp["spa"]=y
        elif x == 7:
            arp["tha"]=y
        elif x == 8:
            arp["tpa"]=y
    return (eth, arp)

def report(eth, arp):
    print("**********ETHERNET-HEADERS************")
    print("MAC_DESTINATION----",eth["mac_destination"],"**")
    print("SOURCE_MAC---------",eth["mac_origin"],"**")
    print("PROTOCOL-----------",eth["proto"],"        **")
    print("**********--ARP-HEADERS--*************")
    print("HARDWARE_TYPE--------",arp["htype"],"      **")
    print("PROTOCOL_TYPE--------",arp["ptype"],"      **")
    print("HARDWARE_LENGTH------",arp["hlen"],"        **")
    print("PROTOCOL_LENGTH------", arp["plen"],"        **")
    print("OPTION(REQ-1, RES-2)-", arp["opcode"],"      **")
    print("SOURCE_MAC-----------", arp["sha"],"**")
    print("SOURCE_IP------------", arp["spa"],"**")
    print("TARGET_MAC-----------", arp["tha"],"**")
    print("TARGET_IP------------", arp["tpa"],"**")
    print("**************************************")

while True:
    packet, addr = raw_socket.recvfrom(2048)
    ethernet_header, arp_header = get_packets_headers(packet)
    ethernet_header = parse_binary_to_hex(ethernet_header)
    arp_header = parse_binary_to_hex(arp_header)
    eth, arp = map_headers(ethernet_header, arp_header)
    report(eth, arp)
    