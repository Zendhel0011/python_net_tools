from packets.arp_packet import Arp_packet, Ethernet_frame
import host
import socket as sk
import ipaddress as ip
from time import sleep


class ScanWithARP():
    """ Scan subnet

    
    """
    def __init__(self, subnet="192.168.1.0/24"):
        self.subnet = ip.IPv4Network(subnet, strict=True)
        my_host = host.Host()
        my_host.my_host()
        self.__my_ip = my_host.ip_addr
        self.__my_mac = my_host.mac_addr

    def scan_subnet(self, interface):
        sock = self.create_raw_sock(interface)
        host_list = self.generate_hosts()
        for host in host_list:
            print("Enviando ARP ping a {}".format(host))
            self.arp_ping(host, sock)
            print("Ping enviado a {}".format(host))
            sleep(0.2)
            



    def generate_hosts(self):
        """Retorna una lista de host
        
        """
        return list(self.subnet.hosts())
    
    def create_raw_sock(self, interface):
        sock = sk.socket(sk.PF_PACKET, sk.SOCK_RAW, sk.htons(0x0800))
        sock.bind((interface, sk.htons(0x0800)))
        return sock
        
    
    def arp_ping(self, host, sock):
        arp_packet = Arp_packet(sha=self.__my_mac, spa=self.__my_ip, tpa=str(host))
        arp_packet.parse_to_net()
        arp = arp_packet.format()
        eth_packet = Ethernet_frame("ff:ff:ff:ff:ff:ff", self.__my_mac, 0x0806, arp)
        eth_packet.parser_to_net()
        arp_packet_complete = eth_packet.format()
        sock.send(arp_packet_complete)

scan = ScanWithARP()
scan.scan_subnet("enp0s3")


        




