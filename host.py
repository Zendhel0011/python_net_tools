import subprocess as sp
import re

class Host():
    def __init__(self, ip_addr="", mac_addr="", name=""):
        self.ip_addr = ip_addr
        self.mac_addr = mac_addr
        self.name = name
        
    def __str__(self):
        return "IPv4: {}, MAC addres: {}, Device MAC name: {}".format(self.ip_addr, self.mac_addr, self.name)

    def my_host(self):
        cmd = sp.run("ifconfig",capture_output=True)
        str_cmd = cmd.stdout.decode("utf-8").split("LOOPBACK")[0]
        my_ip = re.search('((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)', str_cmd).group(0)
        my_mac = re.search('(([aA-fF]|[0-9]){2}:){5}([aA-fF]|[0-9]){2}', str_cmd).group(0)
        self.ip_addr = my_ip
        self.mac_addr = my_mac

