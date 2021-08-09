class Host():
    def __init__(self, ip_addr, mac_addr, name):
        self.ip_addr = ip_addr
        self.mac_addr = mac_addr
        self.name = name
        
    def __str__(self):
        return "IPv4: {}, MAC addres: {}, Device MAC name: {}".format(self.ip_addr, self.mac_addr, self.name)
        
        