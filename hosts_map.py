import subprocess
import re
from host import Host

def filter_address(to_filter):
    """ Returns host object

        The keys from the object is a ip address and the value is the MAC addres
    """
    ptt_ip = re.search('\([0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\.[0-9]{,3}\)', to_filter)
    ptt_mac = re.search(r'\w\w:\w\w:\w\w:\w\w:\w\w:\w\w', to_filter)
    find_lword = to_filter.split("\n")
    del find_lword[-1]
    find_lword = find_lword[-1]
    ptt_device_name = re.search('\(.*\)', find_lword)
    host_active = {}
    if ptt_ip and ptt_mac and ptt_device_name:
        host_active = Host(ptt_ip.group(0), ptt_mac.group(0), ptt_device_name.group(0))
        return host_active
    elif ptt_ip and ptt_mac and ptt_device_name==None:
        host_active = Host(ptt_ip.group(0), ptt_mac.group(0), None)
        return host_active
    elif ptt_ip and ptt_mac==None and ptt_device_name.group(0):
        host_active = Host(ptt_ip.group(0), None, None)
        return host_active
    else:
        host_active = Host(None, ptt_mac.group(0), ptt_device_name.group(0))
        return host_active

    

def scan_net(sub_net):
    """Scan subnet
    
    Return a list of host Object with all host scanned at the subred
    """
    sub_net = str(sub_net)
    list_host = []
    str_nmap = subprocess.run(["nmap", "-sP", sub_net],capture_output=True)
    str_nmap = str_nmap.stdout.decode("utf-8")
    arr_host = str_nmap.split("Nmap scan report for")
    del arr_host[0]
    active_hosts = map(filter_address, arr_host)
    for host in active_hosts:    
        list_host.append(host)
    return list_host

hosts = scan_net("192.168.1.*")
for x in hosts:
    print(x)