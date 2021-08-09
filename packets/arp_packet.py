import struct
import socket
import ipaddress
import binascii

#Clase que crea y formatea de host a bytes para red un packete arp
class Arp_packet():
    global hexa
    def __init__(self, htype = 0x0001, ptype = 0x0800, hlen = 0x6, plen = 0x04, opcode = 0x0001, sha = "", spa ="", tha=None, tpa=""):
    #constructor del paquet arp, configurado inicialmente para hacer una request por IPv4, Ethernet
    #Debe ingresar argumentos para mac de origen, ip origen, ip destino, (opcional)-> mac destino.

        self._htype = htype
        self._ptype = ptype
        self._hlen = hlen
        self._plen = plen
        self._opcode = opcode
        #Este condicional debe ser mejorado, checkea que hallan ingresado 6 valores
        #Luego usa la global Hexa para ponerle tipo de dato hexadecimal a cada espacio de la lista de macs.

        if len(sha.split(":")) == 6:
            self._sha = sha.split(":")
            hexa="0x"
            for x, y in enumerate(self._sha):
                self._sha[x]= hexa+y
        else:
            raise ipaddress.AddressValueError("sha is not mac address. Expected Mac Addres: 'ff:ff:ff:ff:ff:ff'")
        #Comprobacion de ip
        if len(spa.split(".")) == 4:
            self._spa = spa.split(".")
        else:
            raise ipaddress.AddressValueError("source ip it's bad value")
        #Mac destino, (comprueba si es none porque es opcional ingresarla en la istancia de la clase)
        #Si la ingresas en la istancia entonces será procesada como las otras mac y pasada a hexa por cada byte
        if tha == None:
            self._tha = ["0x00","0x00","0x00","0x00","0x00","0x00"]
        elif len(tha.split(":")) == 6:
            self._tha = tha.split(":")
            hexa="0x"
            for x, y in enumerate(self._tha):
                self._tha[x]= hexa+y
        else:
            raise ipaddress.AddressValueError("tha is not mac address. Expected Mac Addres: 'ff:ff:ff:ff:ff:ff'")
        if len(tpa.split(".")) == 4:
            self._tpa = tpa.split(".")
        else:
            raise ipaddress.AddressValueError("source ip it's bad value")
        
    #Funcion que parsea los datos ingresados de decimal(hexa) a bytes.

    def parse_to_net(self):
        aux = b'' #variable auxiliar para concatenar bytes
        self._htype = self._htype.to_bytes(2,'big')
        self._ptype = self._ptype.to_bytes(2,'big')
        self._hlen = self._hlen.to_bytes(1,'big')
        self._plen = self._plen.to_bytes(1,'big')
        self._opcode = self._opcode.to_bytes(2,'big')
        for y in self._sha:
           aux += int(y, 16).to_bytes(1,'big')
        self._sha = aux
        aux = b''
        for y in self._spa:
            aux += int(y).to_bytes(1, 'big')
        self._spa = aux
        aux = b''
        #comprueba si se ingresó la mac destino para procesarla en caso afirmativo
        for y in self._tha:
            aux += int(y, 16).to_bytes(1,'big')
        self._tha = aux
        aux= b''
        for y in self._tpa:
            aux += int(y).to_bytes(1,'big')
        self._tpa = aux
        del aux
        #Al terminar la ejecución de la función todos los atributos del objeto estaŕan en formato de bytes
        # Se deberia implementar para volverlos al formato hexa o decimal. 
    
    #Método para formatear todos los atributos del objeto en una cadena de bytes concatenandolos.
    def format(self):
        to_return = self._htype+self._ptype+self._hlen+self._plen+self._opcode+self._sha+self._spa+self._tha+self._tpa
        return to_return #retorna los bytes formateados.

    def __str__(self) -> str:
        return """Hardware type: {}
            Protocol type: {}
            Hardware len: {}
            Protocol len: {}
            Option code: {}
            Source Mac: {}
            Source IP: {}
            Target Mac: {}
            Target IP: {}""".format(self._htype, self._ptype, self._hlen, self._plen, self._opcode,
             self._sha, self._spa, self._tha,self._tpa)

class Ethernet_frame(): 
    global hexa
    def __init__(self, target_mac,source_mac, ether_type, arp):
        if type(arp) is bytes:
            hexa = "0x"
            # Aqui debo implementar un filtro para que pongan bien las mac como parametro
            self._target_mac = target_mac.split(":")
            self._source_mac = source_mac.split(":")
            self._ether_type = ether_type
            self._arp = arp
            for x, y in enumerate(self._target_mac):
                self._target_mac[x] = hexa + y
            for x, y in enumerate(self._source_mac):
                self._source_mac[x] = hexa + y
        else:
            raise ValueError("Ethernet_frame(arp) expected <class Arp_packet.format()>")
   

    def parser_to_net(self):
        aux = b''
        for y in self._target_mac:
           aux += int(y, 16).to_bytes(1,'big')
        self._target_mac = aux
        aux = b''
        for y in self._source_mac:
            aux += int(y, 16).to_bytes(1,'big')
        self._source_mac = aux
        aux = b''
        self._ether_type = self._ether_type.to_bytes(2,"big")
        del aux

    def format(self):
        formated = self._target_mac+self._source_mac+self._ether_type+self._arp
        return formated

    def __str__(self) -> str:
        return """TARGET_MAC: {}
        SOURCE_MAC: {}
        ETHER_TYPE: {}
        ARP_HEADER: {}
        """.format(self._target_mac, self._source_mac, self._ether_type, self._arp)
        


arp1 = Arp_packet(sha="08:00:27:87:7b:17", spa="192.168.1.11", tpa="192.168.1.2")
#arp1.parse_to_net()
#formato = arp1.format()
#print(type(formato))
#eth = Ethernet_frame("00:11:22:33:44:55", "ff:ff:ff:ff:ff:ff", 0x0800, formato)
#eth.parser_to_net()
#print(eth)
