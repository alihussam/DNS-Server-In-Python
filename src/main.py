import socket, glob, json
from dnslib import *
import dns.resolver

def load_zones():

    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    return jsonzone

zonedata = load_zones()


def getzone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    return zonedata.get(zone_name,{})

class DNS:
    def __init__(self, data):
        self.data = data
        self.DNSTYPE = ''
        self.TRANSACTION_ID = self.data[:2]
        self.OPCODE = ''    
        self.SUPPORTED_RECORD_TYPES = {
            '0001':'a',
            '0005':'cname'
        }
        self.SUPPORTED_OPCODE = ['0000']
        
        #get qtype    
        self.DNSTYPE = self.SUPPORTED_RECORD_TYPES.get(self.data[-4:-2].hex(),b"NOT SUPPORTED")
        #get opcode
        byte1 = (self.data[2:4])[:1]
        for bit in range(1,5):
            self.OPCODE += str(ord(byte1)&(1<<bit))

    def response(self):
        #Check if query kind is supported
        if self.OPCODE not in self.SUPPORTED_OPCODE:
            return self.generate_Not_Implemented()
        elif self.DNSTYPE == b"NOT SUPPORTED":
            return self.generate_Refuse()
        else:
            return self.generate_response_packet()    

    def generate_Refuse(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'1'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0101', 2).to_bytes(1, byteorder='big')     
        return self.TRANSACTION_ID + FLAGS + self.data[4:]

    def generate_Name_Error(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'1'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0011', 2).to_bytes(1, byteorder='big')     
        return self.TRANSACTION_ID + FLAGS + self.data[4:]

    def generate_Not_Implemented(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'1'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0100', 2).to_bytes(1, byteorder='big')     
        return self.TRANSACTION_ID + FLAGS + self.data[4:]

    def generate_Server_Failure(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'1'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0010', 2).to_bytes(1, byteorder='big')     
        return self.TRANSACTION_ID + FLAGS + self.data[4:]

    def generate_Empty(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'0'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0000', 2).to_bytes(1, byteorder='big')  
        return self.TRANSACTION_ID+ FLAGS + self.data[4:]

    def getquestiondomain(self, data):
        state = 0
        expectedlength = 0
        domainstring = ''
        domainparts = []
        x = 0
        for byte in data:
            if state == 1:
                if byte != 0:
                    domainstring += chr(byte)
                x += 1
                if x == expectedlength:
                    domainparts.append(domainstring)
                    domainstring = ''
                    state = 0
                    x = 0
                if byte == 0:
                    domainparts.append(domainstring)
                    break
            else:
                state = 1
                expectedlength = byte
        questiontype = data[-4:-2]

        return (domainparts, questiontype)

    def getrecs(self, data):
        domain, questiontype = self.getquestiondomain(data)
        qt = self.DNSTYPE
        # if questiontype == b'\x00\x01':
        #     qt = 'a'
        zone = getzone(domain)
        if zone == {}:
            return ("NotAA",qt,domain)
        return (zone.get(qt,""), qt, domain)

    def buildquestion(self, domainname, rectype):
        qbytes = b''

        for part in domainname:
            length = len(part)
            qbytes += bytes([length])

            for char in part:
                qbytes += ord(char).to_bytes(1, byteorder='big')

        if rectype == self.DNSTYPE:
            qbytes += (1).to_bytes(2, byteorder='big')

        qbytes += (1).to_bytes(2, byteorder='big')

        return qbytes

    def rectobytes(self, domainname, rectype, recttl, recval):
        rbytes = b'\xc0\x0c'
        if rectype == self.DNSTYPE:
            rbytes = rbytes + bytes([0]) + bytes([1])
        rbytes = rbytes + bytes([0]) + bytes([1])
        rbytes += int(recttl).to_bytes(4, byteorder='big')
        if rectype == self.DNSTYPE:
            rbytes = rbytes + bytes([0]) + bytes([4])
            for part in recval.split('.'):
                rbytes += bytes([int(part)])
        return rbytes

    def generate_response_packet(self):
        #QR+OPCODE+AA+TC+RD && RA+Z+RCODE
        FLAGS = int('1'+self.OPCODE+'1'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0000', 2).to_bytes(1, byteorder='big')     
        QDCOUNT = b'\x00\x01'
        records = self.getrecs(self.data[12:])
        print(records[0])
        if records[0] == "NotAA":
            FLAGS = int('1'+self.OPCODE+'0'+'0'+'0', 2).to_bytes(1, byteorder='big')+int('0'+'000'+'0000', 2).to_bytes(1, byteorder='big')  
            try:   
                answers = dns.resolver.query('.'.join(self.getrecs(self.data[12:])[2]), str(self.DNSTYPE))
            except:
                return self.generate_Empty()
            count =0
            ips = []
            for ip_val in answers:
                count += 1
                ips.append(ip_val.to_text())
            ANCOUNT = count.to_bytes(2,byteorder='big')
            NSCOUNT = (0).to_bytes(2, byteorder='big')
            ARCOUNT = (0).to_bytes(2, byteorder='big')    
            dnsheader = self.TRANSACTION_ID+FLAGS+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
            dnsbody = b''
            records, rectype, domainname = self.getrecs(self.data[12:])
            dnsquestion = self.buildquestion(domainname, rectype)
            for ip in ips:
                dnsbody += self.rectobytes(domainname, rectype, 3600, ip)   
            return dnsheader + dnsquestion + dnsbody

        ANCOUNT = len(records[0]).to_bytes(2, byteorder='big')
        if ANCOUNT == b'\x00\x00':
            return self.generate_Name_Error()
        NSCOUNT = (0).to_bytes(2, byteorder='big')
        ARCOUNT = (0).to_bytes(2, byteorder='big')
        dnsheader = self.TRANSACTION_ID+FLAGS+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT
        dnsbody = b''
        records, rectype, domainname = self.getrecs(self.data[12:])
        dnsquestion = self.buildquestion(domainname, rectype)
        for record in records:
            dnsbody += self.rectobytes(domainname, rectype, record["ttl"], record["value"])
        return dnsheader + dnsquestion + dnsbody

#Main function
def main():
    buffer_size = 512
    server_port = 53
    server_ip = '127.0.0.1'
    
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    serverSocket.bind( (server_ip, server_port) )
    
    try:
        while 1:
            print(':: Listening ..')
            data, address = serverSocket.recvfrom( buffer_size )
            QUERY = DNS(data)
            packet = QUERY.response()
            serverSocket.sendto(packet, address)
            print(":: RESPONSE => "+str(address))
    except KeyboardInterrupt:
        print(':: SHUTTING DOWN SERVER ::')
        serverSocket.close()


#Start Point
if __name__ == '__main__':
    print(':: DNS ACTIVATED ::')
    main()

