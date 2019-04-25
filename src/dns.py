import socket


############# DEF START ###############

def getFlags(flags):
    #extract bytes, byte function converts args to bytes
    #BYTE1 contains QR,OPCODE, AA,TC,RD flags
    byte1 = bytes(flags[:1])
    #BYTE2 contains RA, Z, RCODE flags
    byte2 = bytes(flags[1:2])
    #First bit of flag bytes is QR, for qquery 0 & response 1
    responseFlags = ''
    #Because we need to send response set QR = 1
    QR = '1'
    #we will extract opcode from query 
    #opcode is stored in bits 2 to 5 in byte1 
    OPCODE = ''
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))
    #After opcode we have authoritative answer, Always gonna be one
    AA = '1'
    #Becuase we are sending a short message we will assume that we never truncate the message
    TC = '0'
    #Becuase we are not supporting recursion so
    RD = '0'
    #SECOND BYTE STARTS HERE
    RA = '0'
    #Z reserved for future uses, not used in internet for now
    #Because Z has 3 bytes 
    Z = '000'
    #RCODE tells if DNS Query was successful, for simplicity letes assume all were successful
    RCODE = '0000'

    #return all flags
    #2 because base 2, byte order big endan
    return int(QR+OPCODE+AA+TC+RD, 2).to_bytes(1, byteorder='big')+int(RA+Z+RCODE, 2).to_bytes(1, byteorder='big')

def getQuestionDomain(data):
    state = 0
    expectedlength = 0
    domainString = ''
    domainParts = []
    x = 0; y = 0
    for byte in data:
        if state == 1:
            domainString += chr(byte)
            x += 1
            if x == expectedlength:
                domainParts.append(domainString)
                domainString = ''
                state = 0
                x = 0
            if byte == 0:
                domainParts.append(domainString)
                break
        else:
            state =1
            expectedlength = byte
        y += 1

    questionType = data[y:y+3]
    print(questionType)
    print(domainParts)    
    return (questionType, domainParts)


def buildresponse(data):
    #Get first two bytes because first two bytes are transaction ids
    print('Extracting Transaction ID ...')
    tid = data[:2]
    transactionID = ''
    for byte in tid:
        transactionID += hex(byte)[2:]  #[2:] because we dont want 0x at the start of hex
    print(transactionID)
    print('Transaction ID Extracted!')

    #Get the Flags here, passing 3rd and 4th byte as these contains flags, particularly a bit for each one
    flags = getFlags(data[2:4])
    print(flags)
    #Question count is always 1 in practical 
    #QDCOUNT HAS 2 bytes but as only 1 query is practical only last bit is set to 1
    QDCOUNT = b'\x00\x01'

    #Now get question
    #we will send domain name directly
    getQuestionDomain(data[12:])
    

############# DEF END #################

buffer_size = 512   #query packet size <= 512 bytes 

server_port = 53
server_ip   = '127.0.0.1'

#Create a socket and bind it to port and IP.
serverSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
serverSocket.bind( (server_ip, server_port) )                       #socket.bind(address) where address = (host, port)

#Starts listening for the requests
while 1:
    data, address = serverSocket.recvfrom( buffer_size )
    #print the query data server recieves for now
    print( data )
    #FOR TEST 1
    # #Because send to doesn't take regular strings but string of bytes so put b before string.
    # serverSocket.sendto(b'Sup Mate?', address)

    #Building a DNS response message
    #Passing data as param to buildresponse so it can extract info from original request
    response = buildresponse(data)
    #serverSocket.sendto(response, address)
