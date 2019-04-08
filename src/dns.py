import socket

############# DEF START ###############

def buildresponse(data):
    #Get first two bytes because first two bytes are transaction ids
    print('Extracting Transaction ID ...')
    tid = data[:2]
    transactionID = ''
    for byte in tid:
        transactionID += hex(byte)[2:]  #[2:] because we dont want 0x at the start of hex
    print(transactionID)
    print('Transaction ID Extracted!')

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
