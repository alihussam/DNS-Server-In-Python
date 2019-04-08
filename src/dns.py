import socket

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
    