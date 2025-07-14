import cryptography
import socket
#import thread

#IP address and port on which receiver will listen for connections
def startListening(HOST, PORT):
    
    netSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    netSocket.bind((HOST, PORT))
    netSocket.listen()
    netConnection, incAddress = netSocket.accept()

    return netConnection, incAddress

    while True:
        newData = netConnection.recv(1024)
        if newData :
            print(newData)
            netConnection.sendall(newData)

if __name__ == "__main__" :
    netSoc , address = startListening( HOST="127.0.0.1", PORT=65433)
    print(type(netSoc))
    
    while True:
        newData = netSoc.recv(1024)
        if newData :
            print(newData)
            netSoc.sendall(newData)
