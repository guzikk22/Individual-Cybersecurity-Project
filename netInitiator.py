import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import socket
import tools
#import thread
# sends encrypted/authenticated text over the socket
def sendAuthText (text, netCon, encK, authK):
    if len(encK) != 32 or len(authK) != 32 :
        return False
    message = bytes(text, 'utf-8')
    message = message + b' '*(len(message)%16)

    message = tools.PrepareMessage(message, encK, authK)
    netSoc.sendall( tools.int_to_bytes(len(message), 16) )
    netSoc.sendall( message )
    return True

#IP address and port to which initiator will attempt to connect
def startConnection(HOST, PORT):
    
    netSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    netSocket.connect((HOST, PORT))

    return netSocket

def RepudiableAuthenticationProtocol(netSoc, privK):
    pass

if __name__ == "__main__" :
    
    
    netSoc = startConnection( HOST="127.0.0.1", PORT=65433)

    while True :
        message = input()
        netSoc.sendall(bytes(message, "utf-8"))
        newData = netSoc.recv(1024)
        print(newData)
