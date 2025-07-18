import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.serialization as SERIAL
import os
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

# Returns a encryption key and authentication key if successful
def RepudiableAuthenticationProtocol_Bob(netSoc, Their_pubKey):
	
	with open("BobPrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None,
		)
		f.close()
        My_pubKey = My_privKey.public_key()

        incData = b''
        while len(incData)<256:
                incData += netSoc.recv(256)

        enS = incData[:256]
        incData = incData[256:]

        int_S = tools.bytes_to_int(enS)
        int_S = tools.modExp(
        b = int_S,
        e = My_privKey.private_numbers().d,
        mod = My_pubKey.public_numbers().n,
        )
        # Shared secret
        S = tools.deOAEP( tools.int_to_bytes(int_S, 256), b'encapsulation' )
        # encryption key and authentication key
        encK = S[:32]
	authK = S[32:]

                
if __name__ == "__main__" :
	# Load keys
	with open("AlicePubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)

	netSoc , address = startListening( HOST="127.0.0.1", PORT=65433)
	RepudiableAuthenticationProtocol_Bob(netSoc, Their_pubKey)

		
	input("Press Enter To Quit")

