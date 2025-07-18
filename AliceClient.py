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

#IP address and port to which initiator will attempt to connect
def startConnection(HOST, PORT):
	
	netSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	netSocket.connect((HOST, PORT))

	return netSocket

# Returns a encryption key and authentication key if successful
def RepudiableAuthenticationProtocol_Alice(netSoc, Their_pubKey):
	
	with open("AlicePrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None,
		)
		f.close()
	# Secret to be shared
	S = os.urandom(64)
	# Encapsulated secret
	int_S = tools.bytes_to_int( tools.OAEP(S, b'encapsulation') )
	int_S = tools.modExp(
                b = int_S,
		e = Their_pubKey.public_numbers().e,
		mod = Their_pubKey.public_numbers().n,
		)
	enS = tools.int_to_bytes(int_S, 256)
	netSoc.sendall(enS)
        # encryption key and authentication key
	encK = S[:32]
	authK = S[32:]

if __name__ == "__main__" :
	# Load keys
	with open("BobPubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)

	netSoc = startConnection( HOST="127.0.0.1", PORT=65433 )

	RepudiableAuthenticationProtocol_Alice(netSoc, Their_pubKey)

	input("Press Enter To Quit")
