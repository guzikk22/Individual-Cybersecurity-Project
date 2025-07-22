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

def Send(netSoc, m):
	netSoc.sendall(m)
	if verbose > 1:
		print()
		print('>>', end='')
		print(len(m), end='')
		print('>>', end='')
		print(m)
		print()

def Recv(netSoc, n):
	m = netSoc.recv(n)
	if verbose > 1:
		print()
		print('<<', end='')
		print(len(m), end='')
		print('<<', end='')
		print(m)
		print()
	return m

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
	# step 3
	# Receive initial message
	while len(incData)<256:
		incData += Recv(netSoc, 256)

	enS = incData[:256]
	incData = incData[256:]

	S = tools.RSA_crypt(
		m = enS,
		e = My_privKey.private_numbers().d,
		n = My_pubKey.public_numbers().n
		)
	S = tools.deOAEP( S, b'encapsulation' )
	if verbose:
		print('S = ', end='')
		print(S)
	# step 4
	# encryption key and authentication key
	encK = S[:32]
	authK = S[32:]
	if verbose:
		print('encK = ', end='')
		print(encK)
		print('authK = ', end='')
		print(authK)
	# step 5
	v = tools.trueRand_int( Their_pubKey.public_numbers().n )
	v1 = tools.int_to_bytes(v, 256)
	v0 = v1[:128]
	v1 = v1[128:]
	if verbose:
		print('v = ', end='')
		print(v)
		print('v0 = ', end='')
		print(v0)
		print('v1 = ', end='')
		print(v1)
	# step 6
	s0 = os.urandom(32)
	com0 = tools.OAEP_cs(v0, b'commitment', s0)
	com0 = tools.RSA_crypt(
		m = com0,
		e = My_pubKey.public_numbers().e,
		n = My_pubKey.public_numbers().n
		)
	s1 = os.urandom(32)
	com1 = tools.OAEP_cs(v1, b'commitment', s1)
	com1 = tools.RSA_crypt(
		m = com1,
		e = My_pubKey.public_numbers().e,
		n = My_pubKey.public_numbers().n
		)
	if verbose:
		print('COM(v0) = ', end='')
		print(com0)
		print('s0 = ', end='')
		print(s0)
		print('COM(v1) = ', end='')
		print(com1)
		print('s1 = ', end='')
		print(s1)
	# Send message 1
	Send(netSoc, tools.PrepareMessage(
		m = com0 + com1,
		encK = encK,
		authK = authK
		)
	)
	# step 8
	# Receive message 2
	while len(incData)<304:
		incData += Recv(netSoc, 304)

	m_bytes = incData[:304]
	incData = incData[304:]

	m_bytes = tools.ReadMessage(
		pm = m_bytes,
		encK = encK,
		authK = authK
		)
	m_int = tools.bytes_to_int(m_bytes)
	if verbose:
		print('m = ', end='')
		print(m_int)

	# Send message 3
	Send(netSoc, tools.PrepareMessage(
		m = v0 + s0 + v1 + s1,
		encK = encK,
		authK = authK
		)
	)
	# step 11
	c = v + m_int
	c = c%Their_pubKey.public_numbers().n
	if verbose:
		print('c = ', end='')
		print(c)
	# step 13
	# Receive message 4
	while len(incData)<304:
		incData += netSoc.recv(304)
	r_bytes = incData[:304]
	incData = incData[304:]

	r_bytes = tools.ReadMessage(
		pm = r_bytes,
		encK = encK,
		authK = authK
		)
	r = tools.bytes_to_int(r_bytes)
	if verbose:
		print('r = ', end='')
		print(r)

	test = tools.modExp(
		b = r,
		e = Their_pubKey.public_numbers().e,
		mod = Their_pubKey.public_numbers().n
		)
	if test != c:
		return (b'',b'')
	print("<<RESPONSE VERIFIED>>")
	print("<<PROTOCOL COMPLETED>>")
	return (encK, authK)
	
if __name__ == "__main__" :
	global verbose
	verbose = 1
	# Load keys
	with open("AlicePubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)

	netSoc , address = startListening( HOST="127.0.0.1", PORT=65433)
	
	encK, authK = RepudiableAuthenticationProtocol_Bob(netSoc, Their_pubKey)

	input("Press Enter To Quit")
