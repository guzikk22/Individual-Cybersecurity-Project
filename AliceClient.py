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
def RepudiableAuthenticationProtocol_Alice(netSoc, Their_pubKey):
	
	with open("AlicePrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None,
		)
		f.close()
	My_pubKey = My_privKey.public_key()
	incData = b''
	# step 1
	# Secret to be shared
	S = os.urandom(64)
	if verbose:
		print('S = ', end='')
		print(S)
	# step 2
	# Encapsulated secret
	int_S = tools.bytes_to_int( tools.OAEP(S, b'encapsulation') )
	int_S = tools.modExp(
		b = int_S,
		e = Their_pubKey.public_numbers().e,
		mod = Their_pubKey.public_numbers().n,
		)
	enS = tools.int_to_bytes(int_S, 256)
	# Send initial message
	Send(netSoc, enS)
	# step 4
	# encryption key and authentication key
	encK = S[:32]
	authK = S[32:]
	if verbose:
		print('encK = ', end='')
		print(encK)
		print('authK = ', end='')
		print(authK)
	# step 7
	# Receive message 1
	while len(incData)<560:
		incData += netSoc.recv(560)

	com0 = tools.ReadMessage(
		pm = incData[:560],
		encK = encK,
		authK = authK
		)
	incData = incData[560:]

	com1 = com0[256:]
	com0 = com0[:256]

	m_int = tools.trueRand_int( My_pubKey.public_numbers().n )
	m_bytes = tools.int_to_bytes(m_int)
	# Send message 2
	Send(netSoc, tools.PrepareMessage(
		m = m_bytes,
		encK = encK,
		authK = authK
		)
	)
	if verbose:
	     print('COM(v0) = ', end='')
	     print(com0)
	     print('COM(v1) = ', end='')
	     print(com1)
	     print('m = ', end='')
	     print(m_int)
	# step 9
	# Receive message 3
	while len(incData)<368:
		incData += netSoc.recv(368)
	s1 = incData[:368]
	incData = incData[368:]
	s1 = tools.ReadMessage(
		pm = s1,
		encK = encK,
		authK = authK
		)
	v0 = s1[:128]
	s0 = s1[128:160]
	v1 = s1[160:288]
	s1 = s1[288:320]
	
	if verbose:
		print('v0 = ', end='')
		print(v0)
		print('s0 = ', end='')
		print(s0)
		print('v1 = ', end='')
		print(v1)
		print('s1 = ', end='')
		print(s1)
	
	test = tools.OAEP_cs(v0, b'commitment', s0)
	test = tools.RSA_crypt(
		m = test,
		e = Their_pubKey.public_numbers().e,
		n = Their_pubKey.public_numbers().n
		)
##	if verbose:
##		print('test0 = ', end='')
##		print(test)
	if test != com0 :
		return (b'',b'')
	test = tools.OAEP_cs(v1, b'commitment', s1)
	test = tools.RSA_crypt(
		m = test,
		e = Their_pubKey.public_numbers().e,
		n = Their_pubKey.public_numbers().n
		)
##	if verbose:
##		print('test1 = ', end='')
##		print(test)
	if test != com1 :
		return (b'',b'')
	print("<<COMMITMENT VERIFIED>>")
	# step 10
	v = tools.bytes_to_int(v0+v1)
	# step 11
	c = v + m_int
	c = c%My_pubKey.public_numbers().n
	if verbose:
		print('c=', end='')
		print(c)
	# step 12
	r = tools.modExp(
		b = c,
		e = My_privKey.private_numbers().d,
		mod = My_pubKey.public_numbers().n
		)
	if verbose:
		print('r = ', end='')
		print(r)
	# Send message 4
	r_bytes = tools.int_to_bytes(r, 256)
	Send(netSoc, tools.PrepareMessage(
		m = r_bytes,
		encK = encK,
		authK = authK
		)
	)
	print("<<PROTOCOL COMPLETED>>")
	return (encK, authK)

if __name__ == "__main__" :
	global verbose
	verbose = 1
	# Load keys
	with open("BobPubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)

	netSoc = startConnection( HOST="127.0.0.1", PORT=65433 )

	encK, authK = RepudiableAuthenticationProtocol_Alice(netSoc, Their_pubKey)

	input("Press Enter To Quit")
