import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.serialization as SERIAL
import os
import socket
import tools

def SendAuthText(text, encK, authK, netSoc, seq_n):
	if seq_n >= 2**63:
		return False
	m = bytes(text, encoding="utf-8")
	m += b' '*( (-len(m)+8)%16 )
	m += tools.int_to_bytes(2**64-seq_n-1, 8)
	if len(m)%16!=0 :
		return False
	m = tools.PrepareMessage(
		m = m,
		encK = encK,
		authK = authK,
		)
	l = tools.int_to_bytes(len(m), 8)
	Send(netSoc, l+m)
	if verbose:
		oFile.write('>>TEXT>>  ')
		oFile.write(text)
		oFile.write('\n')
	return True

def RecvAuthText(encK, authK, netSoc, seq_n):
	if seq_n >= 2**63:
		return ''
	incData = b''
	while len(incData)<8:
		incData += Recv(netSoc, 8-len(incData))

	l = tools.bytes_to_int(incData[:8])
	incData = incData[8:]

	while len(incData)<l:
		incData += Recv(netSoc, l-len(incData))
	m = incData[:l]
	incData = incData[l:]

	m = tools.ReadMessage(
		pm = m,
		encK = encK,
		authK = authK
		)
	if tools.bytes_to_int(m[-8:]) != seq_n:
		if verbose:
			oFile.write('<<ERROR<<\n')
		return ''
	text = tools.bytes_to_str(m[:-8])
	while text[-1]==' ':
		text = text[:-1]

	if verbose:
		oFile.write('<<TEXT<<  ')
		oFile.write(text)
		oFile.write('\n')
	return text

#IP address and port to which initiator will attempt to connect
def startConnection(HOST, PORT):
	
	netSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	netSocket.connect((HOST, PORT))

	return netSocket

def Send(netSoc, m):
	netSoc.sendall(m)
	if verbose > 1:
		oFile.write('>>>')
		oFile.write(len(m))
		oFile.write('>>>  ')
		oFile.write(tools.bytes_strRep(m))
		oFile.write('\n')

def Recv(netSoc, n):
	m = netSoc.recv(n)
	if verbose > 1:
		oFile.write('<<<')
		oFile.write(len(m))
		oFile.write('<<<  ')
		oFile.write(tools.bytes_strRep(m))
		oFile.write('\n')
	return m

# Returns a encryption key and authentication key if successful
def RepudiableAuthenticationProtocol_Alice(netSoc, My_privKey, Their_pubKey):
	
	My_pubKey = My_privKey.public_key()
	incData = b''
	# step 1
	# Secret to be shared
	S = os.urandom(64)
	if verbose:
		oFile.write('S = ')
		oFile.write(tools.bytes_strRep(S))
		oFile.write('\n')
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
		oFile.write('encK = ')
		oFile.write(tools.bytes_strRep(encK))
		oFile.write('\n')
		oFile.write('authK = ')
		oFile.write(tools.bytes_strRep(authK))
		oFile.write('\n')
	# step 7
	# Receive message 1
	while len(incData)<560:
		incData += netSoc.recv(560-len(incData))

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
	     oFile.write('COM(v0) = ')
	     oFile.write(tools.bytes_strRep(com0))
	     oFile.write('\n')
	     oFile.write('COM(v1) = ')
	     oFile.write(tools.bytes_strRep(com1))
	     oFile.write('\n')
	     oFile.write('m = ')
	     #oFile.write(str(m_int))
	     oFile.write('\n')
	# step 9
	# Receive message 3
	while len(incData)<368:
		incData += netSoc.recv(368-len(incData))
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
		oFile.write('v0 = ')
		oFile.write(tools.bytes_strRep(v0))
		oFile.write('\n')
		oFile.write('s0 = ')
		oFile.write(tools.bytes_strRep(s0))
		oFile.write('\n')
		oFile.write('v1 = ')
		oFile.write(tools.bytes_strRep(v1))
		oFile.write('\n')
		oFile.write('s1 = ')
		oFile.write(tools.bytes_strRep(s1))
		oFile.write('\n')
	
	test = tools.OAEP_cs(v0, b'commitment', s0)
	test = tools.RSA_crypt(
		m = test,
		e = Their_pubKey.public_numbers().e,
		n = Their_pubKey.public_numbers().n
		)
##	if verbose:
##		oFile.write('test0 = ')
##		oFile.write(tools.bytes_strRep(test))
##		oFile.write('\n')
	if test != com0 :
		return (b'',b'')
	test = tools.OAEP_cs(v1, b'commitment', s1)
	test = tools.RSA_crypt(
		m = test,
		e = Their_pubKey.public_numbers().e,
		n = Their_pubKey.public_numbers().n
		)
##	if verbose:
##		oFile.write('test1 = ')
##		oFile.write(tools.bytes_strRep(test))
##		oFile.write('\n')
	if test != com1 :
		return (b'',b'')
	if verbose:
		oFile.write("{COMMITMENT VERIFIED}")
		oFile.write('\n')
	# step 10
	v = tools.bytes_to_int(v0+v1)
	# step 11
	c = v + m_int
	c = c%My_pubKey.public_numbers().n
	if verbose:
		oFile.write('c = ')
		#oFile.write(str(c))
		oFile.write('\n')
	# step 12
	r = tools.modExp(
		b = c,
		e = My_privKey.private_numbers().d,
		mod = My_pubKey.public_numbers().n
		)
	if verbose:
		oFile.write('r = ')
		#oFile.write(str(r))
		oFile.write('\n')
	# Send message 4
	r_bytes = tools.int_to_bytes(r, 256)
	Send(netSoc, tools.PrepareMessage(
		m = r_bytes,
		encK = encK,
		authK = authK
		)
	)
	if verbose:
		oFile.write("{PROTOCOL COMPLETED}")
		oFile.write('\n')
	return (encK, authK)

global verbose
verbose = 0
global oFile
oFile = open("AliceOutput.txt", 'w')

if __name__ == "__main__" :
	verbose = 1
	# Load keys
	with open("BobPubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read()
		)
		f.close()
	with open("AlicePrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None
		)
		f.close()

	netSoc = startConnection( HOST="127.0.0.1", PORT=65433 )

	encK, authK = RepudiableAuthenticationProtocol_Alice(
		netSoc = netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
		)

	oFile.close()
	input("Press Enter To Quit")
