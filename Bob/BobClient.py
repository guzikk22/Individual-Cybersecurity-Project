import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import cryptography.hazmat.primitives.hashes as hashes
import cryptography.hazmat.primitives.asymmetric.padding as padding
import cryptography.hazmat.primitives.serialization as SERIAL
import os
import socket
import tools

def SendAuthText(text, encK, authK, netSoc, seq_n):

	global oFile
	global oFile_ref
	
	if seq_n >= 2**63:
		return False
	m = bytes(text, encoding="utf-8")
	m += b' '*( (-len(m)+8)%16 )
	m += tools.int_to_bytes(seq_n, 8)
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
		oFile.close()
		oFile = open(oFile_ref, 'a')

	return True

def RecvAuthText(encK, authK, netSoc, seq_n):

	global oFile
	global oFile_ref

	if seq_n >= 2**63:
		return False
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
	if tools.bytes_to_int(m[-8:]) != 2**64-seq_n-1:
		return ''
	text = tools.bytes_to_str(m[:-8])
	while text[-1]==' ':
		text = text[:-1]
	if verbose:
		oFile.write('<<TEXT<<  ')
		oFile.write(text)
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
	return text

#IP address and port on which receiver will listen for connections
def startListening(HOST, PORT):
	LisSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	LisSocket.bind((HOST, PORT))
	LisSocket.listen()
	netSoc, incAddress = LisSocket.accept()
	return netSoc, incAddress

def Send(netSoc, m):

	global oFile
	global oFile_ref

	netSoc.sendall(m)
	if verbose > 1:
		oFile.write('>>>')
		oFile.write(str(len(m)))
		oFile.write('>>>  ')
		oFile.write(tools.bytes_strRep(m))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')

def Recv(netSoc, n):

	global oFile
	global oFile_ref

	m = netSoc.recv(n)
	if verbose > 1:
		oFile.write('<<<')
		oFile.write(str(len(m)))
		oFile.write('<<<  ')
		oFile.write(tools.bytes_strRep(m))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
	return m

# Returns a encryption key and authentication key if successful
def RepudiableAuthenticationProtocol_Bob(netSoc, My_privKey, Their_pubKey):

	global oFile
	global oFile_ref

	My_pubKey = My_privKey.public_key()
	incData = b''

	if verbose:
		oFile.write('E = ')
		oFile.write(str( My_pubKey.public_numbers().e ))
		oFile.write('\n')
		oFile.write('N = ')
		oFile.write(str( My_pubKey.public_numbers().n ))
		oFile.write('\n')
		oFile.write('e = ')
		oFile.write(str( Their_pubKey.public_numbers().e ))
		oFile.write('\n')
		oFile.write('n = ')
		oFile.write(str( Their_pubKey.public_numbers().n ))
		oFile.write('\n')
	# step 3
	# Receive initial message
	while len(incData)<256:
		incData += Recv(netSoc, 256-len(incData))

	enS = incData[:256]
	incData = incData[256:]

	S = tools.RSA_crypt(
		m = enS,
		e = My_privKey.private_numbers().d,
		n = My_pubKey.public_numbers().n
		)
	S = tools.deOAEP( S, b'encapsulation' )
	if verbose:
		oFile.write('S = ')
		oFile.write(tools.bytes_strRep(S))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
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
		oFile.close()
		oFile = open(oFile_ref, 'a')
	# step 5
	v = tools.trueRand_int( Their_pubKey.public_numbers().n )
	v1 = tools.int_to_bytes(v, 256)
	v0 = v1[:128]
	v1 = v1[128:]
	if verbose:
		oFile.write('v = ')
		oFile.write(str(v))
		oFile.write('\n')
		oFile.write('v0 = ')
		oFile.write(tools.bytes_strRep(v0))
		oFile.write('\n')
		oFile.write('v1 = ')
		oFile.write(tools.bytes_strRep(v1))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
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
		oFile.write('COM(v0) = ')
		oFile.write(tools.bytes_strRep(com0))
		oFile.write('\n')
		oFile.write('s0 = ')
		oFile.write(tools.bytes_strRep(s0))
		oFile.write('\n')
		oFile.write('COM(v1) = ')
		oFile.write(tools.bytes_strRep(com1))
		oFile.write('\n')
		oFile.write('s1 = ')
		oFile.write(tools.bytes_strRep(s1))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
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
		incData += Recv(netSoc, 304-len(incData))

	m_bytes = incData[:304]
	incData = incData[304:]

	m_bytes = tools.ReadMessage(
		pm = m_bytes,
		encK = encK,
		authK = authK
		)
	m_int = tools.bytes_to_int(m_bytes)
	if verbose:
		oFile.write('m = ')
		oFile.write(str(m_int))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')

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
		oFile.write('c = ')
		oFile.write(str(c))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
	# step 13
	# Receive message 4
	while len(incData)<304:
		incData += Recv(netSoc, 304-len(incData))
	r_bytes = incData[:304]
	incData = incData[304:]

	r_bytes = tools.ReadMessage(
		pm = r_bytes,
		encK = encK,
		authK = authK
		)
	r = tools.bytes_to_int(r_bytes)
	if verbose:
		oFile.write('r = ')
		oFile.write(str(r))
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')

	test = tools.modExp(
		b = r,
		e = Their_pubKey.public_numbers().e,
		mod = Their_pubKey.public_numbers().n
		)
	if test != c:
		return (b'',b'')
	if verbose:
		oFile.write("{RESPONSE VERIFIED}")
		oFile.write('\n')
		oFile.write("{PROTOCOL COMPLETED}")
		oFile.write('\n')
		oFile.close()
		oFile = open(oFile_ref, 'a')
	return (encK, authK)

global verbose
verbose = 0
global oFile_ref
global oFile

if __name__ == "__main__" :
	oFile_ref = "BobOutput.txt"
	verbose = 1
	oFile = open(oFile_ref, 'w')
	# Load keys
	with open("AlicePubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)
	with open("BobPrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None,
		)
		f.close()

	netSoc, incAddress = startListening( HOST="127.0.0.1", PORT=65433 )
	
	encK, authK = RepudiableAuthenticationProtocol_Bob(
		netSoc=netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
		 )

	oFile.close()
	input("Press Enter To Quit")
