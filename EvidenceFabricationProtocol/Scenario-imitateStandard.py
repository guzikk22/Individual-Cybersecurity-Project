import Alice.ImitatorAliceClient as Alice
import Bob.ImitatorBobClient as Bob
import socket
import cryptography.hazmat.primitives.serialization as SERIAL
import threading
import time
import os
import tools
# Scenario in which the authentication protocol is run and nothing else

def BOB_THREAD(address, port, My_pubKey, Their_pubKey, S, m_int, r):

	netSoc, incAddress = Bob.startListening( HOST=address, PORT=port)
	
	encK, authK = Bob.RepudiableAuthenticationProtocol_Bob(
		netSoc=netSoc,
		My_pubKey = My_pubKey,
		Their_pubKey = Their_pubKey,
		S = S,
		m_int = m_int,
		r = r
		)

def ALICE_THREAD(address, port, My_pubKey, Their_pubKey, S, m_int, r):

	time.sleep(1)
	netSoc = Alice.startConnection( HOST=address, PORT=port )

	encK, authK = Alice.RepudiableAuthenticationProtocol_Alice(
		netSoc = netSoc,
		My_pubKey = My_pubKey,
		Their_pubKey = Their_pubKey,
		S = S,
		m_int = m_int,
		r = r
		)

#CONFIGURATION START
Bob_addr = "127.0.0.1" # address and port used by Bob to set up protocol
Bob_port = 65433
Alice.verbose = 1 #set to 0 to not save Alice's logs, 1 to have include protocol's internal state in the protocol and 2 to include messages exchange in the logs as well. 
Alice.oFile_ref = "AliceOutput.txt" #Output file where the Alice's logs are saved
Bob.verbose = 1 # Same as Alice.verbose but for Bob's logs
Bob.oFile_ref = "BobOutput.txt" # Same as Alice.oFile_ref but for Bob's logs
#CONFIGURATION END

Alice.oFile = open(Alice.oFile_ref, 'w')
Bob.oFile = open(Bob.oFile_ref, 'w')

# Load keys
with open("BobPubKey.pem", "rb") as f:
	Bob_pubKey = SERIAL.load_pem_public_key(
		f.read()
	)
	f.close()
with open("AlicePubKey.pem", "rb") as f:
	Alice_pubKey = SERIAL.load_pem_public_key(
		f.read()
	)
	f.close()

S = os.urandom(64)
m_int = tools.trueRand_int( Alice_pubKey.public_numbers().n )
r = tools.trueRand_int( Alice_pubKey.public_numbers().n )

t1 = threading.Thread(target = BOB_THREAD, kwargs={
	"address":Bob_addr, 
	"port":Bob_port,
	"My_pubKey":Bob_pubKey,
	"Their_pubKey":Alice_pubKey,
	"S":S,
	"m_int":m_int,
	"r":r
})
t1.start()
print("THREAD 1 STARTED")

t2 = threading.Thread(target = ALICE_THREAD, kwargs={
	"address":Bob_addr, 
	"port":Bob_port,
	"My_pubKey":Alice_pubKey,
	"Their_pubKey":Bob_pubKey,
	"S":S,
	"m_int":m_int,
	"r":r
})
t2.start()
print("THREAD 2 STARTED")

t1.join()
t2.join()
Alice.oFile.close()
Bob.oFile.close()
input("Scenario Complete")