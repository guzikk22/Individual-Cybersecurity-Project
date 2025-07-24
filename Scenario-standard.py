import Alice.AliceClient as Alice
import Bob.BobClient as Bob
import socket
import cryptography.hazmat.primitives.serialization as SERIAL
import threading
import time
from contextlib import redirect_stdout
# Scenario in which the authentication protocol is run and nothing else

def BOB_THREAD(address, port):
	# Load keys
	with open("Bob/AlicePubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read(),
		)
	with open("Bob/BobPrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None,
		)
		f.close()

	netSoc, incAddress = Bob.startListening( HOST=address, PORT=port)
	
	encK, authK = Bob.RepudiableAuthenticationProtocol_Bob(
		netSoc=netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
		 )

def ALICE_THREAD(address, port):
	# Load keys
	with open("Alice/BobPubKey.pem", "rb") as f:
		Their_pubKey = SERIAL.load_pem_public_key(
			f.read()
		)
		f.close()
	with open("Alice/AlicePrivKey.pem", "rb") as f:
		My_privKey = SERIAL.load_pem_private_key(
			f.read(),
			password=None
		)
		f.close()


	time.sleep(1)
	netSoc = Alice.startConnection( HOST=address, PORT=port )

	encK, authK = Alice.RepudiableAuthenticationProtocol_Alice(
		netSoc = netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
		)

Bob_addr = "127.0.0.1"
Bob_port = 65433

Alice.verbose = 1
Alice.oFile.close()
Alice.oFile = open("AliceOutput.txt", 'w')
Bob.verbose = 1
Bob.oFile.close()
Bob.oFile = open("BobOutput.txt", 'w')

t1 = threading.Thread(target = BOB_THREAD, args=(Bob_addr, Bob_port))
t1.start()
print("THREAD 1 STARTED")

t2 = threading.Thread(target = ALICE_THREAD, args=(Bob_addr, Bob_port))
t2.start()
print("THREAD 2 STARTED")

t1.join()
t2.join()
Alice.oFile.close()
Bob.oFile.close()
input("Scenario Complete")