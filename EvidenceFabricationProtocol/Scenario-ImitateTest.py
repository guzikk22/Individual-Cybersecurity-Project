import Alice.ImitatorAliceClient as Alice
import Bob.ImitatorBobClient as Bob
import os
import socket
import cryptography.hazmat.primitives.serialization as SERIAL
import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import threading
import time
import tools
# Scenario in which the authentication protocol is run and nothing else

def BOB_THREAD(address, port, My_pubKey, Their_pubKey, S, m_int, r):

	global Bob_encK
	global Bob_authK

	netSoc, incAddress = Bob.startListening( HOST=address, PORT=port)
	
	Bob_encK, Bob_authK = Bob.RepudiableAuthenticationProtocol_Bob(
		netSoc=netSoc,
		My_pubKey = My_pubKey,
		Their_pubKey = Their_pubKey,
		S = S,
		m_int = m_int,
		r = r
		)

def ALICE_THREAD(address, port, My_pubKey, Their_pubKey, S, m_int, r):

	global Alice_encK
	global Alice_authK

	#time.sleep(1)
	netSoc = Alice.startConnection( HOST=address, PORT=port )

	Alice_encK, Alice_authK = Alice.RepudiableAuthenticationProtocol_Alice(
		netSoc = netSoc,
		My_pubKey = My_pubKey,
		Their_pubKey = Their_pubKey,
		S = S,
		m_int = m_int,
		r = r
		)

global Alice_encK
global Alice_authK
global Bob_encK 
global Bob_authK

#CONFIGURATION START
Bob_addr = "127.0.0.1" # address an port used by Bob to set up protocol
Bob_port = 65433
Alice.verbose = 0 #set to 0 to not save Alice's logs, 1 to have include protocol's internal state in the protocol and 2 to include messages exchange in the logs as well. 
Alice.oFile_ref = "AliceOutput.txt" #Output file where the Alice's logs are saved
Bob.verbose = 0 # Same as Alice.verbose but for Bob's logs
Bob.oFile_ref = "BobOutput.txt" # Same as Alice.oFile_ref but for Bob's logs
iteration_count = 100 #number of times protocol will be performed
#CONFIGURATION END

Alice.oFile = open(Alice.oFile_ref, 'w')
Bob.oFile = open(Bob.oFile_ref, 'w')
success_count = 0
time_total = 0

for i in range(iteration_count):
	Alice_encK = b''
	Alice_authK = b''
	Bob_encK = b''
	Bob_authK = b''

	Alice.oFile.write("{ITERATION " + str(i) + " START}\n")
	Alice.oFile.close()
	Alice.oFile = open(Alice.oFile_ref, 'a')
	Bob.oFile.write("{ITERATION " + str(i) + " START}\n")
	Bob.oFile.close()
	Bob.oFile = open(Bob.oFile_ref, 'a')

	Alice_privKey = RSA.generate_private_key(
		public_exponent = 65537,
		key_size = 2048
		)
	Bob_privKey = RSA.generate_private_key(
		public_exponent = 65537,
		key_size = 2048
		)
	Alice_pubKey = Alice_privKey.public_key()
	Bob_pubKey = Bob_privKey.public_key()

	time_start = time.time()

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
	print("THREAD 1-"+str(i)+" STARTED")

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
	print("THREAD 2-"+str(i)+" STARTED")

	t1.join()
	t2.join()
	time_total += time.time() - time_start

	if len(Alice_encK)==32 and len(Alice_authK)==32 and len(Bob_encK)==32 and len(Bob_authK)==32 and Alice_encK==Bob_encK and Alice_authK==Bob_authK:
		success_count += 1


Alice.oFile.close()
Bob.oFile.close()
print("Iterations: " + str(iteration_count))
print("Successful iterations: "+ str(success_count))
print("Success rate: " + str(100*success_count/iteration_count) + "%")
print("Total execution time: " + str(time_total) + "s")
print("Average execution time: " + str(time_total/iteration_count) + "s")
input("Scenario Complete")