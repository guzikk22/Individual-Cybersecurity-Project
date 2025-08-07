import Alice.AliceClient as Alice
import Bob.BobClient as Bob
import socket
import cryptography.hazmat.primitives.serialization as SERIAL
import cryptography.hazmat.primitives.asymmetric.rsa as RSA
import threading
import time
# Scenario in which the authentication protocol is run reapeatedly to test reliability and speed

def BOB_THREAD(address, port, My_privKey, Their_pubKey):

	global Bob_encK
	global Bob_authK

	netSoc, incAddress = Bob.startListening( HOST=address, PORT=port)
	
	Bob_encK, Bob_authK = Bob.RepudiableAuthenticationProtocol_Bob(
		netSoc=netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
		)

def ALICE_THREAD(address, port, My_privKey, Their_pubKey):

	global Alice_encK
	global Alice_authK

	#time.sleep(1)
	netSoc = Alice.startConnection( HOST=address, PORT=port )

	Alice_encK, Alice_authK = Alice.RepudiableAuthenticationProtocol_Alice(
		netSoc = netSoc,
		My_privKey = My_privKey,
		Their_pubKey = Their_pubKey
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
threading_verbose = False
#CONFIGURATION END

Alice.oFile = open(Alice.oFile_ref, 'w')
Bob.oFile = open(Bob.oFile_ref, 'w')
success_count = 0
time_total = 0

t0 = time.time()

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

	Alice_privK = RSA.generate_private_key(
		public_exponent = 65537,
		key_size = 2048
		)
	Bob_privK = RSA.generate_private_key(
		public_exponent = 65537,
		key_size = 2048
		)
	Alice_pubK = Alice_privK.public_key()
	Bob_pubK = Bob_privK.public_key()

	time_start = time.time()

	t1 = threading.Thread(target = BOB_THREAD, args=(Bob_addr, Bob_port, Bob_privK, Alice_pubK))
	t1.start()
	if threading_verbose:
		print("THREAD 1-"+str(i)+" STARTED")

	t2 = threading.Thread(target = ALICE_THREAD, args=(Bob_addr, Bob_port, Alice_privK, Bob_pubK))
	t2.start()
	if threading_verbose:
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