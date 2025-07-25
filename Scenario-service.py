from Alice import AliceClient as Alice
from Bob import BobClient as Bob
from os.path import isfile
from os import listdir
import socket
import cryptography.hazmat.primitives.serialization as SERIAL
import threading
import time
import tools

from contextlib import redirect_stdout
# Scenario in which the authentication protocol is run and later Alice is able to use a simple file storing service hosted by Bob

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

	Bob.oFile.write("{AUTHENTICATION SUCCESSFUL}\n")
	Bob.oFile.close()
	Bob.oFile = open(Bob_oFileRef, 'a')

	mSent = 0 #messages sent
	mReceived = 0 #messages received
	# host the file service
	while True:
		com = Bob.RecvAuthText(encK, authK, netSoc, mReceived)
		mReceived += 1
		Bob.oFile.close()
		Bob.oFile = open(Bob_oFileRef, 'a')
		if len(com)==0:
			break

		match com[0]:
			case 'r':
				if '\\' in com[1:] or '/' in com[1:]:
					Bob.SendAuthText(
						text = 'No such file exists',
						encK = encK,
						authK = authK,
						netSoc = netSoc,
						seq_n = mSent
						)
					mSent+=1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					continue
				if isfile("Bob/fileshare/"+com[1:]+".txt"):
					f = open("Bob/fileshare/"+com[1:]+".txt")
					Bob.SendAuthText(
						text = 'contents of '+com[1:]+":\n" + f.read(),
						encK = encK,
						authK = authK,
						netSoc = netSoc,
						seq_n = mSent
						)
					mSent+=1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					continue
				Bob.SendAuthText(
					text = 'No such file exists',
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Bob.oFile.close()
				Bob.oFile = open(Bob_oFileRef, 'a')
				continue
			case 'w':
				if '\\' in com[1:] or '/' in com[1:]:
					Bob.SendAuthText(
						text = 'd',
						encK = encK,
						authK = authK,
						netSoc = netSoc,
						seq_n = mSent
						)
					mSent+=1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					continue
				if isfile("Bob/fileshare/"+com[1:]+".txt"):
					Bob.SendAuthText(
						text = 'a',
						encK = encK,
						authK = authK,
						netSoc = netSoc,
						seq_n = mSent
						)
					mSent+=1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					edit = Bob.RecvAuthText(encK, authK, netSoc, mReceived)
					mReceived += 1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					if len(edit)==0:
						break
					f = open("Bob/fileshare/"+com[1:]+".txt", 'w')
					f.write(edit[:-1])
					f.close()
					Bob.SendAuthText(
						text = 'File successfully overwritten',
						encK = encK,
						authK = authK,
						netSoc = netSoc,
						seq_n = mSent
						)
					mSent += 1
					Bob.oFile.close()
					Bob.oFile = open(Bob_oFileRef, 'a')
					continue
				Bob.SendAuthText(
					text = 'd',
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Bob.oFile.close()
				Bob.oFile = open(Bob_oFileRef, 'a')
				continue
			case 'l':
				li = listdir("Bob/fileshare")
				for i in range(len(li)):
					li[i] = li[i][:-4]
				Bob.SendAuthText(
					text = str(li)[1:-1],
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Bob.oFile.close()
				Bob.oFile = open(Bob_oFileRef, 'a')
			case 'e':
				break
			case _:
				Bob.SendAuthText(
					text = "WHAT?!",
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Bob.oFile.close()
				Bob.oFile = open(Bob_oFileRef, 'a')

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

	Alice.oFile.write("{AUTHENTICATION SUCCESSFUL}\n")
	Alice.oFile.close()
	Alice.oFile = open(Alice_oFileRef, 'a')

	mSent = 0 #messages sent
	mReceived = 0 #messages received
	# interface with the file service
	while True:
		com = input("Bob//>")
		if len(com)<3 or com[0] == 'h' :
			HelpPrompt()
			continue
		match com[0]:
			case 'r':
				if com[1] != ' ':
					InvalidCommandPrompt()
					continue
				Alice.SendAuthText(
					text = 'r'+com[2:],
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Alice.oFile.close()
				Alice.oFile = open(Alice_oFileRef, 'a')
			case 'w':
				if com[1] != ' ':
					InvalidCommandPrompt()
					continue
				Alice.SendAuthText(
					text = 'w'+com[2:],
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Alice.oFile.close()
				Alice.oFile = open(Alice_oFileRef, 'a')
				message =  Alice.RecvAuthText(encK, authK, netSoc, mReceived)
				Alice.oFile.close()
				Alice.oFile = open(Alice_oFileRef, 'a')
				mReceived += 1
				if message == '':
					break
				if message != 'a':
					print("No such file exists.")
					continue
				newText = input("Enter new contents for the file (use \\n for line break and \\\\ for \\):\n")
				Alice.SendAuthText(
					text = tools.strDeserialize(newText+'.'),
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent+=1
				Alice.oFile.close()
				Alice.oFile = open(Alice_oFileRef, 'a')
			case 'l':
				if com != 'list':
					InvalidCommandPrompt()
					continue
				Alice.SendAuthText(
					text = 'l',
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				mSent += 1
				Alice.oFile.close()
				Alice.oFile = open(Alice_oFileRef, 'a')
			case 'e':
				if com != 'exit':
					InvalidCommandPrompt()
					continue
				Alice.SendAuthText(
					text = 'e',
					encK = encK,
					authK = authK,
					netSoc = netSoc,
					seq_n = mSent
					)
				break
			case _ :
				InvalidCommandPrompt()
				continue
		message = Alice.RecvAuthText(encK, authK, netSoc, mReceived)
		mReceived += 1
		Alice.oFile.close()
		Alice.oFile = open(Alice_oFileRef, 'a')
		if message == '':
			break
		print(message)
		

def HelpPrompt():
	print("h - help")
	print("r [filename] - retrieve file")
	print("w [filename] - overwrite file")
	print("list - see hosted files")
	print("exit - end the connection")

def InvalidCommandPrompt():
	print("Invalid command, type 'help' to see the list of available commands")

Bob_addr = "127.0.0.1"
Bob_port = 65433
Alice.verbose = 1
Alice.oFile_ref = "AliceOutput.txt"
Bob.verbose = 1
Bob.oFile_ref = "BobOutput.txt"

Alice.oFile = open(Alice.oFile_ref, 'w')
Bob.oFile = open(Bob.oFile_ref, 'w')

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