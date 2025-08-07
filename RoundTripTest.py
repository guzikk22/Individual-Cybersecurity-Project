import socket
import threading
import time

def THREAD1(netSocket, n):
	m = b''
	for i in range(n):
		netSocket.sendall(b'1')
		
		while len(m)<=i:
			m += netSocket.recv(1)

def THREAD2(netSocket, n):
	m = b''
	for i in range(n):
		while len(m)<=i:
			m += netSocket.recv(1)
		
		netSocket.sendall(b'2')


#CONFIGURATION START
addr = "127.0.0.1" # address and port used by Bob to set up protocol
port = 65433
iteration_count = 10000
#CONFIGURATION END


LisSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
LisSocket.bind((addr, port))
LisSocket.listen()

netSocket1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
netSocket1.connect((addr, port))

netSocket2, incAddress = LisSocket.accept()

time_total = 0

t1 = threading.Thread(target = THREAD1, args=(netSocket1, iteration_count) ) 
t2 = threading.Thread(target = THREAD2, args=(netSocket2, iteration_count) )

time_start = time.time()

t1.start()
t2.start()
t1.join()
t2.join()

time_total += time.time() - time_start

print("Number of roundtrips: " + str(iteration_count))
print("Total time: " + str(time_total) + "s")
print("Average roundtrip time: " + str(time_total*1000/iteration_count) + "ms")