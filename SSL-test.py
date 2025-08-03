import threading
import socket
import ssl

def CLIENT_THREAD(addr, port):
	context = ssl.create_default_context(purpose=ssl.Pupose.SERVER_AUTH)

def SERVER_THREAD(addr, port):
	context = ssl.create_default_context(purpose=ssl.Pupose.CLIENT_AUTH)
	context.


	LisSock = socket.socket()
	LisSock.bind((addr, port))
	LisSock.listen()
	SSL_sock = context.wrap_socket(LisSock, server_side=True)