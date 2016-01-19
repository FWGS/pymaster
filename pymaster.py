import socket
import random
import struct
import sys
from server_entry import ServerEntry
from util import getAttrOrNone

UDP_IP = "127.0.0.1"
UDP_PORT = 27010

sock = []

def logPrint( msg ):
	if DEBUG:
		print( msg )

class PyMaster:
	self.serverList = []
	self.sock = []
	
	def __init__(self):
		sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		sock.bind( (UDP_IP, UDP_PORT) )

		logprint("Welcome to PyMaster!")
		logprint("I ask you again, are you my master?")
		logprint("Running on %s:%i" % UDP_IP, UDP_PORT)
	
	def serverLoop(self)
		data, addr = sock.recvfrom(1024)4
		logprint("received message: %s" % data)
		
		if data[0] == '1':
			self.clientQuery(data, addr);
		elif data[0] == 'q'
			self.sendChallengeToServer(data, addr);
		elif data[0] == '0'
			self.addServerToList(data, addr);
		elif data[0] == 'b'
			self.removeServerFromList(data, addr);
		else
			logprint("Unknown message: %s from %s" % data, addr)

	def clientQuery(self, data, addr):
		data = data.strip('1')
		
		region = data[0]
		queryAddr, rawFilter = data.split('\0')
		
		rawFilter = rawFilter.split('\\')
		queryFilter = namedtuple('QueryFilter', rawFilter[0::2])._make(rawFilter[1::2])

		#nor       = getAttrOrNone(queryFilter, 'nor')
		#nand      = getAttrOrNone(queryFilter, 'nand')
		#dedicated = getAttrOrNone(queryFilter, 'dedicated')
		#gamedir   = getAttrOrNone(queryFilter, 'gamedir')
		#gamemap   = getAttrOrNone(queryFilter, 'map')
		#linux     = getAttrOrNone(queryFilter, 'linux')
		#empty     = getAttrOrNone(queryFilter, 'empty')
		#full      = getAttrOrNone(queryFilter, 'full')
		#proxy     = getAttrOrNone(queryFilter, 'proxy')
		#noplayers = getAttrOrNone(queryFilter, 'noplayers')
		#white     = getAttrOrNone(queryFilter, 'white')
		#name      = getAttrOrNone(queryFilter, 'name')
		#version   = getAttrOrNone(queryFilter, 'version_match')
		#gameaddr  = getAttrOrNone(queryFilter, 'gameaddr')
		secure    = getAttrOrNone(queryFilter, 'secure')

		packet = '\xff\xff\xff\xff\x66\x0a'
		for i in self.serverList:
			if( !i.check ):
				continue
			
			if( gamedir != None ):
				if( gamedir != i.serverInfo.gamedir):
					continue
			
			# Use pregenerated address string
			packet += self.queryAddr
	
	def sendChallengeToServer(self, data, addr):
		# Generate a 32 bit challenge number
		challenge = random.randint(0, 2**32-1)
		
		# Add server to list
		self.serverList.append(ServerEntry(addr, challenge))
		
		# And send him a challenge
		packet = '\xff\xff\xff\xff\x73\x0a'
		packet += struct.pack('I', challenge)
		socket.sendto(packet, addr)

	def addServerToList(self, data, addr):
		# Remove the header
		serverInfo = data.strip('\x30\x0a\x5c')
		
		# Find a server with 
		for serverEntry in self.serverList:
			if (serverEntry.addr == addr):
				serverEntry.setInfoString(serverInfo)
	
	def removeServerFromList(self, data, addr):
		for i in self.serverList:
			if (i.addr == addr):
				self.serverList.remove(i)

def main( argv = None ):
	if argv is None:
		argv = sys.argv
	
	masterMain = PyMaster()
	while True: 
		masterMain.serverLoop()

if __name__ == "__main__":
	sys.exit( main( ) )