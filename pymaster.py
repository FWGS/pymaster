# Basic networking
import socket

# Challenge generator
import random

# System important... things
import sys
import traceback
import logging

# Network packet creating
from struct import pack

# Server time control
from time import time

# ServerEntry class module
from server_entry import ServerEntry
# Protocol class
from protocol import MasterProtocol

UDP_IP = "127.0.0.1"
UDP_PORT = 27010
LOG_FILENAME = 'pymaster.log'
logging.basicConfig( filename = LOG_FILENAME, level = logging.DEBUG )

def logPrint( msg ):
	logging.debug( msg )

class PyMaster:
	serverList = []
	sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
	
	def __init__(self):
		self.sock.bind( (UDP_IP, UDP_PORT) )

		logPrint("Welcome to PyMaster!")
		logPrint("I ask you again, are you my master?")
		logPrint("Running on {0}:{1}".format( UDP_IP, UDP_PORT))
	
	def serverLoop(self):
		data, addr = self.sock.recvfrom(1024)
		data = data.decode('latin_1')
		
		if( data[0] == MasterProtocol.clientQuery ):
			logPrint("Client Query: from {0}:{1}".format(addr[0], addr[1]))
			self.clientQuery(data, addr);
		elif( data[0] == MasterProtocol.challengeRequest ):
			logPrint("Challenge Request: from {0}:{1}".format(addr[0], addr[1]))
			self.sendChallengeToServer(data, addr);
		elif( data[0] == MasterProtocol.addServer ):
			logPrint("Add Server: from {0}:{1}".format(addr[0], addr[1]))
			self.addServerToList(data, addr);
		elif( data[0] == MasterProtocol.removeServer ):
			logPrint("Remove Server: from {0}:{1}".format(addr[0], addr[1]))
			self.removeServerFromList(data, addr);
		elif( data[0] == MasterProtocol.statusRequest ):
			logPrint("Status Request: from {0}:{1}".format(addr[0], addr[1]))
			self.sendStatus(data, addr);
		else:
			logPrint("Unknown message: {0} from {1}:{2}".format(data, addr[0], addr[1]))

	def clientQuery(self, data, addr):
		data = data.strip('1\xff')
		
		region = data[0]
		try:
			queryAddr, rawFilter = data.split('\0')
		except ValueError:
			return
		
		rawFilter = rawFilter.strip('\\')
		split = rawFilter.split('\\')
		
		#nor       = getAttrOrNone(queryFilter, 'nor')
		#nand      = getAttrOrNone(queryFilter, 'nand')
		#dedicated = getAttrOrNone(queryFilter, 'dedicated')
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
		#secure    = getAttrOrNone(queryFilter, 'secure')
		
		# Use NoneType as undefined
		gamedir   = None
		gamemap   = None
		
		for i in range( 0, len(split), 2 ):
			try:
				key = split[i + 1]
				if( split[i] == 'gamedir' ):
					gamedir = key
				elif( split[i] == 'map' ):
					gamemap = key
				else:
					logPrint('Unhandled info string entry: {0}/{1}'.format(split[i], key))
			except IndexError:
				pass

		packet = MasterProtocol.queryPacketHeader
		for i in self.serverList:
			if(  time() > i.die ):
				self.serverList.remove(i)
				continue
			
			if( not i.check ):
				continue
			
			if( gamedir != None ):
				if( gamedir != i.gamedir):
					continue
			
			# Use pregenerated address string
			packet += i.queryAddr
			
		self.sock.sendto(packet, addr)
	
	def removeServerFromList(self, data, addr):
		for i in self.serverList:
			if (i.addr == addr):
				self.serverList.remove(i)
	
	def sendChallengeToServer(self, data, addr):
		# At first, remove old server data from list
		self.removeServerFromList(None, addr)
		
		# Generate a 32 bit challenge number
		challenge = random.randint(0, 2**32-1)
		
		# Add server to list
		self.serverList.append(ServerEntry(addr, challenge))
		
		# And send him a challenge
		packet = MasterProtocol.challengePacketHeader
		packet += pack('I', challenge)
		self.sock.sendto(packet, addr)

	def addServerToList(self, data, addr):
		# Remove the header. Just for better parsing.
		serverInfo = data.strip('\x30\x0a\x5c')
		
		# Find a server with same address
		for serverEntry in self.serverList:
			if( serverEntry.addr == addr ):
				serverEntry.setInfoString( serverInfo )
	
	def sendStatus( self, data, addr ):
		count = len(self.serverList)
		
		packet = b'Server\t\t\tGame\tMap\tPlayers\tVersion\tChallenge\tCheck\n'
		for i in self.serverList:
			line = '{0}:{1}\t{2}\t{3}\t{4}/{5}\t{6}\n'.format(i.addr[0], i.addr[1], 
													 i.gamedir, i.gamemap, i.players, 
													 i.maxplayers, i.version, i.challenge, i.check)
			packet += line.encode('latin_1')
		self.sock.sendto(packet, addr)


def main( argv = None ):
	if argv is None:
		argv = sys.argv
	
	masterMain = PyMaster()
	while True: 
		try:
			masterMain.serverLoop()
		except Exception:
			logging.exception()
			pass

if __name__ == "__main__":
	sys.exit( main( ) )