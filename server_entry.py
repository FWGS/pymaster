from collections import namedtuple
from time import time

class ServerEntry:
	def setInfoString(self, data):
		infostring = data.translate(None, '\n\r\0')
		split = infostring.split('\\')
		self.serverInfo = namedtuple('ServerInfo', split[0::2])._make(split[1::2])
		self.check = int(self.serverInfo.challenge) == self.challenge

	def __init__(self, addr, challenge):
		# Address
		self.addr = addr
		
		# Shortcuts for generating query
		self.queryAddr = ""
		for i in addr[0].split('.'):
			self.queryAddr += struct.pack('B', int(i))
		self.queryAddr += struct.pack('H', addr[1])
		
		# Random number that server must return 
		self.challenge = challenge
		
		# This server is not checked
		# So it will not get into queries
		self.check = False
		
		# Remove server after this time.
		# This maybe not instant
		self.die = time() + 600.0