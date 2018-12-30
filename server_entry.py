from time import time
from struct import pack

class ServerEntry:
	challenge2 = 0
	gamedir = ''
	protocol = 0
	players = 0
	maxplayers = 0
	bots = 0
	gamemap = ''
	version = '0'
	servtype = 'd'
	password = 0
	os = 'l'
	secure = 0
	lan = 0
	region = 255
	product = ''
	nat = 0
	
	def setInfoString(self, data):
		infostring = data.replace('\n', '').replace('\r', '').replace('\0', '')
		split = infostring.split('\\')
		for i in range(0, len(split), 2):
			try:
				key = split[i + 1]
				if( split[i] == 'challenge' ):
					self.challenge2 = int(key)
				elif( split[i] == 'gamedir' ):
					self.gamedir = key.lower() # keep gamedir lowercase
				elif( split[i] == 'protocol' ):
					self.protocol = int(key)
				elif( split[i] == 'players' ):
					self.players = int(key)
				elif( split[i] == 'max' ):
					self.maxplayers = int(key)
				elif( split[i] == 'bots' ):
					self.bots = int(key)
				elif( split[i] == 'map' ):
					self.gamemap = key
				elif( split[i] == 'version' ):
					self.version = key
				elif( split[i] == 'type' ):
					self.servtype = key
				elif( split[i] == 'password' ):
					self.password = key
				elif( split[i] == 'os' ):
					self.os = key
				elif( split[i] == 'secure' ):
					self.secure = key
				elif( split[i] == 'lan' ):
					self.lan = key
				elif( split[i] == 'region' ):
					self.region = key
				elif( split[i] == 'product' ):
					self.product = key
				elif( split[i] == 'nat' ):
					self.nat = int(key)
			except IndexError:
				pass
		self.check = self.challenge == self.challenge2

	def __init__(self, addr, challenge):
		# Address
		self.addr = addr
		
		# Shortcuts for generating query
		self.queryAddr = b''
		for i in addr[0].split('.'):
			self.queryAddr += pack('!B', int(i))
		self.queryAddr += pack('!H', int(addr[1]))
		
		# Random number that server must return 
		self.challenge = challenge
		
		# This server is not checked
		# So it will not get into queries
		self.check = False
		
		# Remove server after this time.
		# This maybe not instant
		self.die = time() + 600.0
