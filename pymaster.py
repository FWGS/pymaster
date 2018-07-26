#!/usr/bin/env python3
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

UDP_IP = "0.0.0.0"
UDP_PORT = 27010
LOG_FILENAME = 'pymaster.log'
logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().addHandler(logging.FileHandler(LOG_FILENAME))
logging.getLogger().setLevel(logging.DEBUG)

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
			self.clientQuery(data, addr)
		elif( data[0] == MasterProtocol.challengeRequest ):
			self.sendChallengeToServer(data, addr)
		elif( data[0] == MasterProtocol.addServer ):
			self.addServerToList(data, addr)
		elif( data[0] == MasterProtocol.removeServer ):
			self.removeServerFromList(data, addr)
		elif( data[0] == MasterProtocol.statusRequest ):
			self.sendStatus(data, addr)
		else:
			logPrint("Unknown message: {0} from {1}:{2}".format(data, addr[0], addr[1]))

	def clientQuery(self, data, addr):
		region = data[1] # UNUSED
		data = data.strip('1' + region)
		try:
			query = data.split('\0')
		except ValueError:
			logPrint(traceback.format_exc())
			return

		queryAddr = query[0] # UNUSED
		rawFilter = query[1]

		# Remove first \ character
		rawFilter = rawFilter.strip('\\')
		split = rawFilter.split('\\')

		# Use NoneType as undefined
		gamedir = None
		gamemap = None # UNUSED: until Xash3D will not support full filter
		clver   = None
		nat = 0

		for i in range( 0, len(split), 2 ):
			try:
				key = split[i + 1]
				if( split[i] == 'gamedir' ):
					gamedir = key
				elif( split[i] == 'map' ):
					gamemap = key
				elif( split[i] == 'nat' ):
					nat = int(key)
				elif( split[i] == 'clver' ):
					clver = key
				else:
					logPrint('Unhandled info string entry: {0}/{1}. Infostring was: {2}'.format(split[i], key, split))
			except IndexError:
				pass

		if( clver == None ): # Probably an old vulnerable version
			fakeInfoForOldVersions( gamedir, addr )
			return

		packet = MasterProtocol.queryPacketHeader
		for i in self.serverList:
			if(  time() > i.die ):
				self.serverList.remove(i)
				continue

			if( not i.check ):
				continue

			if( nat != i.nat ):
				continue

			if( gamedir != None ):
				if( gamedir != i.gamedir ):
					continue

			if( nat ):
				reply = '\xff\xff\xff\xffc {0}:{1}'.format( addr[0], addr[1] )
				data = reply.encode( 'latin_1' )
				# Tell server to send info reply
				self.sock.sendto( data, i.addr )

			# Use pregenerated address string
			packet += i.queryAddr
		packet += b'\0\0\0\0\0\0' # Fill last IP:Port with \0
		self.sock.sendto(packet, addr)

	def fakeInfoForOldVersions(self, gamedir, addr):
		def sendFakeInfo(sock, warnmsg, gamedir, addr):
			baseReply = "\xff\xff\xff\xffinfo\n\host\\{0}\map\\update\dm\\0\\team\\0\coop\\0\\numcl\\32\maxcl\\32\\gamedir\{1}\\"
			reply = baseReply.format(warnmsg, gamedir)
			data = reply.encode( 'latin_1' )
			sock.sendto(data, addr)

		sendFakeInfo(sock, "This version is not", gamedir, addr)
		sendFakeInfo(sock, "supported anymore", gamedir, addr)
		sendFakeInfo(sock, "Please update Xash3DFWGS", gamedir, addr)
		sendFakeInfo(sock, "From GooglePlay or GitHub", gamedir, addr)
		sendFakeInfo(sock, "Эта версия", gamedir, addr)
		sendFakeInfo(sock, "устарела", gamedir, addr)
		sendFakeInfo(sock, "Обновите Xash3DFWGS c", gamedir, addr)
		sendFakeInfo(sock, "GooglePlay или GitHub", gamedir, addr)

	def removeServerFromList(self, data, addr):
		for i in self.serverList:
			if (i.addr == addr):
				logPrint("Remove Server: from {0}:{1}".format(addr[0], addr[1]))
				self.serverList.remove(i)

	def sendChallengeToServer(self, data, addr):
		logPrint("Challenge Request: from {0}:{1}".format(addr[0], addr[1]))
		# At first, remove old server- data from list
		#self.removeServerFromList(None, addr)

		count = 0
		for i in self.serverList:
			if ( i.addr[0] == addr[0] ):
				if( i.addr[1] == addr[1] ):
					self.serverList.remove(i)
				else:
					count += 1
				if( count > 7 ):
					return

		# Generate a 32 bit challenge number
		challenge = random.randint(0, 2**32-1)

		# Add server to list
		self.serverList.append(ServerEntry(addr, challenge))

		# And send him a challenge
		packet = MasterProtocol.challengePacketHeader
		packet += pack('I', challenge)
		self.sock.sendto(packet, addr)

	def addServerToList(self, data, addr):
		logPrint("Add Server: from {0}:{1}".format(addr[0], addr[1]))
		# Remove the header. Just for better parsing.
		serverInfo = data.strip('\x30\x0a\x5c')

		# Find a server with same address
		for serverEntry in self.serverList:
			if( serverEntry.addr == addr ):
				break

		serverEntry.setInfoString( serverInfo )

	def sendStatus( self, data, addr ):
		logPrint("Status Request: from {0}:{1}".format(addr[0], addr[1]))
		count = len(self.serverList)

		packet = b'Server\t\t\tGame\tMap\t\tPlayers\tVersion\tChallenge\tCheck\n'
		for i in self.serverList:
			line = '{0}:{1}\t{2}\t{3}\t{4}/{5}\t{6}\t{7}\t{8}\n'.format(i.addr[0], i.addr[1], 
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
			logPrint(traceback.format_exc())
			pass

if __name__ == "__main__":
	sys.exit( main( ) )
