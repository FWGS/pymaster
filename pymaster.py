#!/usr/bin/env python3
import socket
import random
import sys
import traceback
import logging
import os
from optparse import OptionParser
from struct import pack, unpack
from time import time
from ipaddress import ip_address, ip_network

from server_entry import ServerEntry
from protocol import MasterProtocol
import ipfilter

LOG_FILENAME = 'pymaster.log'
MAX_SERVERS_FOR_IP = 14
CHALLENGE_SEND_PERIOD = 10

def log(msg):
	logging.debug(msg)

class RateLimitItem:
	def __init__(self, resetAt):
		self.reset(resetAt)

	def reset(self, resetAt):
		self.resetAt = resetAt
		self.logs = self.calls = 0

	def inc(self):
		self.calls = self.calls + 1
		self.logs = self.logs + 1

	def shouldReset(self, curtime):
		return curtime > self.resetAt

class IPRateLimit:
	def __init__(self, type, period, maxcalls):
		self.type = type
		self.period = period
		self.maxcalls = maxcalls
		self.maxlogs  = maxcalls + 2
		self.ips = {}

	def ratelimit(self, ip):
		curtime = time()

		if ip not in self.ips:
			self.ips[ip] = RateLimitItem(curtime + self.period)
		elif self.ips[ip].shouldReset(curtime):
			self.ips[ip].reset(curtime + self.period)

		self.ips[ip].inc()

		if self.ips[ip].calls > self.maxcalls:
			if self.ips[ip].logs < self.maxlogs:
				log('Ratelimited %s %s' % (self.type, ip))
			return True

		return False

class PyMaster:
	def __init__(self, ip, port):
		self.serverList = []
		self.serverRL = IPRateLimit('server', 60, 30)
		self.clientRL = IPRateLimit('client', 60, 120)
		self.ipfilterRL = IPRateLimit('filterlog', 60, 10)
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.bind((ip, port))

		log("Welcome to PyMaster!")
		log("I ask you again, are you my master?")
		log("Running on %s:%d" % (ip, port))

	def serverLoop(self):
		data, addr = self.sock.recvfrom(1024)

		if ip_address(addr[0]) in ipfilter.ipfilter:
			if not self.ipfilterRL.ratelimit(addr[0]):
				log('Filter: %s:%d' % (addr[0], addr[1]))
			return

		if len(data) == 0:
			return

		# only client stuff
		if data.startswith(MasterProtocol.clientQuery):
			if not self.clientRL.ratelimit(addr[0]):
				self.clientQuery(data, addr)
			return

		# only server stuff
		if not self.serverRL.ratelimit(addr[0]):
			if data.startswith(MasterProtocol.challengeRequest):
				self.sendChallengeToServer(data, addr)
			elif data.startswith(MasterProtocol.addServer):
				self.addServerToList(data, addr)
			elif data.startswith(MasterProtocol.removeServer):
				self.removeServerFromList(data, addr)
			else:
				log('Unknown message: %s from %s:%d' % (str(data), addr[0], addr[1]))

	def clientQuery(self, data, addr):
		data = data.decode('latin_1')
		data = data.strip('1' + data[1])
		info = data.split('\0')[1].strip('\\')
		split = info.split('\\')

		key      = None
		protocol = None
		gamedir  = 'valve'
		clver    = None
		nat      = 0

		for i in range(0, len(split), 2):
			try:
				k = split[i]
				v = split[i + 1]
				if k == 'gamedir':
					gamedir = v.lower() # keep gamedir in lowercase
				elif k == 'nat':
					nat = int(v)
				elif k == 'clver':
					clver = v
				elif k == 'protocol':
					protocol = int(v)
				elif k == 'key': # defined but not implemented yet
					key = v
				# somebody is playing :)
				elif k == 'thisismypcid' or k == 'heydevelopersifyoureadthis':
					self.fakeInfoForOldVersions(gamedir, addr)
					return
				else:
					log('Client Query: %s:%d, invalid infostring=%s' % (addr[0], addr[1], rawFilter))
			except IndexError:
				pass

		if( clver == None ): # Probably an old vulnerable version
			self.fakeInfoForOldVersions(gamedir, addr)
			return

		packet = MasterProtocol.queryPacketHeader
		for i in self.serverList:
			if time() > i.die:
				self.serverList.remove(i)
				continue

			if not i.check:
				continue

			if nat != i.nat or gamedir != i.gamedir:
				continue

			if protocol != None and protocol != i.protocol:
				continue

			if nat:
				# Tell server to send info reply
				data = ('\xff\xff\xff\xffc %s:%d' % (addr[0], addr[1])).encode('latin_1')
				self.sock.sendto(data, i.addr)

			# Use pregenerated address string
			packet += i.queryAddr
		packet += b'\0\0\0\0\0\0' # Fill last IP:Port with \0
		self.sock.sendto(packet, addr)

	def fakeInfoForOldVersions(self, gamedir, addr):
		def sendFakeInfo(sock, warnmsg, gamedir, addr):
			baseReply = b"\xff\xff\xff\xffinfo\n\host\\" + warnmsg.encode('utf-8') + b"\map\\update\dm\\0\\team\\0\coop\\0\\numcl\\32\maxcl\\32\\gamedir\\" + gamedir.encode('latin-1') + b"\\"
			sock.sendto(baseReply, addr)

		sendFakeInfo(self.sock, "This version is not", gamedir, addr)
		sendFakeInfo(self.sock, "supported anymore", gamedir, addr)
		sendFakeInfo(self.sock, "Please update Xash3DFWGS", gamedir, addr)
		sendFakeInfo(self.sock, "From GooglePlay or GitHub", gamedir, addr)
		sendFakeInfo(self.sock, "Эта версия", gamedir, addr)
		sendFakeInfo(self.sock, "устарела", gamedir, addr)
		sendFakeInfo(self.sock, "Обновите Xash3DFWGS c", gamedir, addr)
		sendFakeInfo(self.sock, "GooglePlay или GitHub", gamedir, addr)

	def removeServerFromList(self, data, addr):
		pass

	def sendChallengeToServer(self, data, addr):
		count = 0
		s = None
		for i in self.serverList:
			if addr[0] != i.addr[0]:
				continue
			if addr[1] == i.addr[1]:
				s = i
				break
			else:
				count += 1
				if count > MAX_SERVERS_FOR_IP:
					return

		challenge2 = None
		if len(data) == 6:
			# little endian challenge
			challenge2 = unpack('<I', data[2:])[0]

		if not s:
			challenge = random.randint(0, 2**32-1) & 0xffffffff #hash(addr[0]) + hash(addr[1]) + hash(time())
			s = ServerEntry(addr, challenge)
			self.serverList.append(s)
		elif s.sentChallengeAt + 5 > time():
			return

		packet = MasterProtocol.challengePacketHeader
		packet += pack('I', s.challenge)

		# send server-to-master challenge back
		if challenge2 is not None:
			packet += pack('I', challenge2)

		self.sock.sendto(packet, addr)

	def addServerToList(self, data, addr):
		# Remove the header. Just for better parsing.
		info = data.strip(b'\x30\x0a\x5c').decode('latin_1')

		# Find a server with same address
		s = None
		for s in self.serverList:
			if s.addr == addr:
				break
		if not s:
			log('Server skipped challenge request: %s:%d' % (addr[0], addr[1]))
			return

		if s.setInfoString( info ):
			log('Add server: %s:%d, game=%s/%s, protocol=%d, players=%d/%d/%d, version=%s' % (addr[0], addr[1], s.gamemap, s.gamedir, s.protocol, s.players, s.bots, s.maxplayers, s.version))
		else:
			log('Failed challenge from %s:%d: %d must be %d' % (addr[0], addr[1], s.challenge, s.challenge2))

def spawn_pymaster(verbose, ip, port):
	if verbose:
		logging.getLogger().addHandler(logging.StreamHandler())
#	logging.getLogger().addHandler(logging.FileHandler(LOG_FILENAME))
	logging.getLogger().setLevel(logging.DEBUG)

	masterMain = PyMaster(ip, port)
	while True:
		try:
			masterMain.serverLoop()
		except Exception:
			log(traceback.format_exc())
			pass

if __name__ == "__main__":
	parser = OptionParser()
	parser.add_option('-i', '--ip', action='store', dest='ip', default='0.0.0.0',
		help='ip to listen [default: %default]')
	parser.add_option('-p', '--port', action='store', dest='port', type='int', default=27010,
		help='port to listen [default: %default]')
	parser.add_option('-d', '--daemonize', action='store_true', dest='daemonize', default=False,
		help='run in background, argument is uid [default: %default]')
	parser.add_option('-q', '--quiet', action='store_false', dest='verbose', default=True,
		help='don\'t print to stdout [default: %default]')

	(options, args) = parser.parse_args()

	if options.daemonize != 0:
		from daemon import pidfile, DaemonContext

		with DaemonContext(stdout=sys.stdout, stderr=sys.stderr, working_directory=os.getcwd()) as context:
			spawn_pymaster(options.verbose, options.ip, options.port)
	else:
		sys.exit(spawn_pymaster(options.verbose, options.ip, options.port))
