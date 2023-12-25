class MasterProtocol:
	# Client To Master
	clientQuery = b'1'

	# Server To Master
	challengeRequest = b'q\xFF'
	addServer = b'0\n'
	removeServer = b'\x62\x0A'

	# Master To Client
	# queryPacketHeader = b'\xff\xff\xff\xff\x66\x0a'
	queryPacketHeader = b'\x7f\x0a'

	# Master To Server
	challengePacketHeader = b'\xff\xff\xff\xff\x73\x0a'
