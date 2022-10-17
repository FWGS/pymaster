from time import time
from struct import pack


class ServerEntry:
    challenge2 = 0
    gamedir = ""
    protocol = 0
    players = 0
    maxplayers = 0
    bots = 0
    gamemap = ""
    version = "0"
    servtype = "d"
    password = 0
    os = "l"
    secure = 0
    lan = 0
    region = 255
    product = ""
    nat = 0

    def setInfoString(self, data):
        infostring = data.replace("\n", "").replace("\r", "").replace("\0", "")
        split = infostring.split("\\")
        for i in range(0, len(split), 2):
            try:
                key = split[i + 1]

                if split[i] in ["players", "protocol", "bots", "nat"]:
                    self.i = int(key)

                elif split[i] in ["version", "password", "os", "secure", "lan", "region", "product"]:
                    self.i = key

                match split[i]:
                    case "gamedir":
                        self.gamedir = key.lower()
                    case "max":
                        self.maxplayers = int(key.split(".")[0])
                    case "challenge":
                        self.challenge2 = int(key)
                    case "map":
                        self.gamemap = key
                    case "type":
                        self.servtype = key

            except IndexError:
                pass
        self.check = self.challenge == self.challenge2

    def __init__(self, addr, challenge):
        # Address
        self.addr = addr

        # Shortcuts for generating query
        self.queryAddr = b""
        for i in addr[0].split("."):
            self.queryAddr += pack("!B", int(i))
        self.queryAddr += pack("!H", int(addr[1]))

        # Random number that server must return
        self.challenge = challenge

        # This server is not checked
        # So it will not get into queries
        self.check = False

        # Remove server after this time.
        # This maybe not instant
        self.die = time() + 600.0
