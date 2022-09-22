#!/usr/bin/env python3
import socket
import random
import sys
import traceback
import logging
import os
from optparse import OptionParser
from struct import pack
from time import time

from server_entry import ServerEntry
from protocol import MasterProtocol

LOG_FILENAME = "pymaster.log"
MAX_SERVERS_FOR_IP = 14


def log_print(msg):
    logging.debug(msg)


class PyMaster:
    def __init__(self, ip, port):
        self.serverList = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((ip, port))

        log_print("Welcome to PyMaster!")
        log_print("I ask you again, are you my master? @-@")
        log_print("Running on %s:%d" % (ip, port))

    def server_loop(self):
        data, addr = self.sock.recvfrom(1024)
        data = data.decode("latin_1")

        if data[0] == MasterProtocol.clientQuery:
            self.client_query(data, addr)
        elif data[0] == MasterProtocol.challengeRequest:
            self.send_challenge_to_server(data, addr)
        elif data[0] == MasterProtocol.addServer:
            self.add_server_to_list(data, addr)
        elif data[0] == MasterProtocol.removeServer:
            self.remove_server_from_list(data, addr)
        else:
            log_print("Unknown message: {0} from {1}:{2}".format(data, addr[0], addr[1]))

    def client_query(self, data, addr):
        region = data[1]  # UNUSED
        data = data.strip("1" + region)
        try:
            query = data.split("\0")
        except ValueError:
            log_print(traceback.format_exc())
            return

        queryAddr = query[0]  # UNUSED
        rawFilter = query[1]

        # Remove first \ character
        rawFilter = rawFilter.strip("\\")
        split = rawFilter.split("\\")

        # Use NoneType as undefined
        gamedir = "valve"  # halflife, by default
        clver = None
        nat = 0

        for i in range(0, len(split), 2):
            try:
                key = split[i + 1]
                if split[i] == "gamedir":
                    gamedir = key.lower()  # keep gamedir in lowercase
                elif split[i] == "nat":
                    nat = int(key)
                elif split[i] == "clver":
                    clver = key
                else:
                    log_print(
                        "Unhandled info string entry: {0}/{1}. Infostring was: {2}".format(
                            split[i], key, split
                        )
                    )
            except IndexError:
                pass

        if clver is None:  # Probably an old vulnerable version
            self.fake_info_for_old_versions(gamedir, addr)
            return

        packet = MasterProtocol.queryPacketHeader
        for i in self.serverList:
            if time() > i.die:
                self.serverList.remove(i)
                continue

            if not i.check:
                continue

            if nat != i.nat:
                continue

            if gamedir is not None and gamedir != i.gamedir:
                continue

            if nat:
                reply = "\xff\xff\xff\xffc {0}:{1}".format(addr[0], addr[1])
                data = reply.encode("latin_1")
                # Tell server to send info reply
                self.sock.sendto(data, i.addr)

            # Use pregenerated address string
            packet += i.queryAddr

        packet += b"\0\0\0\0\0\0"  # Fill last IP:Port with \0
        self.sock.sendto(packet, addr)


    def _send_fake_info(sock, warnmsg, gamedir, addr):
        baseReply = (
            b"\xff\xff\xff\xffinfo\n\host\\"
            + warnmsg.encode("utf-8")
            + b"\map\\update\dm\\0\\team\\0\coop\\0\\numcl\\32\maxcl\\32\\gamedir\\"
            + gamedir.encode("latin-1")
            + b"\\"
        )
        sock.sendto(baseReply, addr)


    def fake_info_for_old_versions(self, gamedir, addr):
        error_message = [
            "This version is not",
            "supported anymore",
            "Please update Xash3DFWGS",
            "From GooglePlay or GitHub",
            "Эта версия",
            "устарела",
            "Обновите Xash3DFWGS c",
            "GooglePlay или GitHub",
        ]

        for string in error_message:
            _send_fake_info(self.sock, string, gamedir, addr)


    def remove_server_from_list(self, data, addr):
        for server in self.serverList:
            if server.addr == addr:
                log_print("Remove Server: from {0}:{1}".format(addr[0], addr[1]))
                self.serverList.remove(server)


    def send_challenge_to_server(self, data, addr):
        log_print("Challenge Request: from {0}:{1}".format(addr[0], addr[1]))
        # At first, remove old server- data from list
        # self.removeServerFromList(None, addr)

        count = 0
        for i in self.serverList:
            if i.addr[0] == addr[0]:
                if i.addr[1] == addr[1]:
                    self.serverList.remove(i)
                else:
                    count += 1
                if count > MAX_SERVERS_FOR_IP:
                    return

        challenge = random.randint(0, 2**32 - 1)

        # Add server to list
        self.serverList.append(ServerEntry(addr, challenge))

        # And send him a challenge
        packet = MasterProtocol.challengePacketHeader
        packet += pack("I", challenge)
        self.sock.sendto(packet, addr)


    def add_server_to_list(self, data, addr):
        log_print("Add Server: from {0}:{1}".format(addr[0], addr[1]))
        # Remove the header. Just for better parsing.
        serverInfo = data.strip("\x30\x0a\x5c")

        # Find a server with same address
        for serverEntry in self.serverList:
            if serverEntry.addr == addr:
                break

        serverEntry.setInfoString(serverInfo)


def spawn_pymaster(verbose, ip, port):
    if verbose:
        logging.getLogger().addHandler(logging.StreamHandler())
    logging.getLogger().addHandler(logging.FileHandler(LOG_FILENAME))
    logging.getLogger().setLevel(logging.DEBUG)

    masterMain = PyMaster(ip, port)
    while True:
        try:
            masterMain.server_loop()
        except Exception:
            log_print(traceback.format_exc())
            pass


if __name__ == "__main__":

    parser = OptionParser()
    parser.add_option(
        "-i",
        "--ip",
        action="store",
        dest="ip",
        default="0.0.0.0",
        help="ip to listen [default: %default]",
    )
    parser.add_option(
        "-p",
        "--port",
        action="store",
        dest="port",
        type="int",
        default=27010,
        help="port to listen [default: %default]",
    )
    parser.add_option(
        "-d",
        "--daemonize",
        action="store_true",
        dest="daemonize",
        default=False,
        help="run in background, argument is uid [default: %default]",
    )
    parser.add_option(
        "-q",
        "--quiet",
        action="store_false",
        dest="verbose",
        default=True,
        help="don't print to stdout [default: %default]",
    )

    (options, args) = parser.parse_args()

    if options.daemonize != 0:
        from daemon import DaemonContext

        with DaemonContext(
            stdout=sys.stdout, stderr=sys.stderr, working_directory=os.getcwd()
        ) as context:
            spawn_pymaster(options.verbose, options.ip, options.port)
    else:
        sys.exit(spawn_pymaster(options.verbose, options.ip, options.port))
