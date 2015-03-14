import socket
import time
import binascii
import struct
import select
import string
from crypt import getTransTable
from crypt import KEY
from SocketServer import ThreadingMixIn,TCPServer,StreamRequestHandler
SERVER = "my_server_ip"
REMOTE_PORT = 8866

def send_all(sock,data):
    byte_sent = 0
    while True:
        r = sock.send(data[byte_sent:])
        if r < 0:
            return r
        byte_sent += r
        if byte_sent == len(data):
            return byte_sent

class SocksServerHandler(StreamRequestHandler):

    def handle(self):
        try:
            local = self.connection
        except:
            print "Socket Err"
        self.handleSocks5(local)

    def TCPconnection(self,local,remote):
        try:
            TCPConnectionList = [local,remote]
            while True:
                rs,ws,ex = select.select(TCPConnectionList,[],[])
                if local in rs:
                    #ready to read
                    data = local.recv(4096)
                    if len(data) <= 0:
                        break
                    encryptedData = self.encrypt(data)

                    result = send_all(remote,encryptedData)
                    if result < len(encryptedData):
                        raise Exception('Fail to send all data')
                if remote in rs:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    decryptedData = self.decrypt(data)
                    result = send_all(local,decryptedData)
                    if result < len(decryptedData):
                        raise Exception('Fail to send all data')
        finally:
            local.close()
            remote.close()

    def handleSocks5(self,local):
        """
        identifier
        client->local
        +----+----------+----------+
        |VER | NMETHODS | METHODS  |
        +----+----------+----------+
        | 1  |    1     | 1 to 255 |
        +----+----------+----------+
        local->client
        +----+--------+
        |VER | METHOD |
        +----+--------+
        | 1  |   1    |
        +----+--------+

        Request:
        client->local
        +----+-----+-------+------+----------+----------+
        |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        Replies:
        local->client
        +----+-----+-------+------+----------+----------+
        |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        +----+-----+-------+------+----------+----------+
        | 1  |  1  | X'00' |  1   | Variable |    2     |
        +----+-----+-------+------+----------+----------+

        """
        #socks5
        #Authentication
        local.recv(257)
        local.send("\x05\x00")#ver:5 method:no authentication required
        #Request
        requestData = self.rfile.read(4)#ver cmd rsv atyp
        requestDataVer = ord(requestData[0])
        requestDataCmd = ord(requestData[1])
        requestDataRsv = ord(requestData[2])
        requestDataAtyp = ord(requestData[3])
        requestDataAddrLen = 0
        r_requestDataAddr = ''
        connectOrder = False
        if requestDataAtyp == 1:
            #ipv4 (4 octets)
            r_requestDataAddr = self.rfile.read(4)
            requestDataAddr = socket.inet_ntoa(r_requestDataAddr)
        elif requestDataAtyp == 2:
            #not support
            return
        elif requestDataAtyp == 3:
            #domain (1st:number of octests of name)
            r_requestDataAddrLen = local.recv(1)
            requestDataAddrLen = ord(r_requestDataAddrLen)
            requestDataAddr = self.rfile.read(requestDataAddrLen)
        elif requestDataAtyp == 4:
            #ipv6
            #not support
            return
        r_requestDataPort = self.rfile.read(2)
        requestDataPort = struct.unpack('>H',r_requestDataPort)#Big Endian,unsigned short 2Byte
        requestDataPort = requestDataPort[0]
        reply = "\x05\x00\x00\x01" #version5 succeeded 00 addressType ipv4
        if requestDataCmd == 1:
            #Cmd Connect
            presentConnection = local.getpeername() #(address,port)
            reply += socket.inet_aton(presentConnection[0]) + struct.pack('>H',presentConnection[1])

            #I need requestdataaddr,requestDataPort,sockname
            remoteServer = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            remoteServer.connect((SERVER,REMOTE_PORT))
            #Connect Remote Server
            self.connectRemoteServer(remoteServer,requestData,r_requestDataAddrLen,requestDataAddr,r_requestDataPort)
            connectOrder = True
        else:
            #cmd 02:bind 03:udp associate , not support
            #connection refused
            reply = '\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00'
        local.send(reply)
        if connectOrder:
            if requestDataCmd == 1:
                self.TCPconnection(local,remoteServer)

    def connectRemoteServer(self,remote,requestData,r_requestDataAddrLen,requestDataAddr,r_requestDataPort):
        #send atyp
        self.encryptSend(remote,requestData[3])
        #send addr
        requestDataAtyp = ord(requestData[3])
        if requestDataAtyp == 1:
            #ipv4 (4 octets)
            self.encryptSend(remote,requestDataAddr)
        elif requestDataAtyp == 2:
            #not support
            return
        elif requestDataAtyp == 3:
            #domain (1st:number of octests of name)
            #send len
            self.encryptSend(remote,r_requestDataAddrLen)
            #send addr
            self.encryptSend(remote,requestDataAddr)
        elif requestDataAtyp == 4:
            #ipv6
            #not support
            return
        #send port
        self.encryptSend(remote,r_requestDataPort)
        return

    def encryptSend(self,sock,data):
        sock.send(self.encrypt(data))

    def encrypt(self,data):
        return data.translate(encryptTable)

    def decrypt(self,data):
        return data.translate(decryptTable)


class SocksServer(ThreadingMixIn,TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    encryptTable = getTransTable(KEY)
    decryptTable = string.maketrans(encryptTable,string.maketrans('',''))

    serveraddr = ('',8765)
    sevr = SocksServer(serveraddr,SocksServerHandler)
    sevr.serve_forever()
