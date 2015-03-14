import socket
from SocketServer import ThreadingMixIn,TCPServer,StreamRequestHandler
import time
import binascii
import struct
import select
import string
PORT = 8866
from crypt import getTransTable
from crypt import KEY

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
            #Get request connection address
            addr = self.preSecureConnection(local)
            remote = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
            remote.connect((addr[0],addr[1]))
            self.TCPconnection(local,remote)
        except:
            print "Socket Err"


    def preSecureConnection(self,sock):
        #Get Atyp
        r_requestDataAtyp = self.decrypt(sock.recv(1))
        requestDataAtyp = ord(r_requestDataAtyp)
        #Get Addr
        if requestDataAtyp == 1:
            #ipv4 (4 octets)
            r_requestDataAddr = (sock.recv(4))
            requestDataAddr = socket.inet_ntoa(self.decrypt(r_requestDataAddr))
        elif requestDataAtyp == 2:
            #not support
            return ()
        elif requestDataAtyp == 3:
            #domain (1st:number of octests of name)
            #recv len
            r_requestDataAddrLen = self.decrypt(sock.recv(1))
            requestDataAddrLen = ord(r_requestDataAddrLen)
            #recv addr
            requestDataAddr = self.rfile.read(requestDataAddrLen)
            requestDataAddr = self.decrypt(requestDataAddr)
        elif requestDataAtyp == 4:
            #ipv6
            #not support
            return ()

        #Get port
        r_requestDataPort = self.decrypt(self.rfile.read(2))
        requestDataPort = struct.unpack('>H',r_requestDataPort)
        requestDataPort = requestDataPort[0]
        print (requestDataAddr,requestDataPort)
        return (requestDataAddr,requestDataPort)

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
                    decryptedData = self.decrypt(data)
                    result = send_all(remote,decryptedData)
                    if result < len(decryptedData):
                        raise Exception('Fail to send all data')
                if remote in rs:
                    data = remote.recv(4096)
                    if len(data) <= 0:
                        break
                    encryptedData = self.encrypt(data)
                    result = send_all(local,encryptedData)
                    if result < len(encryptedData):
                        raise Exception('Fail to send all data')

        finally:
            local.close()
            remote.close()

    def encrypt(self,data):
        return data.translate(encryptTable)

    def decrypt(self,data):
        return data.translate(decryptTable)

class SocksServer(ThreadingMixIn,TCPServer):
    allow_reuse_address = True

if __name__ == "__main__":
    encryptTable = getTransTable(KEY)
    decryptTable = string.maketrans(encryptTable,string.maketrans('',''))

    sevr = SocksServer(('', PORT), SocksServerHandler)
    print 'Starting server at port %d' % PORT
    sevr.serve_forever()

