import string
import hashlib
import random
import struct
KEY = "no more secret"

def getTransTable(key):
    md5Box = hashlib.md5()
    md5Box.update(key)
    md5Digest = md5Box.digest()#128bit
    random.seed(md5Digest)
    table = [ch for ch in string.maketrans('','')]
    for i in xrange(1,1024):
        table.sort(lambda x,y:random.randint(-1,1))
    return ''.join(table)


