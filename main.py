from socket import socket,AF_INET,SOCK_STREAM
from pymirai.utils.tools import *
from pymirai.utils.pack import Pack
from pymirai.utils.unpack import Unpack
from pymirai.utils.tea import Tea
import time
from AndroidQQ import AndroidQQ

Loginqq = AndroidQQ('xxxx','xxxx',0)
#print(bytes2hex(Loginqq.Pack_Login()))
s=socket(AF_INET,SOCK_STREAM)
s.connect(("113.96.12.224",8080))
s.send(Loginqq.Pack_Login())
buf = s.recv(2048)

a,b = Loginqq.Unpack_Login(buf)

while True:
    print("验证方式:",a,b)
    if a == 0:
        break
    elif a == 204:
        s.send(Loginqq.Pack_Login_204())
        buf = s.recv(2048)
        a,b = Loginqq.Unpack_Login(buf)
    else:
        exit(0)

s.send(Loginqq.Pack_Online(0))
up = Unpack()
while True:
    buf = s.recv(2048)
    try:
        up.setData(buf)
        datalen = up.getInt()
        if datalen >= 10000:
            continue
        while len(buf) > datalen:
            Loginqq.Unpack_All(int2bytes(datalen,4)+up.getBin(datalen))
            buf = up.getAll()
            datalen = up.getInt()
        while len(buf) < datalen:
            buf = buf + s.recv(2048)
            up.setData(buf)
            datalen = up.getInt()
            while len(buf) > datalen:
                Loginqq.Unpack_All(int2bytes(datalen,4)+up.getBin(datalen))
                buf = up.getAll()
                datalen = up.getInt()
        Loginqq.Unpack_All(buf)
    except Exception as e:
        print(e)
