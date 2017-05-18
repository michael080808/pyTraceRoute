# -*- coding: utf-8 -*-
"""

IP(Internet Protocol):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|Version|  IHL  |Type of Service|         Total Length          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Identification         | Flags | Fragmentation Offset  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Time to Live  |   Protocol    |        Header Checksum        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Source Address                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                      Destination Address                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Options                    |    Padding    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                             Data                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP(Internet Control Message Protocol):
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |     Code      |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Identifier           |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Optional Data                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

TCP(Transmission Control Protocol)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Acknowledgment Number(if ACK set)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Data  | | | |N|C|E|U|A|P|R|S|F|            Window             |
|       |0|0|0| |W|C|R|C|S|S|Y|I|                               |
|Offset | | | |S|R|E|G|K|H|T|N|N|             Size              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |   Urgent pointer(if URG set)  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Options                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

Tracert/TraceRouter Process
1.Struct TCP, Set TTL(Time to Live) = 1
2.Try to start TCP connection, Record Time t1,
3.Receive ICMP Error Packets

    Timeout     -> Middleware Router, Continue to 4
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
    |0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Type = 11   |   Code = 0    |           Checksum            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                            Unused                             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |              IP Header + Original Data Fisrt 8B               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Reachable -> Catch TCP [SYN, ACK]

4.TTL = TTL + 1, Return Item 2.
"""
import time
import socket
import fcntl
import struct
import random
import threading

def setTcpSYNPacket(sourceIP, destinationIP, sourcePort = None, destinationPort = 80):
    srcIP = socket.gethostbyname(sourceIP)
    dstIP = socket.gethostbyname(destinationIP)

    if sourcePort:
        srcPort = sourcePort
    else:
        srcPort = random.randint(1024, 65536)

    dstPort = destinationPort

    seqNumb = int(time.time())
    randomA = random.randint(0, 65536)

    tcpPrePacket = struct.pack('!HHLLBBHHHL', srcPort, dstPort, seqNumb, 0, 0x50, 0x02, 65535, 0, 0, randomA)
    tcpPseudoPacket = struct.pack('!BBBBBBBBHH',
                                  socket.inet_aton(srcIP)[0], socket.inet_aton(srcIP)[1], socket.inet_aton(srcIP)[2], socket.inet_aton(srcIP)[3],
                                  socket.inet_aton(dstIP)[0], socket.inet_aton(dstIP)[1], socket.inet_aton(dstIP)[2], socket.inet_aton(dstIP)[3],
                                  0x0006, len(tcpPrePacket)) + tcpPrePacket

    sum = 0
    for i in range(0, len(tcpPseudoPacket), 2):
        sum += (tcpPseudoPacket[i] << 8) + tcpPseudoPacket[i + 1]
    checksum = 0xFFFF - (((sum & 0xFFFF0000) >> 16) + sum & 0xFFFF)

    tcpPacket = struct.pack('!HHLLBBHHHL', srcPort, dstPort, seqNumb, 0, 0x50, 0x02, 65535, checksum, 0, randomA)
    return tcpPacket

class RecvSocket:

    def __init__(self, type, timeout):
        self.r = socket.socket(socket.AF_INET, socket.SOCK_RAW, type)
        self.r.settimeout(timeout)
        self.packet = b''

    def run(self):
        try:
            self.t1 = time.time()
            self.packet, self.address = self.r.recvfrom(1024)
            self.t2 = time.time()
        except socket.timeout as err:
            self.address = None
        except KeyboardInterrupt:
            exit()
        finally:
            self.r.close()

    def getResponseAddress(self):
        if self.address:
            return self.address[0]
        else:
            return None

    def getTimeCost(self):
        return self.t2 - self.t1

def main(dst, dstPort = 80, src = '0.0.0.0', srcPort = None, timeout = 1):

    type = socket.IPPROTO_ICMP

    ttl = 1

    while type == socket.IPPROTO_ICMP and ttl <= 30:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

        recvIcmpSocket = RecvSocket(socket.IPPROTO_ICMP, timeout)
        recvTcpSocket = RecvSocket(socket.IPPROTO_TCP, timeout)
        threads = [threading.Thread(target=recvIcmpSocket.run), threading.Thread(target=recvTcpSocket.run)]

        s.sendto(setTcpSYNPacket(src, dst, srcPort, dstPort), (dst, dstPort))
        for t in threads:
            t.start()
            t.join()

        delta_t = 0
        if recvTcpSocket.getResponseAddress():
            address = recvTcpSocket.getResponseAddress()
            delta_t = recvTcpSocket.getTimeCost()
            type = socket.IPPROTO_TCP
        elif recvIcmpSocket.getResponseAddress():
            address = recvIcmpSocket.getResponseAddress()
            delta_t = recvIcmpSocket.getTimeCost()
            type = socket.IPPROTO_ICMP
        else:
            address = None

        if address:
            print("%2d: %4dms, %3d.%3d.%3d.%3d" % (ttl, int(delta_t * 1000), socket.inet_aton(address)[0], socket.inet_aton(address)[1], socket.inet_aton(address)[2], socket.inet_aton(address)[3]))
        else:
            print("%2d: ____ms, ___.___.___.___" % (ttl))

        ttl += 1

if __name__ == '__main__':

    main(dst='www.baidu.com', src='192.168.0.20')
