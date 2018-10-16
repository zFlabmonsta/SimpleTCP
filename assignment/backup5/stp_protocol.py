#!/usr/bin/python2.7

import sys
import hashlib

SYN_FLAG = 0
ACK_FLAG = 1
FIN_FLAG = 2

class STP_Protocol(object):

    def __init__(self, dest_port=None):
        self.dest_port = dest_port
        self.seq_num = None
        self.ack_num = None
        # syn, #ack, #fin
        self.flags = [0, 0, 0]
        self.payload= None
        self.hash_checksum = 0

    def isSYN(self):
        return self.flags[SYN_FLAG] == 1

    def isACK(self):
        return self.flags[ACK_FLAG] == 1

    def isFIN(self):
        return self.flags[FIN_FLAG] == 1

    def payload_size(self):
        if (self.payload == None):
            return 0
        return sys.getsizeof(self.payload)

    def set_checksum(self, cs):
        self.hash_checksum = str(cs)

    def cmp_checksum(self):
        try:
            checksum = hashlib.sha256(self.payload)
            return str(checksum.hexdigest()) == self.hash_checksum
        except (TypeError):
            return True

    @staticmethod
    def stp_syn(dest_port, seq_num):
        packet = STP_Protocol(dest_port)
        packet.seq_num = seq_num 
        packet.flags[SYN_FLAG] = 1
        return packet

    @staticmethod
    def stp_syn_ack(dest_port, seq_num, ack_num):
        packet = STP_Protocol(dest_port)
        packet.seq_num  = seq_num
        packet.ack_num = ack_num
        packet.flags[SYN_FLAG] = 1
        packet.flags[ACK_FLAG] = 1
        return packet

    @staticmethod
    def stp_ack(dest_port, seq_num, ack_num, payload=None):
        packet = STP_Protocol(dest_port)
        packet.seq_num  = seq_num
        packet.ack_num = ack_num
        packet.flags[ACK_FLAG] = 1
        packet.payload = payload
        return packet

    @staticmethod
    def stp_fin(dest_port):
        packet = STP_Protocol(dest_port)
        packet.flags[FIN_FLAG] = 1
        return packet
