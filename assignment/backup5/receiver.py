#!/usr/bin/python2.7

import sys
import socket
import pickle
import time
from stp_protocol import *
from segments import *

SYN_FLAG = 0
ACK_FLAG = 1
FIN_FLAG = 2

class Receiver(object):
    def __init__(self, portnumber, filename):
        self.curr_packet = None
        self.next_seq_num = 0
        self.next_ack_num = 0
        self.tear_down = False

        self.rcvr_socket = None
        self.port = int(portnumber)
        self.filename = str(filename)
        self.rcvd_segs = STP_Segment()
    
    # creates socket for the receiver using UDP stream
    def create_socket(self):
        print("Creating Socket ...")
        self.rcvr_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Socket Created")
   
    # binds the socket and portnumber to application
    def bind_socket(self):
        print ("Binding Socket ...")
        port = self.port
        self.rcvr_socket.bind(('', self.port))
        print ("Socket Binded")

    def send_seg(self, stp_seg, addr, msg):
        print (msg)
        self.rcvr_socket.sendto(pickle.dumps(stp_seg), addr)

    # receives item from the sender ... runs whole program
    # No listening/accepting socket connection over UDP
    def run_receivefile(self):
        while True:
            (seg, addr) = self.rcvr_socket.recvfrom(256000)
            self.curr_packet = pickle.loads(seg)
            
            # Received SYN packet
            if (self.curr_packet.isSYN()):
                print ("Received SYN ...| SEQ = {}".format(self.curr_packet.seq_num))
                self.next_seq_num = 0
                self.next_ack_num = self.curr_packet.seq_num + 1

                msg = "Sending SYACK| SEQ = {} | ACK = {}...".format(self.next_seq_num, self.next_ack_num)
                stp_syn_ack = STP_Protocol.stp_syn_ack(self.port, self.next_seq_num, self.next_ack_num)
                self.send_seg(stp_syn_ack, addr, msg)
            
            # Received ACK packet
            elif (self.curr_packet.isACK() and self.tear_down == False):
                # size of payload received
                payload_size = STP_Segment.datasize(self.curr_packet.payload)
                print ("Received ACK|SEQ = {}|ACK = {}| Data Size = {}...".format(self.curr_packet.seq_num, self.curr_packet.ack_num, payload_size))

                # Packet already received send ack back and continue loop
                # Append payload to other segments if segment hasn't already been received
                print("Checksum Correct: " + str(self.curr_packet.cmp_checksum()))
                if (payload_size != 0 and self.rcvd_segs.getIndex(self.curr_packet.seq_num) == None and self.curr_packet.cmp_checksum()):
                    # this if for first segment if it fails then dont append to list otherwise list will be out of order
                    if (self.next_ack_num == self.curr_packet.seq_num):
                        self.rcvd_segs.seq.append(int(self.curr_packet.seq_num))
                        self.rcvd_segs.segments.append(self.curr_packet.payload)
                else:
                    payload_size = 0
                
                # Extract seq and ack | update next ack only if expected seq is rcvd otherwise resends latest ack
                if (self.next_ack_num == self.curr_packet.seq_num):
                    self.next_ack_num += payload_size 
                else:
                    try:
                        latest_index = len(self.rcvd_segs.segments) - 1
                        latest_seg_size = len(self.rcvd_segs.segments[latest_index])
                        self.next_ack_num = self.rcvd_segs.seq[latest_index] + latest_seg_size
                    except (IndexError):
                        pass
                self.next_seq_num = self.curr_packet.ack_num

                # Send ACK packet back to sender
                msg = "Sending Packet|SEQ = {}|ACK = {}...".format(self.next_seq_num, self.next_ack_num)
                stp_ack = STP_Protocol.stp_ack(self.port, self.next_seq_num, self.next_ack_num)
                self.send_seg(stp_ack, addr, msg)
            
            elif (self.curr_packet.isFIN() == True):
                print ("\nClosing Connection ...")
                self.tear_down = True
                # Send ACK
                stp_ack = STP_Protocol.stp_ack(self.port, 0, 0)
                self.send_seg(stp_ack, addr, "Sending ACK ...")
                time.sleep(0.1)
                # Send FIN
                stp_fin = STP_Protocol.stp_fin(self.port)
                self.send_seg(stp_fin, addr, "Sending FIN ...")
                # Receive ACK
            elif (self.tear_down == True):
                print ("Received ACK ...")
                if (self.curr_packet.isACK() == False):
                    continue
                # Close socket
                print("Closing socket")
                self.rcvr_socket.close()
                break

            print ("\n")



rcv = Receiver(sys.argv[1], sys.argv[2])
rcv.create_socket()
rcv.bind_socket()
rcv.run_receivefile()
rcv.rcvd_segs.writefile(rcv.filename)





























