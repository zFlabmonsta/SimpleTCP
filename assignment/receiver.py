#!/usr/bin/python2.7

import sys
import socket
import pickle
import time
from stp_protocol import *
from segments import *
from logger import *

class Receiver(object):
    def __init__(self, portnumber, filename):
        ''' receiver is able to send back ACK, FIN and
            writes the segment that were sent by the sender
        '''

        ''' These are variables to keep track of the certain state of the program'''
        self.rcvd_packet = None
        self.next_seq_num = 0
        self.next_ack_num = 0
        self.tear_down = False

        ''' other program sender uses ''' 
        self.rcvr_socket = None
        self.port = int(portnumber)
        self.filename = str(filename)
        self.rcvd_segs = STP_Segment()
        self.logger = None

        ''' Data '''
        self.amount_data_received = 0
        self.total_seg_rcvd = 0
        self.num_bit_errors = 0
        self.num_dupl = 0
        self.dup_sent = 0
    
    '''creates socket for the receiver using UDP stream 
        REFERENCE: The socket function was used and edited, out of docs.python
    '''
    def create_socket(self):
        print("Creating Socket ...")
        self.rcvr_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Socket Created")
   
    '''binds the socket and portnumber to application
       REFERENCE: The bind function was used and edited, out of docs.python
    '''
    def bind_socket(self):
        print ("Binding Socket ...")
        port = self.port
        self.rcvr_socket.bind(('', self.port))
        print ("Socket Binded")

    ''' prints out message prior to sending message,
        before message is sent, the packet is passed through pickle dump
    '''
    def send_seg(self, stp_seg, addr, msg):
        print (msg)
        self.rcvr_socket.sendto(pickle.dumps(stp_seg), addr)

    ''' Functions that initiates connection (3-way handshake),
        Receives packets and process them
        Closes the socket when finished
    '''
    def run_receivefile(self):
        delayed = False
        while True:
            # Data collecting purposes#
            try:
                prevseqnum = self.rcvd_packet.seq_num
            except (AttributeError):
                prevseqnum = -1
            #############################
            # receives some sort of packet
            (seg, addr) = self.rcvr_socket.recvfrom(256000)
            self.rcvd_packet = pickle.loads(seg)
            ############## Data collecting purposes#############
            if (self.rcvd_packet.seq_num == prevseqnum):
                print("duplicate files")
                delayed = True
                self.num_dupl += 1
            #################################################
            # Received SYN packet | Handshake
            if (self.rcvd_packet.isSYN()):
                self.logger = Logger("Receiver_log.txt")
                print ("Received SYN ...| SEQ = {}".format(self.rcvd_packet.seq_num))
                self.next_seq_num = 0
                self.next_ack_num = self.rcvd_packet.seq_num + 1
                ################## Logging Purpose #####################
                self.logger.write_log(self.rcvd_packet, "SYN", "rcv")
                #########################################################
                msg = "Sending SYACK| SEQ = {} | ACK = {}...".format(self.next_seq_num, self.next_ack_num)
                stp_syn_ack = STP_Protocol.stp_syn_ack(self.port, self.next_seq_num, self.next_ack_num)
                self.send_seg(stp_syn_ack, addr, msg)
                ################## Logging Purpose #####################
                self.logger.write_log(stp_syn_ack, "SA", "snd")
                #########################################################

            # Received ACK packet
            elif (self.rcvd_packet.isACK() and self.tear_down == False):
                # size of payload received
                payload_size = STP_Segment.datasize(self.rcvd_packet.payload)
                print ("Received ACK|SEQ = {}|ACK = {}| Data Size = {}...".format(self.rcvd_packet.seq_num, self.rcvd_packet.ack_num, payload_size))

                # Data 
                self.amount_data_received += payload_size
                ################## Logging Purpose #####################
                print(self.rcvd_packet.seq_num )
                if (self.rcvd_segs.getIndex(self.rcvd_packet.seq_num) != None):
                    self.logger.write_log(self.rcvd_packet, "D", "rcv/DA")
                    print "here"
                elif (self.rcvd_packet.cmp_checksum() == False):
                    self.logger.write_log(self.rcvd_packet, "D", "rcv/corr")
                    self.num_bit_errors += 1
                    delayed = True
                else:
                    self.logger.write_log(self.rcvd_packet, "D", "rcv")
                #########################################################

                # Packet already received send ack back and continue loop
                # Append payload to other segments if segment hasn't already been received
                print("Checksum Correct: " + str(self.rcvd_packet.cmp_checksum()))
                if (payload_size != 0 and self.rcvd_segs.getIndex(self.rcvd_packet.seq_num) == None and self.rcvd_packet.cmp_checksum()):
                    # this if for first segment if it fails then dont append to list otherwise list will be out of order
                    self.total_seg_rcvd += 1
                    if (self.next_ack_num == self.rcvd_packet.seq_num):
                        self.rcvd_segs.seq.append(int(self.rcvd_packet.seq_num))
                        self.rcvd_segs.segments.append(self.rcvd_packet.payload)
                else:
                    payload_size = 0

                # Extract seq and ack | update next ack only if expected seq is rcvd otherwise resends latest ack
                # cumaltive ACK behaviour
                if (self.next_ack_num == self.rcvd_packet.seq_num):
                    self.next_ack_num += payload_size 
                else:
                    try:
                        latest_index = len(self.rcvd_segs.segments) - 1
                        latest_seg_size = len(self.rcvd_segs.segments[latest_index])
                        self.next_ack_num = self.rcvd_segs.seq[latest_index] + latest_seg_size
                    except (IndexError):
                        pass
                self.next_seq_num = self.rcvd_packet.ack_num
                # Send ACK packet back to sender
                msg = "Sending Packet|SEQ = {}|ACK = {}...".format(self.next_seq_num, self.next_ack_num)
                stp_ack = STP_Protocol.stp_ack(self.port, self.next_seq_num, self.next_ack_num)
                self.send_seg(stp_ack, addr, msg)
                ################## Logging Purpose #####################
                if (delayed == True):
                    self.logger.write_log(stp_ack, "A", "snd/DA")
                    delayed = False
                    self.dup_sent += 1
                else:
                    self.logger.write_log(stp_ack, "A", "snd")
                #########################################################

            # Receives a FIN flag 
            elif (self.rcvd_packet.isFIN() == True):
                print ("\nClosing Connection ...")
                ################## Logging Purpose #####################
                self.logger.write_log(self.rcvd_packet, "F", "rcv")
                #########################################################
                self.tear_down = True
                # Send ACK
                stp_ack = STP_Protocol.stp_ack(self.port, self.rcvd_packet.ack_num, self.rcvd_packet.seq_num + 1)
                self.send_seg(stp_ack, addr, "Sending ACK ...")
                ################## Logging Purpose #####################
                self.logger.write_log(stp_ack, "A", "snd")
                #########################################################
                # Send FIN
                stp_fin = STP_Protocol.stp_fin(self.port, self.rcvd_packet.ack_num, self.rcvd_packet.seq_num + 1)
                self.send_seg(stp_fin, addr, "Sending FIN ...")
                ################## Logging Purpose #####################
                self.logger.write_log(stp_fin, "F", "snd")
                #########################################################

            # Finalising tear down
            elif (self.tear_down == True):
                if (self.rcvd_packet.isACK() == False):
                    continue
                ################## Logging Purpose #####################
                self.logger.write_log(self.rcvd_packet, "A", "rcv")
                #########################################################
                print ("Received ACK ...")
                # Close socket
                print("Closing socket")
                self.rcvr_socket.close()
                break

            print ("\n")
        self.logger.write_data("Amount of data received (bytes)", self.amount_data_received)
        self.logger.write_data("Total Segments Received", self.total_seg_rcvd)
        self.logger.write_data("Data Segments Received", len(self.rcvd_segs.segments))
        self.logger.write_data("Total Segments with Bit Errors", self.num_bit_errors)
        self.logger.write_data("Duplicate data segments received", self.num_dupl)
        self.logger.write_data("Duplicate ACKs sent", self.dup_sent)


if __name__ == "__main__":
    rcv = Receiver(sys.argv[1], sys.argv[2])
    rcv.create_socket()
    rcv.bind_socket()
    rcv.run_receivefile()
    rcv.rcvd_segs.writefile(rcv.filename)





























