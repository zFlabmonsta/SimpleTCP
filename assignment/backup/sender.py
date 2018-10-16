#!/usr/bin/python2.7

import sys
import socket
import pickle
import time
import hashlib
from stp_protocol import *
from segments import *
from timer import *
from pld_module import *

SYN_FLAG = 0
ACK_FLAG = 1
FIN_FLAG = 2

class Sender(object):
    def __init__(self, ip, port, filename, mws, mss, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed):
        self.sender_socket = None
        self.stp_segment = STP_Segment(mss)
        self.stp_timer = Timer(gamma)
        self.pld = PLD(pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed)

        # Keeping Track of STP state
        self.rcvd_packet = None
        self.sendbase = 0
        self.next_seq_num = 0
        self.next_ack_num = 0
        self.num_windows = int(mws)/int(mss)
        self.stp_handshake_completed = False

        # Stored Arguements
        self.rcv_host_ip = str(ip)
        self.rcv_port = int(port)
        self.filename = str(filename)

    # create socket for teh sender using UDP stream
    def create_socket(self):
        print ("Creating socket ....")
        self.sender_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Socket For Sender is created")

    # segmentations the file 
    def file_segmentation(self):
        self.stp_segment.segmentation(self.filename)

    # sends packet and prints out msg 
    def send_seg(self, stp_seg, msg):
        print (msg)
        self.sender_socket.sendto(pickle.dumps(stp_seg), (self.rcv_host_ip, self.rcv_port))

    # sends file to the receiver ... runs the whole program 
    # No listening/accepting socket connection over UDP
    def run_sendfile(self):
        print ("Sending file")
        # IP and PORT
        window = 0
        index = 0
        window_ack = 0
        was_dropped = False
        corrupt_seg = None
        while (True):
            # Three-way handshake 
            if (self.stp_handshake_completed == False):
                # Initate or timed-out
                if (self.rcvd_packet == None):
                    msg = "Initiating 3-way HandShake and sending SYN packet ... "
                    # start timer to set first sampleRTT
                    self.stp_timer.start_timer()
                    # send packet
                    stp_syn = STP_Protocol.stp_syn(self.rcv_port, self.next_seq_num)
                    self.send_seg(stp_syn, msg)
                
                # SYNACK - completes 3 way handshake 
                elif (self.rcvd_packet.flags[SYN_FLAG] == 1 and self.rcvd_packet.flags[ACK_FLAG] == 1):
                    print ("# Received SYNACK...")

                    # stop timer, set the samplertt, calculate new devrtt and estimated rtt, reset timer
                    self.stp_timer.stop_timer()
                    self.stp_timer.set_sampleRTT(self.stp_timer.diff_time())
                    self.stp_timer.calculate_new_devRTT()
                    self.stp_timer.calculate_new_estRTT()
                    self.stp_timer.reset_timer()

                    # extract / calculate next ack and seq number
                    self.next_ack_num = self.rcvd_packet.seq_num + 1 # No Payload so ACK doesn't increase
                    self.next_seq_num += 1
                    self.sendbase = self.next_seq_num

                    # completed 3-way handshake
                    print ("# 3-way HandShake Completed")
                    self.stp_handshake_completed = True

                    # Setup file segments ack and seq
                    self.stp_segment.setup(self.next_seq_num)

                    msg = "# Sending ACK | SEQ = {}| ACK = {}".format(self.next_seq_num, self.next_ack_num)
                    # start timer
                    self.stp_timer.start_timer()
                    # Send ACK back
                    stp_ack = STP_Protocol.stp_ack(self.rcv_port, self.next_seq_num, self.next_ack_num)
                    self.send_seg(stp_ack, msg)

            else:

                # send ACK with payload
                if (self.rcvd_packet.flags[ACK_FLAG] == 1 and self.rcvd_packet.flags[FIN_FLAG] == 0 or was_dropped == True):

                    # Retrieve packet from the receiver and extracting SEQ and ACK for sender's next SEQ and ACK
                    print ("# Received ACK| SEQ = {}| ACK = {}...".format(self.rcvd_packet.seq_num, self.rcvd_packet.ack_num))
                    # stop timer and calculate 
                    self.stp_timer.stop_timer()
                    self.stp_timer.set_sampleRTT(self.stp_timer.diff_time())
                    self.stp_timer.calculate_new_devRTT()
                    self.stp_timer.calculate_new_estRTT()
                    self.stp_timer.reset_timer()

                    # rebase last unacknowledged number
                    if (self.rcvd_packet.ack_num > self.sendbase): 
                        # acknum > sendbase == first segment has already been sent 
                        self.next_seq_num += seg_size
                        self.sendbase = self.rcvd_packet.ack_num
                        window_ack += 1

                    # index of the sendbase | last unacked 
                    index = self.stp_segment.getIndex(self.sendbase)

                    # restart window when all windows have been acked
                    if (window_ack == self.num_windows or window == self.num_windows):
                        window_ack = 0
                        window = 0

                    # All segments sent, send finish flag
                    if (index == None):
                        stp_fin = STP_Protocol.stp_fin(self.rcv_port)
                        msg = "# Sending FIN ... "
                        self.send_seg(stp_fin, msg)
                        break
                    # Send packet with payload to the retriever 
                    else:
                        # Next ack number, unidirectional so no payload
                        self.next_ack_num = self.rcvd_packet.seq_num  

                        # Start Timer
                        self.stp_timer.start_timer()

                        # PLD Module
                        if (self.pld.isDrop() == True):
                            was_dropped = True
                            print ("# Packet has been dropped\n")
                            continue
                        else:
                            was_dropped = False
                            # add duplicate packet into window
                            if (self.pld.isDuplicate() == True):
                                pass
                            else:
                                # corrupt the file
                                if (self.pld.isCorrupt() == True):
                                    print ("# Segment is Corrupted")
                                    corrupt_seg = self.stp_segment.segments[index] + 'c'
                                else:
                                    if (self.pld.isOrder() == True):
                                        # something to do with maxOrder
                                        pass
                                    else:
                                        delay_time = self.pld.delay_time()
                                        print ("# Delay time " + str(delay_time))
                                        time.sleep(delay_time/1000)

                        print ("# Amount Acked per Window: " + str(window_ack))
                        print ("# Window Number: " + str(window) + " | Max Windows: " + str(self.num_windows))
                        while (window < self.num_windows and index < len(self.stp_segment.segments)):
                            # Get size of segment new segment 
                            seg = self.stp_segment.segments[index]
                            seg_size = self.stp_segment.datasize(seg)
                            # create hashvalue | checksum
                            h = hashlib.sha256(seg)
                            # pld corrupt
                            if (corrupt_seg != None):
                                seg = corrupt_seg
                                corrupt_seg = None
                            # put payload into a packet with flag (ACK)
                            # PLD Module
                            
#                            if (self.pld.isDrop() == True):
#                                print ("# Sent Packet has been dropped\n")
#                                was_dropped = True
#                                window += 1
#                                index += 1
#                                continue
#                            else:
#                                was_dropped = False
#                                # add duplicate packet into window
#                                if (self.pld.isDuplicate() == True):
#                                    pass
#                                else:
#                                    # corrupt the file
#                                    if (self.pld.isCorrupt() == True):
#                                        print ("# Sent Pack has Corrupted Segment")
#                                        seg = self.stp_segment.segments[index] + 'c'
#                                    else:
#                                        if (self.pld.isOrder() == True):
#                                            # something to do with maxOrder
#                                            pass
#                                        else:
#                                            delay_time = self.pld.delay_time()
#                                            print ("# Delay time " + str(delay_time))
#                                            time.sleep(delay_time/1000)

                            stp_ack = STP_Protocol.stp_ack(self.rcv_port, self.stp_segment.seq[index], self.next_ack_num, seg) 
                            # set checksum in the packet
                            stp_ack.set_checksum(h.hexdigest())
                            msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(self.stp_segment.seq[index], self.next_ack_num, seg_size)
                            self.send_seg(stp_ack, msg)
                            # increment packets, piping like
                            window += 1
                            index += 1

            print ("****************************************\n")
            
            # Save curr tcp-segment
            (packet, address) = self.sender_socket.recvfrom(1024)
            self.rcvd_packet = pickle.loads(packet)

sender = Sender(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9], sys.argv[10], sys.argv[11], sys.argv[12], sys.argv[13], sys.argv[14])
sender.create_socket()
sender.file_segmentation()
sender.run_sendfile()
