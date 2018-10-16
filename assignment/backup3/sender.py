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
        self.init_seg_sent = False
        self.window = 0
        self.index = 0
        self.window_ack = 0
        self.was_dropped = False
        self.to_dup = False
        self.to_reorder = False
        self.reorder_list = []
        self.tear_down = False

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
    def snd_pckt(self, stp_seg, msg):
        print (msg)
        self.sender_socket.sendto(pickle.dumps(stp_seg), (self.rcv_host_ip, self.rcv_port))

    def parse_pld(self):
        if (self.pld.isDrop() == True):
            return "dropped"
        else:
            self.was_dropped = False
            if (self.pld.isDuplicate() == True):
                return "duplicated"
            else:
                self.to_dup = False
                if (self.pld.isCorrupt() == True):
                    return "corrupted"
                else:
                    if (self.pld.isOrder() == True):
                        return "reorder"
                    else:
                        return self.pld.delay_time()

    def snd_wind_pckt(self):
        while (self.window < self.num_windows and self.index < len(self.stp_segment.segments)):
            print ("# Amount Acked per Window: " + str(self.window_ack))
            print ("# Window Number: " + str(self.window + 1) + " | Max Windows: " + str(self.num_windows))

            # get segment | size | hash checksum
            seg = self.stp_segment.segments[self.index]
            seg_size = self.stp_segment.datasize(seg)
            h = hashlib.sha256(seg)

            # create packet | set checksum to packet
            seqnum = self.stp_segment.seq[self.index]
            acknum = self.next_ack_num
            stp_ack = STP_Protocol.stp_ack(self.rcv_port, seqnum, acknum, seg) 
            stp_ack.set_checksum(h.hexdigest())

            pld_result = self.parse_pld()
            if (pld_result == "dropped"):
                print ("# Sent Packet has been dropped\n")
                self.was_dropped = True
                self.window += 1
                self.index += 1
                continue

            elif (pld_result == "duplicated"):
                print ("# Sent Packet has Duplicated")
                self.to_dup = True
                msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                self.snd_pckt(stp_ack, msg)
                self.window += 1

            elif (pld_result == "corrupted"):
                print ("# Sent Packet Corrupted Segment")
                seg = self.stp_segment.segments[self.index] + 'c'
                stp_ack.payload = seg

            elif (pld_result == "reorder"):
                print("# Re-ordering Packet")
                self.reorder_list.append(stp_ack)
                if (len(self.reorder_list) == self.pld.maxOrder):
                    stp_ack = self.reorder_list.pop(0)

            elif (pld_result >= 0 and pld_result <= self.pld.maxDelay):
                print ("# Delay time " + str(pld_result))
                time.sleep(pld_result/1000)
                pass

            self.init_seg_sent = True
            self.was_dropped = False
            # send packet | print msg
            msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
            self.snd_pckt(stp_ack, msg)

            # increment through window
            self.window += 1
            self.index += 1

            print ("###############################################\n")

    # sends file to the receiver ... runs the whole program 
    # No listening/accepting socket connection over UDP
    def run_sendfile(self):
        print ("Sending file")
        # IP and PORT
        while (True):
            # Three-way handshake 
            #time.sleep(1.1)
            curr = self.stp_timer.curr_time_diff()
            print ("current time diff: " + str(curr))
            if (self.stp_handshake_completed == False):
                # Initate or timed-out
                if (self.rcvd_packet == None):
                    msg = "Initiating 3-way HandShake and sending SYN packet ... "
                    # start timer to set first sampleRTT
                    self.stp_timer.start_timer()
                    # send packet
                    stp_syn = STP_Protocol.stp_syn(self.rcv_port, self.next_seq_num)
                    self.snd_pckt(stp_syn, msg)
                
                # SYNACK - completes 3 way handshake 
                elif (self.rcvd_packet.isSYN() and self.rcvd_packet.isACK()):
                    print ("# Received SYNACK...")

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
                    print ("Timer Started")
                    self.stp_timer.start_timer()
                    # Send ACK back
                    stp_ack = STP_Protocol.stp_ack(self.rcv_port, self.next_seq_num, self.next_ack_num)
                    self.snd_pckt(stp_ack, msg)
            
            elif (curr > self.stp_timer.timeout_interval):
                print("# Timeout - Retransmitting Packet")
                self.stp_timer.stop_timer()
                self.stp_timer.double_timeout_interval()
                self.stp_timer.start_timer()
                # Get index of sendbase
                self.index = self.stp_segment.getIndex(self.sendbase)

                # get segment | size | hash checksum
                seg = self.stp_segment.segments[self.index]
                seg_size = self.stp_segment.datasize(seg)
                h = hashlib.sha256(seg)

                # create packet | set checksum to packet
                seqnum = self.stp_segment.seq[self.index]
                acknum = self.next_ack_num
                stp_ack = STP_Protocol.stp_ack(self.rcv_port, seqnum, acknum, seg) 
                stp_ack.set_checksum(h.hexdigest())

                # pld parse
                pld_result = self.parse_pld()
                if (pld_result == "dropped"):
                    self.was_dropped = True
                    print ("# Sent Packet has been dropped\n")
                    continue

                elif (pld_result == "duplicated"):
                    print ("# Sent Packet has Duplicated")
                    self.to_dup = True
                    msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                    self.snd_pckt(stp_ack, msg)

                elif (pld_result == "corrupted"):
                    print ("# Sent Packet Corrupted Segment")
                    seg = self.stp_segment.segments[self.index] + 'c'
                    stp_ack.payload = seg

                elif (pld_result == "reorder"):
                    print("# Re-ordering Packet")
                    self.reorder_list.append(stp_ack)
                    if (len(self.reorder_list) == self.pld.maxOrder):
                        stp_ack = self.reorder_list.pop(0)

                elif (pld_result >= 0 and pld_result <= self.pld.maxDelay):
                    print ("# Delay time " + str(pld_result))
                    time.sleep(pld_result/1000)
                    pass

                self.was_dropped = False
                # send packet | print msg
                msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                self.snd_pckt(stp_ack, msg)
                print ("****************************************\n")

            elif (self.tear_down == True):
                print ("Closing Connection ...")
                # Send FIN flag
                stp_fin = STP_Protocol.stp_fin(self.rcv_port)
                self.snd_pckt(stp_fin, "Sending FIN...")
                # Receive ACK flag
                print("Received ACK ...")
                (packet, address) = self.sender_socket.recvfrom(1024)
                self.rcvd_packet = pickle.loads(packet)
                if (self.rcvd_packet.isACK() == False):
                    continue
                # Receive FIN flag
                print("Received FIN ...")
                (packet, address) = self.sender_socket.recvfrom(1024)
                self.rcvd_packet = pickle.loads(packet)
                if (self.rcvd_packet.isFIN() == False):
                    continue
                # Send ACK flag
                stp_ack = STP_Protocol.stp_ack(self.rcv_port, 0, 0)
                self.snd_pckt(stp_ack, "Sending ACK ...")
                # Close Socket and tear down
                print("Closing Socket ...")
                self.sender_socket.close()
                break
            
            else:
                # send ACK with payload
                if ((self.rcvd_packet.isACK() or self.was_dropped == True) and self.tear_down == False):

                    # Retrieve packet from the receiver and extracting SEQ and ACK for sender's next SEQ and ACK
                    if (self.was_dropped != True):
                        print ("# Received ACK| SEQ = {}| ACK = {}...".format(self.rcvd_packet.seq_num, self.rcvd_packet.ack_num))
                   
                    # count ack for a particular seq num
                    try:
                        self.index = self.stp_segment.getIndex(self.rcvd_packet.ack_num)
                        self.stp_segment.ack_inc[self.index] += 1
                    except (TypeError):
                        pass

                    # rebase last unacknowledged number
                    if (self.rcvd_packet.ack_num > self.sendbase): 
                        # Reset all ack dups
                        for e in self.stp_segment.ack_inc:
                            e = 0
                        self.sendbase = self.rcvd_packet.ack_num
                        self.window_ack += 1

                    # index of the sendbase | last unacked | fast retransmission
                    if (self.index != None and self.stp_segment.ack_inc[self.index] == 3):
                        print ("Fast Retransmission")
                        self.index = self.stp_segment.getIndex(self.sendbase)

                    # All segments sent, send finish flag
                    if (self.index == None):
                        self.tear_down = True
                        continue

                    # Send packet with payload to the receiver
                    else:
                        # Next ack number, unidirectional so no payload
                        self.next_ack_num = self.rcvd_packet.seq_num  

                        # restart window when all windows have been acked
                        if (self.window_ack == self.num_windows or self.window == self.num_windows):
                            self.window_ack = 0
                            self.window = 0

                        # Start Timer
                        if (self.stp_timer.timer_running() == False):
                            print ("Starting Timer")
                            self.stp_timer.start_timer()

                        # send packets that are in the window
                        self.snd_wind_pckt()

                        # Case for window size of 1 
                        if (self.was_dropped == True and self.num_windows == self.window):
                            continue

            print ("****************************************\n")
            
            # Save curr tcp-segment
            (packet, address) = self.sender_socket.recvfrom(1024)
            self.rcvd_packet = pickle.loads(packet)

            # stop timer and calculate new RTTs
            print("Timer Stopped")
            self.stp_timer.stop_timer()
            self.stp_timer.set_sampleRTT(self.stp_timer.diff_time())
            self.stp_timer.calculate_new_devRTT()
            self.stp_timer.calculate_new_estRTT()
            self.stp_timer.calculate_timeout_interval()
#            self.stp_timer.reset_timer()

sender = Sender(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9], sys.argv[10], sys.argv[11], sys.argv[12], sys.argv[13], sys.argv[14])
sender.create_socket()
sender.file_segmentation()
sender.run_sendfile()
