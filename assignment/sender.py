#!/usr/bin/python2.7

import sys
import socket
import pickle
import time
import hashlib
import thread
from stp_protocol import *
from segments import *
from timer import *
from pld_module import *
from logger import *

class Sender(object):
    def __init__(self, ip, port, filename, mws, mss, gamma, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed):
        ''' other program sender uses ''' 
        self.socket = None
        self.segment = STP_Segment(mss)
        self.timer = Timer(gamma)
        self.pld = PLD(pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed)
        self.logger = Logger("Sender_log.txt")

        ''' These are variables to keep track of the certain state of the program'''
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
        self.reorder_list = []
        self.to_delay = False
        self.tear_down = False
        self.is_frtx = False
        self.wait = False

        # Counting Data
        self.filesize = 0
        self.num_transmitted = 0
        self.num_pld_handle = 0
        self.num_dropped = 0
        self.num_corrupted = 0
        self.num_reordered = 0
        self.num_delay = 0
        self.rtx_timeout = 0
        self.fast_rtx = 0
        self.num_dup_ack = 0

        # Stored Arguements
        ''' instance variables for arguments entered ''' 
        self.host_ip = str(ip)
        self.port_num = int(port)
        self.filename = str(filename)

    ''' This function creates a socket for the sender.
        REFERENCE: The socket function was used and edited, out of docs.python
    '''
    def create_socket(self):
        print ("Creating socket ....")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        print("Socket created")
    
    ''' Splits the file into segments and stores it in a list, which is
        sitting inside object segment
    '''
    def file_segmentation(self):
        self.segment.segmentation(self.filename)

    ''' prints out message prior to sending message,
        before message is sent, the packet is passed through pickle dump
    '''
    def snd_pckt(self, packet, msg):
        print (msg)
        self.socket.sendto(pickle.dumps(packet), (self.host_ip, self.port_num))

    ''' Uses pld and returns whatever the probability lands on '''
    def parse_pld(self):
        if (self.pld.isDrop() == True):
            self.num_pld_handle += 1
            return "dropped"
        else:
           # self.was_dropped = False
            if (self.pld.isDuplicate() == True):
                self.num_pld_handle += 1
                return "duplicated"
            else:
                self.to_dup = False
                if (self.pld.isCorrupt() == True):
                    self.num_pld_handle += 1
                    return "corrupted"
                else:
                    if (self.pld.isOrder() == True):
                        self.num_pld_handle += 1
                        return "reorder"
                    else:
                        return self.pld.delay_time()

    ''' A function that used specifically for multithreading, 
        which delays the packet with pausing the process
    ''' 
    def snd_delay(self, packet, delay):
        time.sleep(delay/1000) 
        self.snd_pckt(packet, "Sending Delayed Packet | SEQ = {} | ACK = {}". format(packet.seq_num, packet.ack_num))
        ###################### Logging Purpose ##########################
        self.logger.write_log(packet, "D", "snd/dely")
        self.num_transmitted += 1
        self.num_delay += 1
        self.num_pld_handle += 1
        #################################################################

    ''' A loop which acts as window '''
    def snd_wind_pckt(self):
        while (self.window < self.num_windows and self.index < len(self.segment.segments) and self.window_ack < self.num_windows):
            print ("# Amount Acked per Window: " + str(self.window_ack))
            print ("# Window Number: " + str(self.window + 1) + " | Max Windows: " + str(self.num_windows))

            # segment | size | hash checksum
            seg = self.segment.segments[self.index]
            seg_size = self.segment.datasize(seg)
            h = hashlib.sha256(seg)

            # create packet | set checksum to packet
            seqnum = self.segment.seq[self.index]
            acknum = self.next_ack_num
            stp_ack = STP_Protocol.stp_ack(self.port_num, seqnum, acknum, seg) 
            stp_ack.set_checksum(h.hexdigest())

            # Packet goes through PLD Module
            pld_result = self.parse_pld()
            # Drops packet
            if (pld_result == "dropped"):
                print ("# Sent Packet has been dropped\n")
                self.was_dropped = True
                self.window += 1
                self.index += 1
                ################# Logging Purpose #################
                self.logger.write_log(stp_ack, "D", "drop")
                self.num_transmitted += 1
                self.num_dropped += 1
                ###################################################
                continue
            # Duplicates packet and send it
            elif (pld_result == "duplicated"):
                print ("# Sent Packet has Duplicated")
                self.to_dup = True
                msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                self.snd_pckt(stp_ack, msg)
            # Corrupts payload by having something different 
            elif (pld_result == "corrupted"):
                print ("# Sent Packet Corrupted Segment")
                seg = self.segment.segments[self.index] + 'c'
                stp_ack.payload = seg
            # Reorders the packet being sent, by appending packet to list and sending first one in FIFO
            elif (pld_result == "reorder"):
                print("# Re-ordering Packet")
                self.reorder_list.append(stp_ack)
                # Send only if Queue is full
                if (len(self.reorder_list) == self.pld.maxOrder):
                    stp_ack = self.reorder_list.pop(0)
            # Delay packet, calls function and uses multi-threading 
            elif (pld_result > 0 and pld_result <= self.pld.maxDelay):
                print ("# Delay time " + str(pld_result))
                self.to_delay = True
                thread.start_new_thread(self.snd_delay, (stp_ack, pld_result, ))

            # send packet | print msg
            if (self.to_delay == False):
                msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                self.snd_pckt(stp_ack, msg)
                ################## Logging Purpose ######################
                if (self.is_frtx == True):
                    self.logger.write_log(stp_ack, "D", "snd/RXT")
                    self.is_frtx = False
                else:
                    self.logger.write_log(stp_ack, "D", "snd")
                self.num_transmitted += 1
                #########################################################

            ################## Logging Purpose ########################
            if (pld_result == "duplicate"):
                self.logger.write_log(stp_ack, "D", "snd/dup")
            elif (pld_result == "corrupted"):
                self.logger.write_log(stp_ack, "D", "snd/corr")
                self.num_corrupted += 1
            elif (pld_result == "reorder"):
                self.logger.write_log(stp_ack, "D", "snd/rord")
                self.num_reordered += 1
            #############################################################

            # Fix status 
            self.to_delay = False
            self.init_seg_sent = True
            self.was_dropped = False
            self.window += 1
            self.index += 1

            print ("###############################################\n")

    ''' Functions that initiates connection (3-way handshake),
        Receives packets and process them
        Closes the socket when finished
    '''
    def run_sendfile(self):
        print ("Sending file")
        while (True):
            # Initiate the 3 way Hand Shake
            curr = self.timer.curr_time_diff()
#            print (curr)
#            print (self.timer.timeout_interval)
            if (self.stp_handshake_completed == False):
                # Sends SYN Packet | Start Timer
                if (self.rcvd_packet == None):
                    msg = "Initiating 3-way HandShake and sending SYN packet ... "
                    self.timer.start_timer()
                    stp_syn = STP_Protocol.stp_syn(self.port_num, self.next_seq_num)
                    self.snd_pckt(stp_syn, msg)
                    ##################### Logging Purpose #####################
                    self.logger.write_log(stp_syn, "S", "snd")
                    self.num_transmitted += 1
                    ########################################################### 

                # Receives SYNACK | Send ACK (No Data back) | Start Timer
                elif (self.rcvd_packet.isSYN() and self.rcvd_packet.isACK()):
                    print ("# Received SYNACK...| SEQ = {} | ACK = {}".format(self.rcvd_packet.seq_num, self.rcvd_packet.ack_num))
                    ################## Logging Purpose ###################
                    self.logger.write_log(self.rcvd_packet, "SA", "rcv")
                    ######################################################

                    # Calculate next ack and seq values
                    self.next_ack_num = self.rcvd_packet.seq_num + 1 # No Payload so ACK doesn't increase
                    self.next_seq_num += 1
                    self.sendbase = self.next_seq_num

                    # Completed 3-way Handshake, due to SYNACK
                    print ("# 3-way HandShake Completed")
                    self.stp_handshake_completed = True

                    # Setup file segments the sequence numbers needed for each segment 
                    self.segment.setup(self.next_seq_num)
                    
                    # Start the timer
                    print ("Timer Started"); self.timer.start_timer()
                    # Send ACK
                    msg = "# Sending ACK | SEQ = {}| ACK = {}".format(self.next_seq_num, self.next_ack_num)
                    stp_ack = STP_Protocol.stp_ack(self.port_num, self.next_seq_num, self.next_ack_num)
                    self.snd_pckt(stp_ack, msg)
                    #################### Logging Purpose ################
                    self.logger.write_log(stp_ack, "A", "snd")
                    self.num_transmitted += 1
                    #####################################################
            
            # Retransmit packets when timeout has occurs, doesn't work if delayed ack or during tear down
            # REFERENCE: This was section here was taken and edited out of the textbook
            elif ((curr > self.timer.timeout_interval or curr > 60000) and self.tear_down == False):
                print("# Timeout - Retransmitting Packet")
                self.rtx_timeout += 1
                self.timer.stop_timer()
                # Double timeout interval
                self.timer.double_timeout_interval()
                # Start timer
                self.timer.start_timer()

                # Get index of sendbase
                self.index = self.segment.getIndex(self.sendbase)

                # get segment | size | hash checksum
                seg = self.segment.segments[self.index]
                seg_size = self.segment.datasize(seg)
                h = hashlib.sha256(seg)

                # create packet | set checksum to packet
                seqnum = self.segment.seq[self.index]
                acknum = self.next_ack_num
                stp_ack = STP_Protocol.stp_ack(self.port_num, seqnum, acknum, seg) 
                stp_ack.set_checksum(h.hexdigest())

                # PLD Parse
                pld_result = self.parse_pld()
                # Drop Packet
                if (pld_result == "dropped"):
                    self.was_dropped = True
                    print ("# Sent Packet has been dropped\n")
                    ############### Logging Purpose ##################
                    self.logger.write_log(stp_ack, "D", "drop")
                    self.num_transmitted += 1
                    self.num_dropped += 1
                    ##################################################
                    continue
                # Duplicates packet and sends it
                elif (pld_result == "duplicated"):
                    print ("# Sent Packet has Duplicated")
                    self.to_dup = True
                    msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                    self.snd_pckt(stp_ack, msg)
                    self.num_transmitted += 1
                # Corrupts packet by editting the segment
                elif (pld_result == "corrupted"):
                    print ("# Sent Packet Corrupted Segment")
                    seg = self.segment.segments[self.index] + 'c'
                    stp_ack.payload = seg
                # Reorders packet that going to be sent
                elif (pld_result == "reorder"):
                    print("# Re-ordering Packet")
                    self.reorder_list.append(stp_ack)
                    if (len(self.reorder_list) == self.pld.maxOrder):
                        stp_ack = self.reorder_list.pop(0)
                # Delay packet
                elif (pld_result > 0 and pld_result <= self.pld.maxDelay):
                    print ("# Delay time " + str(pld_result))
                    self.to_delay = True
                    thread.start_new_thread(self.snd_delay, (stp_ack, pld_result,))
                    pass

                # Send packet | Print msg
                if (self.to_delay == False):
                    msg ="# Sending Packet|SEQ = {}|ACK = {}|Data Size = {}...".format(str(stp_ack.seq_num), str(stp_ack.ack_num), str(len(stp_ack.payload)))
                    self.snd_pckt(stp_ack, msg)
                    ##################Logging Purpose ##################
                    self.logger.write_log(stp_ack, "D", "snd/RXT")
                    self.num_transmitted += 1
                    ####################################################

                ################## Logging Purposes ########################
                if (pld_result == "duplicate"):
                    self.logger.write_log(stp_ack, "D", "snd/dup")
                elif (pld_result == "corrupted"):
                    self.logger.write_log(stp_ack, "D", "snd/corr")
                    self.num_corrupted += 1
                elif (pld_result == "reorder"):
                    self.logger.write_log(stp_ack, "D", "snd/rord")
                    self.num_reordered += 1
                #############################################################

                # Reset status
                self.is_delay = False
                print ("****************************************\n")

            elif (self.tear_down == True):
                print ("Closing Connection ...")
                # Send FIN flag
                stp_fin = STP_Protocol.stp_fin(self.port_num, self.rcvd_packet.ack_num, self.rcvd_packet.seq_num)
                self.snd_pckt(stp_fin, "Sending FIN...")
                ################# Logging Purpose ##################
                self.logger.write_log(stp_fin, "F", "snd")
                self.num_transmitted += 1
                ####################################################

                # Receive ACK flag
                (packet, address) = self.socket.recvfrom(1024)
                self.rcvd_packet = pickle.loads(packet)
                if (self.rcvd_packet.ack_num < self.segment.filesize()):
                    print("HERE")
                    ################## Logging Purpose ##################
                    self.logger.write_log(self.rcvd_packet, "A", "rcv/DA")
                    self.num_dup_ack += 1
                    #####################################################
                    continue
                print("Received ACK ...")
                ################## Logging Purpose ##################
                self.logger.write_log(self.rcvd_packet, "A", "rcv")
                #####################################################

                # Receive FIN flag
                (packet, address) = self.socket.recvfrom(1024)
                self.rcvd_packet = pickle.loads(packet)
                if (self.rcvd_packet.isFIN() == False):
                    ################## Logging Purpose ##################
                    self.logger.write_log(self.rcvd_packet, "A", "rcv/DA")
                    self.num_dup_ack += 1
                    #####################################################
                    continue
                print("Received FIN ...")
                ################## Logging Purpose ###################
                self.logger.write_log(self.rcvd_packet, "F", "rcv")
                ######################################################

                # Send ACK flag
                stp_ack = STP_Protocol.stp_ack(self.port_num, self.rcvd_packet.ack_num, self.rcvd_packet.seq_num + 1)
                self.snd_pckt(stp_ack, "Sending ACK ...")
                ################## Logging Purpose #################
                self.logger.write_log(stp_ack, "A", "snd")
                self.num_transmitted += 1
                ####################################################

                # Close Socket and tear down
                print("Closing Socket ...")
                self.socket.close()
                break
            
            else:
                # Send ACK with payload
                if ((self.rcvd_packet.isACK()) and self.wait == False and self.tear_down == False):
                    # Retrieve packet from the receiver and extracting SEQ and ACK for sender's next SEQ and ACK
                    #if (self.was_dropped != True):
                    print ("# Received ACK| SEQ = {}| ACK = {}...".format(self.rcvd_packet.seq_num, self.rcvd_packet.ack_num))

                    # Count number of acks received for the window 
                    if (self.init_seg_sent == True): 
                        self.window_ack += 1
                    # Count ack for a particular seq num
                    try:
                        self.index = self.segment.getIndex(self.rcvd_packet.ack_num)
                        self.segment.ack_inc[self.index] += 1
                    except (TypeError):
                        pass
                        
                    # Rebase last unacknowledged number
                    if (self.rcvd_packet.ack_num > self.sendbase): 
                        # Reset all ack dups
                        for e in self.segment.ack_inc:
                            e = 0
                        self.sendbase = self.rcvd_packet.ack_num

                    ##################### Loggin Purpose ######################
                        self.logger.write_log(self.rcvd_packet, "A", "rcv")
                    else:
                        if (self.init_seg_sent == False):
                            self.logger.write_log(self.rcvd_packet, "A", "rcv")
                        else:
                            self.logger.write_log(self.rcvd_packet, "A", "rcv/DA")
                            self.num_dup_ack += 1
                    ############################################################

                    # index of the sendbase | last unacked | fast retransmission
                    # REFERENCE: idea taken from textbook
                    if (self.index != None and self.segment.ack_inc[self.index] == 3):
                        print ("Fast Retransmission")
                        self.is_frtx = True 
                        self.fast_rtx += 1
                        self.index = self.segment.getIndex(self.sendbase)
                        self.window_ack = 0
                        self.window = 0
                        self.segment.ack_inc[self.index] = 0

                    # All segments sent, send finish flag
                    if (self.index == None):
                        self.tear_down = True
                        continue

                    # Next ack number, unidirectional so no payload
                    self.next_ack_num = self.rcvd_packet.seq_num  

                    # restart window when all windows have been acked
                    print (self.window_ack, self.window, self.num_windows)
                    if (self.window_ack == self.num_windows and self.window == self.num_windows):
                        self.window_ack = 0
                        self.window = 0

                    # Start Timer
                    if (self.timer.timer_running() == False):
                        print ("Starting Timer")
                        self.timer.start_timer()

                    # send packets that are in the window
                    self.snd_wind_pckt()
                
                # waits for any packets that were dropped
                if (self.window_ack < self.num_windows):
                    self.wait = True
                    continue

            print ("****************************************\n")
            
            # Save curr tcp-segment
            (packet, address) = self.socket.recvfrom(1024)
            self.rcvd_packet = pickle.loads(packet)
            self.wait = False

            # stop timer and calculate new RTTs
            print("Timer Stopped")
            self.timer.stop_timer()
            self.timer.set_sampleRTT(self.timer.diff_time())
            self.timer.calculate_new_devRTT()
            self.timer.calculate_new_estRTT()
            self.timer.calculate_timeout_interval()

        self.logger.write_data("Size of the file (in Bytes)", self.segment.filesize())
        self.logger.write_data("Segments transmitted (including drop & RXT)", self.num_transmitted)
        self.logger.write_data("Number of Segments handled by PLD", self.num_pld_handle)
        self.logger.write_data("Number of Segments dropped", self.num_dropped)
        self.logger.write_data("Number of Segments Corrupted", self.num_corrupted)
        self.logger.write_data("Number of Segments Re-ordered", self.num_reordered)
        self.logger.write_data("Number of Segments delay", self.num_delay)
        self.logger.write_data("Number of Retransmission due to TIMEOUT", self.rtx_timeout)
        self.logger.write_data("Number of FAST RETRANSMISSION", self.fast_rtx)
        self.logger.write_data("Number of DUP ACKS received", self.num_dup_ack)


                
if __name__ == "__main__":
    sender = Sender(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6], sys.argv[7], sys.argv[8], sys.argv[9], sys.argv[10], sys.argv[11], sys.argv[12], sys.argv[13], sys.argv[14])
    sender.create_socket()
    sender.file_segmentation()
    sender.run_sendfile()
