#!/usr/bin/python2.7
import time
from segments import *
class Logger(object):

    ''' This class helps log scenarios of the STP '''
    def __init__(self, filename):
        # Clear up existing logging file 
        f = open(filename, "w")
        f.close()
        # filename | time program was initialised
        self.filename = filename
        self.init_time = time.time()
    
    ''' creates a log and appends line into file '''
    def write_log (self, packet, pck_type, event):
        seq_num = str(packet.seq_num)
        ack_num = str(packet.ack_num)
        nbytes = str(STP_Segment.datasize(packet.payload))
        time_relative = str(round(time.time() - self.init_time, 1))
        line = ""
        line = self.appendtext(line, event, 10)
        line = self.appendtext(line, time_relative, 20)
        line = self.appendtext(line, pck_type, 30)
        line = self.appendtext(line, seq_num, 40)
        line = self.appendtext(line, nbytes, 50)
        line = self.appendtext(line, ack_num, 60)
        line += "\n"
        f = open(self.filename, "a+")
        f.write(line)
        f.close()
    
    ''' appends text '''
    def appendtext (self, line, text, num):
        line += text
        i = len(line)
        while (i < num):
            line += " "
            i += 1
        return line
    
    def write_data(self, text, value):
        print ("WRITE DATA")
        line = ""
        line = self.appendtext(line, text, 50)
        line = self.appendtext(line, str(value), 80)
        line += "\n"
        f = open(self.filename, "a+")
        f.write(line)
        f.close()
        pass

        











