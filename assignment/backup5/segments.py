#!/usr/bin/python2.7

import sys
class STP_Segment(object):

    def __init__(self, mss=0, mws=0):
        self.mss = int(mss)
        self.segments = []
        self.seq = []
        self.ack_inc = []
        self.baseindex = 0

    def segmentation(self, filename):
        fd = open(str(filename), "rb")
        print("segmenting file {} ...".format(filename))
        segment = fd.read(self.mss)

        while (len(segment) > 0):
            self.segments.append(segment)
            segment = fd.read(self.mss)
        fd.close()

    def getIndex(self, seqnum):
        i = 0
        while (i < len(self.seq)):
            if (self.seq[i] == seqnum):
                return i
            i += 1
        return None

    def setup (self, seq_num):
        seq = seq_num
        i = 0
        while (i < len(self.segments)):
            self.seq.append(seq_num)
            self.ack_inc.append(0)
            seq_num += self.datasize(self.segments[i])
            i += 1

    def maxSize (self):
        return len(self.segments)
    
    def writefile (self, filename):
        # make sure file is empty 
#        fd = open(filename, "wb")
#        fd.close()
        # write file 
        fd = open(filename, "wb+")
        for seg in self.segments:
            fd.write(seg)
        fd.close()

    @staticmethod
    def datasize(seg):
        try:
            return len(seg)
        except TypeError:
            return 0
        

