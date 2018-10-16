#!/usr/bin/python2.7

import sys
class STP_Segment(object):

    ''' This class helps sender.py by maintain and creating segments of file.
        List of sequence number is also maintain, corresponding to each segment in the list.
    '''
    def __init__(self, mss=0, mws=0):
        self.mss = int(mss)
        self.segments = []
        self.seq = []
        self.ack_inc = []

    ''' Function reads file in bytes, then appends each segment into a list '''
    def segmentation(self, filename):
        fd = open(str(filename), "rb")
        print("segmenting file {} ...".format(filename))
        segment = fd.read(self.mss)

        while (len(segment) > 0):
            self.segments.append(segment)
            segment = fd.read(self.mss)
        fd.close()

    ''' Gets the index with a certain sequence number '''
    def getIndex(self, seqnum):
        i = 0
        while (i < len(self.seq)):
            if (self.seq[i] == seqnum):
                return i
            i += 1
        return None

    ''' receive a sequence number and initialise sequence number corresponding to its segment
        seqnum = seqnum(before) + payload
    '''
    def setup (self, seq_num):
        seq = seq_num
        i = 0
        while (i < len(self.segments)):
            self.seq.append(seq_num)
            self.ack_inc.append(0)
            seq_num += self.datasize(self.segments[i])
            i += 1

    def filesize (self):
        return self.seq[-1] + len(self.segments[-1]) - 1
    
    '''Writes all the list (in order... index 0...n-1) into a file'''
    def writefile (self, filename):
        fd = open(filename, "wb+")
        for seg in self.segments:
            fd.write(seg)
        fd.close()
    
    ''' gets the size of a segment ''' 
    @staticmethod
    def datasize(seg):
        try:
            return len(seg)
        except TypeError:
            return 0
        

