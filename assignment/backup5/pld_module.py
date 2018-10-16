#!/usr/bin/python2.7
import random

class PLD(object):

    def __init__(self, pDrop, pDuplicate, pCorrupt, pOrder, maxOrder, pDelay, maxDelay, seed):
       self.pDrop = float(pDrop)
       self.pDuplcate = float(pDuplicate)
       self.pCorrupt = float(pCorrupt)
       self.pOrder = float(pOrder)
       self.maxOrder = float(maxOrder)
       self.pDelay = float(pDelay)
       self.maxDelay = float(maxDelay)
       random.seed(seed)

    # determines whether packet gets dropped
    def isDrop (self):
        rand = random.random()
        return rand < self.pDrop
    
    # determines whether packet gets duplicated
    def isDuplicate(self):
        rand = random.random()
        return rand < self.pDuplcate

    # determines whether packet is corrupted
    def isCorrupt(self):
        rand = random.random()
        return rand < self.pCorrupt

    # determine whether packet gets stored for re-orderring purposes
    def isOrder(self):
        rand = random.random()
        return rand < self.pOrder

    # determines whether packets get delayed and returns delay time
    def delay_time(self):
        rand = random.random()
        if (rand < self.pDelay):
            return random.randrange(1, self.maxDelay)
        return 0
