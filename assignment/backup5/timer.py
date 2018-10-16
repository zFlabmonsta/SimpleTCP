#!/usr/bin/python2.7

import sys
import time
import math

class Timer(object):

    def __init__(self, gamma):
        self.gamma = int(gamma)
        self.timeout_interval = 1000
        self.est_RTT = 500 #milliseconds
        self.dev_RTT = 250 #milliseconds
        self.sample_RTT = None
        self.start = 0
        self.end = 0
        self.running = False

    def calculate_timeout_interval(self):
        self.timeout_interval = self.est_RTT + self.gamma * self.dev_RTT
        print ("New Interval Time: {}".format(self.timeout_interval))
        return self.timeout_interval

    def double_timeout_interval(self):
        self.timeout_interval = self.timeout_interval * 2
        print ("New Interval Time: {}".format(self.timeout_interval))

    def start_timer(self):
        self.running = True
        self.start = int(round(time.time()*1000))
        
    def stop_timer(self):
        self.running = False
        self.end = int(round(time.time()*1000))

    def diff_time(self):
        return self.end - self.start

    def curr_time_diff(self):
        return int(round(time.time()*1000)) - self.start

    def calculate_new_estRTT (self):
        self.est_RTT = (1 - 0.125) * self.est_RTT + 0.125 * self.sample_RTT

    def calculate_new_devRTT (self):
        self.dev_RTT = (1 - 0.25) * self.dev_RTT + 0.25 * math.fabs(self.sample_RTT - self.est_RTT)

    def set_sampleRTT(self, sampleRTT):
        self.sample_RTT = sampleRTT

    def reset_timer(self):
        self.start = 0
        self.end = 0

    def timer_running(self):
        return self.running

# Test Timer
#timer = Timer(2)
#timer.start_timer()
#timer.stop_timer()
#print (timer.diff_time())
