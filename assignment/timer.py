#!/usr/bin/python2.7

import sys
import time
import math

class Timer(object):
    ''' This Class is used to help calculate DevRTT, EstRTT, sampleRTT
        and timeout interval by stop and starting timer
    '''
    def __init__(self, gamma):
        self.gamma = int(gamma)
        self.timeout_interval = 1000
        self.est_RTT = 500 #milliseconds
        self.dev_RTT = 250 #milliseconds
        self.sample_RTT = None
        self.start = 0
        self.end = 0
        self.running = False

    ''' Caluclates timeout interval
        REFERENCE: Formula taken out of the textbook
    '''
    def calculate_timeout_interval(self):
        self.timeout_interval = self.est_RTT + self.gamma * self.dev_RTT
        print ("New Interval Time: {}".format(self.timeout_interval))
        return self.timeout_interval

    ''' doubles the timeout interval '''
    def double_timeout_interval(self):
        self.timeout_interval = self.timeout_interval * 2
        print ("New Interval Time: {}".format(self.timeout_interval))

    ''' starts the timer '''
    def start_timer(self):
        self.running = True
        self.start = int(round(time.time()*1000))
       
    ''' stops the timer '''
    def stop_timer(self):
        self.running = False
        self.end = int(round(time.time()*1000))

    ''' gets the time difference of end and start '''
    def diff_time(self):
        return self.end - self.start

    ''' gets the time different between current time and start '''
    def curr_time_diff(self):
        return int(round(time.time()*1000)) - self.start

    ''' calculates ned estRTT '''
    def calculate_new_estRTT (self):
        self.est_RTT = (1 - 0.125) * self.est_RTT + 0.125 * self.sample_RTT

    ''' calculates new devRTT '''
    def calculate_new_devRTT (self):
        self.dev_RTT = (1 - 0.25) * self.dev_RTT + 0.25 * math.fabs(self.sample_RTT - self.est_RTT)

    ''' set new sampleRTT '''
    def set_sampleRTT(self, sampleRTT):
        self.sample_RTT = sampleRTT

    ''' reset timer '''
    def reset_timer(self):
        self.start = 0
        self.end = 0

    ''' determine whether timer is running or not '''
    def timer_running(self):
        return self.running

# Test Timer
#timer = Timer(2)
#timer.start_timer()
#timer.stop_timer()
#print (timer.diff_time())
