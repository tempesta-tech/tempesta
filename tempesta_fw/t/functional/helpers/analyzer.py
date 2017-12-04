"""
Instruments for network traffic analysis
"""
from __future__ import print_function
import os
from threading import Thread
from scapy.all import *
from . import remote, tf_cfg, error

__author__ = 'Tempesta Technologies, Inc.'
__copyright__ = 'Copyright (C) 2017 Tempesta Technologies, Inc.'
__license__ = 'GPL2'


FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


class Sniffer(object):

    def __init__(self, node, host, count=0,
                 timeout=30, port=80,
                 node_close=True):
        self.node = node
        self.port = port
        self.thread = None
        self.captured = 0
        self.packets = []
        self.dump_file = '/tmp/tmp_packet_dump'
        cmd = 'timeout %s tcpdump -i any %s -w - tcp port %s || true'
        count_flag = ('-c %s' % count) if count else ''
        self.cmd = cmd % (timeout, count_flag, port)
        self.err_msg = ' '.join(["Can't %s sniffer on", host])
        self.node_side_close = node_close

    def sniff(self):
        '''Thread function for starting system sniffer and saving
        its output. We need to use temporary file here, because
        scapy.sniff(offline=file_obj) interface does not support
        neither StringIO objects nor paramiko file objects.
        '''
        stdout, stderr = self.node.run_cmd(self.cmd, timeout=None,
                                           err_msg=(self.err_msg % 'start'))
        match = re.search(r'(\d+) packets captured', stderr)
        if match:
            self.captured = int(match.group(1))
        with open(self.dump_file, 'w') as f:
            f.write(stdout)

    def start(self):
        self.thread = Thread(target=self.sniff)
        self.thread.start()

    def stop(self):
        if self.thread:
            self.thread.join()
            if os.path.exists(self.dump_file):
                self.packets = sniff(count=self.captured,
                                     offline=self.dump_file)
                os.remove(self.dump_file)
            else:
                error.bug('Dump file "%s" does not exist!' % self.dump_file)

    def check_results(self):
        """Analyzing captured packets. Should be called after start-stop cycle.
        Should be redefined in sublasses.
        """
        return True

class AnalyzerCloseRegular(Sniffer):

    def portcmp(self, packet, invert=False):
        if self.node_side_close and invert:
            return packet[TCP].dport == self.port
        elif self.node_side_close and not invert:
            return packet[TCP].sport == self.port
        elif not self.node_side_close and invert:
            return packet[TCP].sport == self.port
        else:
            return packet[TCP].dport == self.port

    def check_results(self):
        """Four-way (FIN-ACK-FIN-ACK) and
        three-way (FIN-ACK/FIN-ACK) handshake order checking.
        """
        if not self.packets:
            return False

        dbg_dump(5, self.packets, 'AnalyzerCloseRegular: FIN sequence:')

        count_seq = 0
        l_seq = 0
        for p in self.packets:
            if p[TCP].flags & RST:
                return False
            if count_seq >= 4:
                return False
            if count_seq == 0 and p[TCP].flags & FIN and self.portcmp(p):
                l_seq = p[TCP].seq + p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
                count_seq += 1
                continue
            if count_seq == 1 and p[TCP].flags & ACK and self.portcmp(p, invert=True):
                if p[TCP].ack > l_seq:
                    count_seq += 1
            if count_seq == 2 and p[TCP].flags & FIN and self.portcmp(p, invert=True):
                l_seq = p[TCP].seq + p[IP].len - p[IP].ihl * 4 - p[TCP].dataofs * 4
                count_seq += 1
                continue
            if count_seq == 3 and p[TCP].flags & ACK and self.portcmp(p):
                if  p[TCP].ack > l_seq:
                    count_seq += 1

        if count_seq != 4:
            return False

        return True

def dbg_dump(level, packets, msg):
    if tf_cfg.v_level() >= level:
        print(msg, file=sys.stderr)
        for p in packets:
            print(p.show(), file=sys.stderr)

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
