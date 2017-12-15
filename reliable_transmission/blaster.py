#!/usr/bin/env python3

'''
    Sends data packets to blastee through the middlebox

'''
import os
import time
from queue import Queue
from switchyard.lib.userlib import *


class Blaster(object):
    def __init__(self, net, params_file):
        self.net = net
        self.parse_params(params_file)
        self.intf = self.net.interface_by_name('blaster-eth0')
        self.middlbox_eth = EthAddr('40:00:00:00:00:01')
        self.lhs, self.rhs = 1, 1
        self.retransmission_queue = Queue()
        self.num_coarse_timeouts = 0
        self.num_retrans_packets = 0
        self.total_packets_sent = 0

    def parse_params(self, params_file):
        params_map = {
            '-b': {'name': 'blastee_ip', 'type': IPv4Address},
            '-n': {'name': 'num_packets', 'type': int},
            '-l': {'name': 'length_variable_payload', 'type': int},
            '-w': {'name': 'sender_window', 'type': int},
            '-t': {'name': 'coarse_timeout', 'type': float},
            '-r': {'name': 'recv_timeout', 'type': float}
        }
        with open(params_file, 'r') as fp:
            params = fp.readline().strip().split()
            while '' in params:
                params.remove('')
            i = 0
            while i < len(params):
                if params[i] in params_map:
                    setattr(self, params_map[params[i]]['name'],
                            params_map[params[i]]['type'](params[i + 1]))
                    if params[i] in ['-t', '-r']:
                        attr = getattr(self, params_map[params[i]]['name'])
                        setattr(self, params_map[params[i]]['name'], attr / 1000)

                    if params[i] == '-n':
                        self.packet_window = [False] * (self.num_packets + 1)
                    i += 2
                    continue
                i += 1

    def construct_packet(self, seq_num):
        eth = Ethernet()
        eth.src = self.intf.ethaddr
        eth.dst = self.middlbox_eth

        ip = IPv4(protocol=IPProtocol.UDP)
        ip.src = self.intf.ipaddr
        ip.dst = self.blastee_ip

        udp = UDP()

        pkt = eth + ip + udp
        pkt += seq_num.to_bytes(4, 'big')
        pkt += self.length_variable_payload.to_bytes(2, 'big')
        pkt += os.urandom(self.length_variable_payload)
        return pkt

    def send_packet(self, seq_num):
        if seq_num == 1:
            self.first_packet_send_time = time.time()

        self.total_packets_sent += 1
        pkt = self.construct_packet(seq_num)
        self.net.send_packet(self.intf.name, pkt)

    def update_window(self):
        """
        This function checks if there is a timeout on the current LHS and
        updates the window
        :return: None
        """

        if (self.rhs - self.lhs + 1) <= self.sender_window \
                and self.rhs <= self.num_packets \
                and not self.packet_window[self.rhs]:

            log_info("Sending packet with seq_num %s" % self.rhs)
            self.send_packet(self.rhs)
            self.rhs += 1

    def deconstruct_packet(self, packet):
        contents = packet.get_header(RawPacketContents)
        seq_num = int.from_bytes(contents.data[:4], 'big')
        log_info('Received ACK for sequence number %s' % seq_num)

        self.packet_window[seq_num] = True
        if seq_num == self.lhs:
            while self.lhs < self.rhs and self.packet_window[self.lhs]:
                self.lhs += 1

            self.window_timestamp = time.time()

    def check_if_transmission_complete(self):
        return self.lhs == self.num_packets + 1

    def check_timeout(self):
        cur_time = time.time()
        if cur_time - self.window_timestamp > self.coarse_timeout:
            self.num_coarse_timeouts += 1
            # have to resend all unack'd packets in this window
            for i, packet_sent in enumerate(self.packet_window[self.lhs:self.rhs]):
                if not packet_sent:
                    self.retransmission_queue.put(self.lhs + i)

            self.window_timestamp = time.time()

    def blaster_main(self):
        # Fist time
        self.window_timestamp = time.time()
        while True:
            try:
                timestamp, dev, packet = self.net.recv_packet(
                    timeout=self.recv_timeout
                )
                self.deconstruct_packet(packet)
                if self.check_if_transmission_complete():
                    self.last_packet_ackd_time = time.time()
                    print(
                        "End of transmission. "
                        "Successfully received ACK for %d packets" %
                        self.num_packets
                    )
                    raise Shutdown(
                        "Finished reliable transmission of all packets"
                    )

            except NoPackets:
                log_debug("No packets received!")
            except Shutdown:
                log_debug("Received signal for shutdown!")
                return

            self.check_timeout()
            retransmitted_packet = False
            while not self.retransmission_queue.empty():
                seq_num = self.retransmission_queue.get()
                if not self.packet_window[seq_num]:
                    self.num_retrans_packets += 1
                    log_info("Resending packet with seq_num %s" % seq_num)
                    self.send_packet(seq_num)
                    retransmitted_packet = True
                    break

            if not retransmitted_packet:
                self.update_window()

    def stats(self):
        total_transmission_time = (self.last_packet_ackd_time -
                                   self.first_packet_send_time)

        throughput = ((self.total_packets_sent * self.length_variable_payload) /
                      total_transmission_time)

        goodput = ((self.num_packets * self.length_variable_payload) /
                   total_transmission_time)

        print("#" * 80)
        print(" " * 20 + "Total TX time(in seconds): %s" % total_transmission_time)
        print(" " * 20 + "Number of reTX: %s" % self.num_retrans_packets)
        print(" " * 20 + "Number of coarse TOs: %s" % self.num_coarse_timeouts)
        print(" " * 20 + "Throughput(Bps): %s" % throughput)
        print(" " * 20 + "Goodput(Bps): %s" % goodput)
        print("#" * 80)


def main(net):
    blaster = Blaster(net, 'blaster_params.txt')
    blaster.blaster_main()
    blaster.stats()
    net.shutdown()

