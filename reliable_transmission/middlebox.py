#!/usr/bin/env python3

from random import random
from switchyard.lib.userlib import *


class MiddleBox(object):
    def __init__(self, net, params_file):
        self.net = net
        self.parse_params(params_file)
        self.arp_table = {
            IPv4Address('192.168.100.1'): EthAddr('10:00:00:00:00:01'),
            IPv4Address('192.168.200.1'): EthAddr('20:00:00:00:00:01')
        }
        self.num_packets_dropped = 0

    def parse_params(self, params_file):
        params_map = {'-d': {'name': 'drop_rate', 'type': float}}
        with open(params_file, 'r') as fp:
            params = fp.readline().strip().split()
            while '' in params:
                params.remove('')
            i = 0
            while i < len(params):
                if params[i] in params_map:
                    setattr(self, params_map[params[i]]['name'],
                            params_map[params[i]]['type'](params[i + 1]))
                    i += 2
                    continue
                i += 1

    def should_forward(self, packet):
        acceptable_headers = [IPv4, Ethernet, UDP, RawPacketContents]
        for header in acceptable_headers:
            if packet.get_header(header) is None:
                return False

        return True

    def forward_packet(self, dev, packet):
        if not self.should_forward(packet):
            log_warn(
                "Received some other random packet. Not forwarding it: %s"
                % packet
            )
            return

        intf = self.net.interface_by_name(dev)
        ip_payload = packet.get_header(IPv4)
        eth_payload = packet.get_header(Ethernet)
        try:
            eth_dst = self.arp_table[ip_payload.dst]
            eth_payload.src = intf.ethaddr
            eth_payload.dst = eth_dst

            log_info("Forwarding packet to %s" % ip_payload.dst)
            self.net.send_packet(dev, packet)
        except KeyError:
            log_debug('Packet not received from blaster or blastee?')

    def middlebox_main(self):
        while True:
            try:
                timestamp, dev, packet = self.net.recv_packet()

                if dev == 'middlebox-eth0':
                    # Received from blaster,
                    # Generate a random number. If it is greater than drop_rate
                    # forward it else do nothing
                    if random() > self.drop_rate:
                        self.forward_packet('middlebox-eth1', packet)
                    else:
                        self.num_packets_dropped += 1
                        log_info("Dropping packet %s for fun." % packet)
                        log_info("Current num packets dropped %s" %
                                 self.num_packets_dropped)
                elif dev == 'middlebox-eth1':
                    # Received from blastee. These are ACK packets and they are
                    # just forwarded
                    self.forward_packet('middlebox-eth0', packet)
                else:
                    log_debug("This is not possible. "
                              "Middlebox has only two interfaces")

            except NoPackets:
                log_debug("No packets available in recv_packet")

            except Shutdown:
                log_debug("Got shutdown signal")
                break


def main(net):
    middlebox = MiddleBox(net, params_file="middlebox_params.txt")
    middlebox.middlebox_main()
    net.shutdown()

