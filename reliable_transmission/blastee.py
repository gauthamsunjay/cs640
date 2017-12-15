#!/usr/bin/env python3

from base64 import b64encode
from switchyard.lib.userlib import *


class Blastee(object):
    def __init__(self, net, params_file):
        self.net = net
        self.parse_params(params_file)
        self.intf = self.net.interface_by_name('blastee-eth0')
        self.middlebox_eth = EthAddr('40:00:00:00:00:02')

    def parse_params(self, params_file):
        params_map = {
            '-b': {'name': 'blaster_ip', 'type': IPv4Address},
            '-n': {'name': 'num_packets', 'type': int}
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
                    i += 2
                    continue
                i += 1

    def construct_packet(self, seq_num):
        eth = Ethernet()
        eth.src = self.intf.ethaddr
        eth.dst = self.middlebox_eth

        ip = IPv4(protocol=IPProtocol.UDP)
        ip.src = self.intf.ipaddr
        ip.dst = self.blaster_ip

        udp = UDP()

        pkt = eth + ip + udp
        pkt += seq_num.to_bytes(4, 'big')

        return pkt

    def ack(self, packet):
        contents = packet.get_header(RawPacketContents)
        seq_num = int.from_bytes(contents.data[:4], 'big')
        variable_data = b64encode(contents.data[6:]).decode('utf-8')
        log_info("Obtained data for seq_num = %s and data = %s" %
                 (seq_num, variable_data))

        self.net.send_packet(self.intf.name, self.construct_packet(seq_num))

    def blastee_main(self):
        while True:
            try:
                timestamp, dev, packet = self.net.recv_packet()
                self.ack(packet)
            except NoPackets:
                log_debug("No packets received!")
                continue
            except Shutdown:
                log_debug("Received signal for shutdown!")
                return


def main(net):
    blastee = Blastee(net, 'blastee_params.txt')
    blastee.blastee_main()
    net.shutdown()
