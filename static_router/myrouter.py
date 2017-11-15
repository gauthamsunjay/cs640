#!/usr/bin/env python3

'''
  Basic IPv4 router for the Computer Networks course CS640
'''

import time
from switchyard.lib.userlib import *


class Router(object):
    def __init__(self, net, static_table):
        # initialization done here
        self.net = net
        self.forwarding_table = Router.parse_forwaring_table(static_table)
        self.ips = self.get_intf_ips()
        self.arp_table = self.construct_arp_table()
        self.update_forwarding_table()
        self.arp_requests = {}
        self.packets_queue = {}

    @staticmethod
    def parse_forwaring_table(static_file):
        forwarding_table = {}
        with open(static_file, 'r') as fp:
            for line in fp.readlines():
                net, subnet, next_hop, eth_port = line.strip().split()
                forwarding_table[IPAddr(net)] = (IPAddr(subnet),
                                                 IPAddr(next_hop), eth_port)

        return forwarding_table

    @staticmethod
    def make_arp_request(senderhwaddr, senderprotoaddr, targetprotoaddr):
        ether = Ethernet()
        ether.src = senderhwaddr
        ether.dst = 'ff:ff:ff:ff:ff:ff'
        ether.ethertype = EtherType.ARP
        arp = Arp(operation=ArpOperation.Request,
                  senderhwaddr=senderhwaddr,
                  senderprotoaddr=senderprotoaddr,
                  targethwaddr='ff:ff:ff:ff:ff:ff',
                  targetprotoaddr=targetprotoaddr)

        arppacket = ether + arp
        return arppacket

    @staticmethod
    def make_icmp_reply(pkt, icmp_type=ICMPType.EchoReply,
                        icmp_code=ICMPCodeEchoReply.EchoReply):
        eth_payload = pkt.get_header(Ethernet)
        ip_payload = pkt.get_header(IPv4)
        icmp_payload = pkt.get_header(ICMP)

        eth = Ethernet()
        eth.src = eth_payload.dst

        ip = IPv4()
        ip.src, ip.dst = ip_payload.dst, ip_payload.src
        ip.ttl = 64
        # ip.ttl = ip_payload.ttl

        icmp = ICMP()
        icmp.icmptype = icmp_type
        icmp.icmpcode = icmp_code
        if icmp_type == ICMPType.EchoReply:
            echo_reply = ICMPEchoReply()
            echo_reply.sequence = icmp_payload.icmpdata.sequence
            echo_reply.identifier = icmp_payload.icmpdata.identifier
            echo_reply.data = icmp_payload.icmpdata.data
            icmp.icmpdata = echo_reply

        return eth + ip + icmp

    def update_forwarding_table(self):
        for intf in self.net.interfaces():
            net = IPv4Network(
                int(IPv4Address(intf.ipaddr)) & int(IPv4Address(intf.netmask))
            )
            self.forwarding_table[net.network_address] = (intf.netmask,
                                                          intf.ipaddr,
                                                          intf.name)

    def get_intf_ips(self):
        return [intf.ipaddr for intf in self.net.interfaces()]

    def get_intf(self, ethaddr):
        for intf in self.net.interfaces():
            if intf.ethaddr == ethaddr:
                return intf

    def construct_arp_table(self):
        return {intf.ipaddr: intf.ethaddr for intf in self.net.interfaces()}

    def make_arp_reply(self, dev, senderhwaddr, targethwaddr, senderprotoaddr,
                       targetprotoaddr):
        pkt = create_ip_arp_reply(senderhwaddr, targethwaddr, senderprotoaddr,
                                  targetprotoaddr)
        self.net.send_packet(dev, pkt)

    def find_next_hop(self, dest_ip):
        # perform look up in the forwarding table and find the interface
        # the packet has to be forwarded to
        dest_ip = IPv4Address(dest_ip)
        matches = []
        for net_addr, value in self.forwarding_table.items():
            subnet, next_hop_ip, next_hop_dev = value
            network = IPv4Network(str(net_addr) + '/' + str(subnet))
            if dest_ip in network:
                matches.append(
                    (network.prefixlen, (next_hop_ip, next_hop_dev))
                )

        matches = sorted(matches, key=lambda x: x[0], reverse=True)
        try:
            return matches[0][1]
        except IndexError:
            raise NoMatchFoundException(
                "Network not found in the forwarding table"
            )

    def forward_packet(self, dev, next_hop_ip, pkt):
        # Forwards packet if eth address is known, else makes arp request
        if next_hop_ip in self.ips:
            ip_payload = pkt.get_header(IPv4)
            next_hop_ip = ip_payload.dst

        intf = self.net.interface_by_name(dev)
        if next_hop_ip in self.arp_table:
            # Have to change the destination ethernet address
            # and the source ethernet address
            eth_payload = pkt.get_header(Ethernet)
            eth_payload.src = intf.ethaddr
            eth_payload.dst = self.arp_table[next_hop_ip]

            pkt[IPv4].ttl -= 1
            if pkt[IPv4].ttl <= 0:
                raise TTLExpiredException("TTL has expired")

            self.net.send_packet(dev, pkt)
        else:
            arprequest = Router.make_arp_request(intf.ethaddr, intf.ipaddr,
                                                 next_hop_ip)

            if next_hop_ip not in self.arp_requests:
                self.arp_requests[next_hop_ip] = [dev, arprequest,
                                                  time.time(), 0]
                self.packets_queue.setdefault(next_hop_ip, [])
                if pkt not in self.packets_queue[next_hop_ip]:
                    self.packets_queue[next_hop_ip].append(pkt)
                self.net.send_packet(dev, arprequest)

    def icmp_error_handler(self, pkt, icmp_type, icmp_code, error_message):
        log_debug(error_message)
        next_hop_ip, next_hop_dev = self.find_next_hop(pkt[IPv4].src)
        pkt = Router.make_icmp_reply(pkt, icmp_type=icmp_type,
                                     icmp_code=icmp_code)
        self.forward_packet(next_hop_dev, next_hop_ip, pkt)

    def clear_arp_requests(self):
        to_remove = []
        for ipaddr, value in self.arp_requests.items():
            dev, arprequest, time_sent, num_requests = value
            if num_requests >= 5:
                to_remove.append(ipaddr)
            else:
                cur_time = time.time()
                if cur_time - time_sent > 1.0:
                    self.net.send_packet(dev, arprequest)
                    self.arp_requests[ipaddr][-2] = cur_time
                    self.arp_requests[ipaddr][-1] += 1

        for ipaddr in to_remove:
            self.arp_requests.pop(ipaddr)
            # for all packets in the packets_queue waiting for this
            # arp response, generate an ICMP error message
            for pkt in self.packets_queue[ipaddr]:
                self.icmp_error_handler(
                    pkt, ICMPType.DestinationUnreachable,
                    ICMPCodeDestinationUnreachable.HostUnreachable,
                    "Unable to get ARP response even after 5 retries"
                )
            self.packets_queue.pop(ipaddr)

    def router_main(self):    
        '''
        Main method for router; we stay in a loop in this method, receiving
        packets until the end of time.
        '''
        while True:
            gotpkt = True

            try:
                # Clear ARP requests
                self.clear_arp_requests()

                timestamp, dev, pkt = self.net.recv_packet(timeout=1.0)
                eth_payload = pkt.get_header(Ethernet)
                if eth_payload.ethertype == EtherType.ARP:
                    arp_header = pkt.get_header(Arp)
                    if arp_header.operation == ArpOperation.Request:
                        targetprotoaddr = arp_header.targetprotoaddr
                        if targetprotoaddr in self.ips:
                            targethwaddr = self.arp_table[targetprotoaddr]
                            self.make_arp_reply(dev, targethwaddr,
                                                arp_header.senderhwaddr,
                                                targetprotoaddr,
                                                arp_header.senderprotoaddr)

                    elif arp_header.operation == ArpOperation.Reply:
                        # Handle arp replies here.
                        ipaddr = arp_header.senderprotoaddr
                        ethaddr = arp_header.senderhwaddr
                        # update ARP table
                        self.arp_table[ipaddr] = ethaddr

                        # iterate over all packets waiting for this arp resp
                        for pkt in self.packets_queue[ipaddr]:
                            next_hop_ip, next_hop_dev = self.find_next_hop(
                                pkt.get_header(IPv4).dst
                            )
                            self.forward_packet(next_hop_dev, next_hop_ip, pkt)

                        self.packets_queue.pop(ipaddr)
                        self.arp_requests.pop(ipaddr)

                elif eth_payload.ethertype == EtherType.IP:
                    ip_payload = pkt.get_header(IPv4)

                    # Have to route the pkt
                    dst_ip = ip_payload.dst
                    next_hop_ip, next_hop_dev = self.find_next_hop(dst_ip)

                    if dst_ip in self.ips:
                        if pkt.has_header(ICMP) and \
                                pkt[ICMP].icmptype == ICMPType.EchoRequest:
                            # Handle ICMP requests here
                            next_hop_ip, next_hop_dev = \
                                self.find_next_hop(ip_payload.src)
                            pkt = Router.make_icmp_reply(pkt)
                        else:
                            raise DestinationPortUnreachableException(
                                "Request sent to one of the routers interfaces "
                                "but is not an ICMP request"
                            )

                    self.forward_packet(next_hop_dev, next_hop_ip, pkt)

            except NoPackets:
                log_debug("No packets available in recv_packet")
                gotpkt = False

            except Shutdown:
                log_debug("Got shutdown signal")
                break

            except NoMatchFoundException as e:
                self.icmp_error_handler(
                    pkt, ICMPType.DestinationUnreachable,
                    ICMPCodeDestinationUnreachable.NetworkUnreachable, str(e)
                )

            except TTLExpiredException as e:
                self.icmp_error_handler(
                    pkt, ICMPType.TimeExceeded, ICMPCodeTimeExceeded.TTLExpired,
                    str(e)
                )

            except DestinationPortUnreachableException as e:
                self.icmp_error_handler(
                    pkt, ICMPType.DestinationUnreachable,
                    ICMPCodeDestinationUnreachable.PortUnreachable, str(e)
                )

            if gotpkt:
                log_debug("Got a packet: {}".format(str(pkt)))


class NoMatchFoundException(Exception):
    pass


class TTLExpiredException(Exception):
    pass


class DestinationPortUnreachableException(Exception):
    pass


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    r = Router(net, "forwarding_table.txt")
    r.router_main()
    net.shutdown()
