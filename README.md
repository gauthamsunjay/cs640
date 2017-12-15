# CS640

This repository contains programming assignments for the course Introduction to Computer Networks
taken during the Fall of 2017 at the University of Wisconsin-Madison.

# Learning Switch - Programming Assignment 1

Building a learning switch using the switchyard framework with the following packet retention policies:

1. Timeout
1. LRU
1. Least Traffic First

# Static Router - Programming Assignment 2

Building a static router using the switchyard framework with the following functionalities:

1. Respond to ARP (address resolution protocol) requests for addresses that are assigned to interfaces on the router. 
2. Make ARP requests for IP addresses that have no known Ethernet MAC address.
3. Receive and forward packets that arrive on links and are destined to other hosts.
4. Respond to ICMP messages like echo requests ("pings").
5. Generate ICMP error messages when necessary, such as when an IP packet's TTL (time to live) value has been decremented to zero.

# Reliable Transmission - Programming Assignment 3

Building a simulation of reliable transmission using three components.

1. Blaster
1. Blastee
1. Middlebox

The blaster sends packets to blastee via the middlebox which can randomly drop packets. The blastee ACK's the packets sent by the blaster.
The ACK packets are not dropped.
