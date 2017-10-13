'''
   Learning swtich that maintains a forwarding table and 
   removes entries in the table after a timeout of 10 seconds
'''
import time
from switchyard.lib.userlib import *

def main(net):
    my_interfaces = net.interfaces() 
    mymacs = [intf.ethaddr for intf in my_interfaces]
    forwarding_table = dict()

    def lru_update_and_add(ethaddr, input_port, timestamp, max_entries=5):
        if len(forwarding_table.keys()) >= max_entries:
            to_remove = sorted(forwarding_table.items(), key=lambda x: x[1][1])
            forwarding_table.pop(to_remove[0][0], None)

        forwarding_table[ethaddr] = (input_port, timestamp)

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet()
        except NoPackets:
            log_debug("No packets received!")
            continue
        except Shutdown:
            log_debug("Received signal for shutdown!")
            return
        
        # update the forwarding table
        if packet[0].src not in forwarding_table:
            lru_update_and_add(packet[0].src, input_port, timestamp)
        
        # check if the destination exists in the forwarding table.
        # if it doesn't flood 
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].dst in forwarding_table:
                #update timestamp in forwarding_table
                forwarding_table[packet[0].dst] = (forwarding_table[packet[0].dst][0], time.time())
                net.send_packet(forwarding_table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

    net.shutdown()
