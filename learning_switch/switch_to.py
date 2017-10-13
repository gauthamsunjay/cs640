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

    def update_forwarding_table(cur_timestamp, timeout=10):
        to_remove = []
        for key, val in forwarding_table.items():
            port, timestamp = val
            if cur_timestamp - timestamp > timeout:
                to_remove.append(key)

        for key in to_remove:
            forwarding_table.pop(key, None)

    while True:
        try:
            timestamp,input_port,packet = net.recv_packet(timeout=10)
        except NoPackets:
            log_debug("No packets received!")
            update_forwarding_table(time.time())
            continue
        except Shutdown:
            log_debug("Received signal for shutdown!")
            return
        
        #update the forwarding table
        if packet[0].src not in forwarding_table:
            forwarding_table[packet[0].src] = (input_port, timestamp)
        
        # check if the destination exists in the forwarding table.
        # if it doesn't flood 
        log_debug ("In {} received packet {} on {}".format(net.name, packet, input_port))
        if packet[0].dst in mymacs:
            log_debug ("Packet intended for me")
        else:
            if packet[0].dst in forwarding_table:
                net.send_packet(forwarding_table[packet[0].dst][0], packet)
            else:
                for intf in my_interfaces:
                    if input_port != intf.name:
                        log_debug ("Flooding packet {} to {}".format(packet, intf.name))
                        net.send_packet(intf.name, packet)

        #update the forwarding table with the current timestamp.
        update_forwarding_table(timestamp)
    net.shutdown()
