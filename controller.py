'''
Please add your name: Duong Thanh Dat
Please add your matric number: A0119656W
'''

from pox.core import core
from collections import defaultdict

import pox.openflow.libopenflow_01 as of
import pox.openflow.discovery
import pox.openflow.spanning_tree

from pox.lib.revent import *
from pox.lib.util import dpid_to_str
from pox.lib.util import dpidToStr
from pox.lib.addresses import IPAddr, EthAddr
from collections import namedtuple
import os

log = core.getLogger()


class VideoSlice (EventMixin):
    blockedList = []

    def __init__(self):
        self.listenTo(core.openflow)
        core.openflow_discovery.addListeners(self)
        policies = open("firewall-policies.csv").readlines()
        header = True
        for policy in policies:
            if header:
                header = False
                continue
            policy = policy.rstrip('\r\n').split(',')
            src, dst = policy[1], policy[2]
            self.blockedList.append((EthAddr(src), EthAddr(dst)))
            self.blockedList.append((EthAddr(dst), EthAddr(src)))

    def _handle_PacketIn (self, event):
        """
        Handle packet in messages from the switch to implement above algorithm.
        """
        packet = event.parsed
        tcp = event.parsed.find('tcp')

        def install(outport):
            msg = of.ofp_flow_mod() #install a flow table entry
            msg.idle_timeout = 10
            msg.hard_timeout = 30
            msg.match = of.ofp_match.from_packet(packet, event.port)
            msg.actions.append(of.ofp_action_output(port = outport))
            msg.priority = 1
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        def ban(src, dst):
            msg = of.ofp_flow_mod()
            msg.match = of.ofp_match(dl_src = src, dl_dst = dst)
            msg.priority = 2
            event.connection.send(msg)

        def isVideo():
            if tcp is not None:
                return tcp.srcport == 80 or tcp.dstport == 80
            return False

        def nearSwitch(hostA, hostB):
            if packet.dst == EthAddr(hostA):
                install(3)
            elif packet.dst == EthAddr(hostB):
                install(4)
            else:
                if isVideo():
                    install(2)
                else:
                    install(1)

        def farSwitch():
            if packet.dst == EthAddr("00:00:00:00:00:01") or packet.dst == EthAddr("00:00:00:00:00:02"):
                install(1)
            elif packet.dst == EthAddr("00:00:00:00:00:03") or packet.dst == EthAddr("00:00:00:00:00:04"):
                install(2)

        def forward(message = None):
            if packet.dst.is_multicast:
                flood()
                return
            else:
                if (packet.src, packet.dst) in self.blockedList:
                    ban(packet.src, packet.dst)
                    return
                if event.dpid == 2 or event.dpid == 3:
                    farSwitch()
                elif event.dpid == 1:
                    nearSwitch("00:00:00:00:00:01", "00:00:00:00:00:02")
                elif event.dpid == 4:
                    nearSwitch("00:00:00:00:00:03", "00:00:00:00:00:04")
                log.debug("Got unicast packet for %s at %s (input port %d):", packet.dst, dpid_to_str(event.dpid), event.port)

        # flood, but don't install the rule
        def flood (message = None):
            """ Floods the packet """
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            event.connection.send(msg)

        forward()


    def _handle_ConnectionUp(self, event):
        log.debug("Switch %s has come up.", dpidToStr(event.dpid))

def launch():
    # Run spanning tree so that we can deal with topologies with loops
    pox.openflow.discovery.launch()
    pox.openflow.spanning_tree.launch()

    '''
    Starting the Video Slicing module
    '''
    core.registerNew(VideoSlice)