#!/usr/bin/python

"""

"""

import inspect
import os
import atexit
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.topo import Topo
from mininet.link import TCLink
from mininet.topo import SingleSwitchTopo
from mininet.node import RemoteController


net = None

class FVTopo(Topo):
    host = {}
    switch = {}

    def __init__(self):
        # Initialize topology
        Topo.__init__(self)
        for i in range(1, 5):
            # Create Host
            name = "h%d" % i
            ip = "10.0.0.%d" % i
            config = {'ip': ip}
            self.host[name] = self.addHost(name, **config)
            # Create Switch
            name = "s%d" % i
            dpid = "%d" % i
            config = {'dpid': dpid}
            self.switch[name] = self.addSwitch(name, **config)

        localConfig = {'bw': 1000}
        # Site A
        self.addLink(self.host['h1'], self.switch['s1'], port2 = 3, **localConfig)
        self.addLink(self.host['h2'], self.switch['s1'], port2 = 4, **localConfig)
        # SiteB
        self.addLink(self.host['h3'], self.switch['s4'], port2 = 3, **localConfig)
        self.addLink(self.host['h4'], self.switch['s4'], port2 = 4, **localConfig)
        # Middle
        videoConfig = {'bw': 10}
        nonVideoConfig = {'bw': 1}
        self.addLink(self.switch['s1'], self.switch['s2'], port1 = 1, port2 = 1, **nonVideoConfig)
        self.addLink(self.switch['s1'], self.switch['s3'], port1 = 2, port2 = 1, **videoConfig)
        self.addLink(self.switch['s2'], self.switch['s4'], port1 = 2, port2 = 1, **nonVideoConfig)
        self.addLink(self.switch['s3'], self.switch['s4'], port1 = 2, port2 = 2, **videoConfig)

        info( '\n*** printing and validating the ports running on each interface\n' )

def startNetwork():
    info('** Creating Overlay network topology\n')
    topo = FVTopo()
    global net
    net = Mininet(topo=topo, link = TCLink,
                  controller=lambda name: RemoteController(name, ip='192.168.56.102'),
                  listenPort=6633, autoSetMacs=True)

    info('** Starting the network\n')
    net.start()


    info('** Running CLI\n')
    CLI(net)


def stopNetwork():
    if net is not None:
        info('** Tearing down Overlay network\n')
        net.stop()

def main():
    # Force cleanup on exit by registering a cleanup function
    atexit.register(stopNetwork)

    # Tell mininet to print useful information
    setLogLevel('info')
    startNetwork()

if __name__ == '__main__':
    main()
