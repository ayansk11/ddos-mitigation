#!/usr/bin/env python3


from mininet.net import Mininet
from mininet.node import Node
from mininet.cli import CLI
from mininet.log import setLogLevel

class FRRRouter(Node):
    def config(self, **params):
        super().config(**params)
        # Enable forwarding
        self.cmd("sysctl -w net.ipv4.ip_forward=1")
        # Start FRR (path may differ by distro)
        self.cmd("/usr/lib/frr/frrinit.sh start || service frr start")

    def terminate(self):
        self.cmd("/usr/lib/frr/frrinit.sh stop || service frr stop")
        super().terminate()

def run():
    net = Mininet()

    r1 = net.addHost('r1', cls=FRRRouter, ip='10.0.1.1/24')
    r2 = net.addHost('r2', cls=FRRRouter, ip='10.0.2.1/24')

    hA = net.addHost('hA', ip='10.0.1.10/24', defaultRoute='via 10.0.1.1')
    hV = net.addHost('hV', ip='10.0.2.10/24', defaultRoute='via 10.0.2.1')

    net.addLink(hA, r1)     # hA-eth0 <-> r1-eth0 (10.0.1.0/24)
    net.addLink(r1, r2)     # r1-eth1 <-> r2-eth1 (10.0.12.0/24)
    net.addLink(r2, hV)     # r2-eth0 <-> hV-eth0 (10.0.2.0/24)

    net.start()

    r1.cmd("ip addr add 10.0.12.1/24 dev r1-eth1")
    r2.cmd("ip addr add 10.0.12.2/24 dev r2-eth1")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()
