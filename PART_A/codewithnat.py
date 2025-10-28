from mininet.net import Mininet
from mininet.node import Node
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.nodelib import NAT
from mininet.topo import Topo

class LinearFourTopo(Topo):
    def build(self):
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')

        host_params = dict(bw=100, delay='2ms')
        self.addLink(h1, s1, cls=TCLink, **host_params)
        self.addLink(h2, s2, cls=TCLink, **host_params)
        self.addLink(h3, s3, cls=TCLink, **host_params)
        self.addLink(h4, s4, cls=TCLink, **host_params)

        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')


def topo():
    return LinearFourTopo()

topos = { 'lin4': topo }


def run():
    topo = LinearFourTopo()
    net = Mininet(topo=topo, link=TCLink, controller=None)

    info('*** Adding NAT\n')
    nat = net.addNAT(name='nat', connectTo='s2')
    nat.configDefault()
    net.start()


    info('*** Network configured. Ready for testing.\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    run()

