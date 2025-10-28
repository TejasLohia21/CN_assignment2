from mininet.topo import Topo
from mininet.link import TCLink

class LinearFourTopo(Topo):
    def build(self):
        # defining  Switches
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')
        s3 = self.addSwitch('s3')
        s4 = self.addSwitch('s4')

        # Adding  Hosts with fixed IPs
        h1 = self.addHost('h1', ip='10.0.0.1/24')
        h2 = self.addHost('h2', ip='10.0.0.2/24')
        h3 = self.addHost('h3', ip='10.0.0.3/24')
        h4 = self.addHost('h4', ip='10.0.0.4/24')
        dns = self.addHost('dns', ip='10.0.0.5/24')  # This will eventualy be the  DNS Resolver

        # Adding links between hosts and switches
        host_params = dict(bw=100, delay='2ms')
        self.addLink(h1, s1, cls=TCLink, **host_params)
        self.addLink(h2, s2, cls=TCLink, **host_params)
        self.addLink(h3, s3, cls=TCLink, **host_params)
        self.addLink(h4, s4, cls=TCLink, **host_params)

        # DNS to s2: BW 100 Mbps, delay 1 ms
        self.addLink(dns, s2, cls=TCLink, bw=100, delay='1ms')

        # Switch-to-switch links as specified
        self.addLink(s1, s2, cls=TCLink, bw=100, delay='5ms')
        self.addLink(s2, s3, cls=TCLink, bw=100, delay='8ms')
        self.addLink(s3, s4, cls=TCLink, bw=100, delay='10ms')

def topo():
    return LinearFourTopo()

topos = { 'lin4': topo }

