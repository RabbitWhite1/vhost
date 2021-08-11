from logging import setLoggerClass
from mininet.topo import Topo
from mininet.node import OVSSwitch, Switch, Controller, Node, OVSController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel, info
import multiprocessing as mp
from scapy.all import *
from scapy.layers.l2 import Ether, ARP, ARP_am
from scapy.layers.inet import UDP, TCP, IP, ICMP
from utils import Config
import os.path as osp


config_path = osp.join(osp.dirname(__file__), 'config.json')
config = Config(config_path)


class VHostTopo(Topo):
    def build(self, config):
        switch = self.addSwitch('s1', log_file='s1.log')
        for name, attr in config.hosts.items():
            self.addHost(name=name, ip=attr['ip'])
            self.addLink(name, switch, 
                         addr1=attr['mac'], addr2=attr['sw_mac'],
                         intfName1=attr['host_iface_name'], intfName2=attr['sw_iface_name'])
                         
        
class VHostController(OVSController):
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.processes = []
        self.config = Config(config_path)


    def sniff_and_forward(self, in_iface):
        def handle_pkt(pkt):
            try:
                out_iface = self.config.map_iface(in_iface)
                sendp(pkt, iface=out_iface, verbose=False)
                info(f'forward a pkt from {in_iface} to {out_iface}')
            except KeyError:
                ...
        while True:
            try:
                sniff(iface=in_iface, filter='inbound', prn=lambda x: handle_pkt(x))
            except:
                import traceback
                traceback.print_exc()

    def start(self):
        # sniff on sw_ifaces
        for iface in self.config.sw_iface_names:
            p = mp.Process(target=self.sniff_and_forward, args=(iface,))
            p.start()
            self.processes.append(p)
        # sniff on veths
        for iface in self.config.veths:
            p = mp.Process(target=self.sniff_and_forward, args=(iface,))
            p.start()
            self.processes.append(p)

    def stop(self):
        for p in self.processes:
            p.terminate()


if __name__ == '__main__':
    setLogLevel('info')
    topo = VHostTopo(config=config)
    net = Mininet(topo=topo, switch=OVSSwitch, link=TCLink, controller=VHostController)
    net.start()
    CLI(net)
    net.stop()
