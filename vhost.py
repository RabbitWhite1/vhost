from logging import setLoggerClass
from mininet.topo import Topo
from mininet.node import OVSSwitch, Switch, Controller, Node, OVSController
from mininet.link import TCLink, OVSLink
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
                if IP in pkt:
                    del pkt[IP].chksum
                if TCP in pkt:
                    del pkt[TCP].chksum
                if UDP in pkt:
                    del pkt[UDP].chksum
                if Ether in pkt and pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff':
                    # broadcast (recognized by ether dst addr)
                    for iface in self.config.sw_iface_names:
                        sendp(pkt, iface=iface, verbose=False)
                else:
                    out_iface = self.config.map_iface(in_iface)
                    sendp(pkt, iface=out_iface, verbose=False)
                    print(f'{in_iface} --> {out_iface}: {pkt.summary()}')
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


class VHostNet(Mininet):
    def __init__(self, config, topo, switch=OVSSwitch, link=OVSLink, controller=VHostController, **kwargs):
        super(VHostNet, self).__init__(topo=topo, switch=switch, link=link, controller=controller, **kwargs)
        self.config=config

    def setup_host_alias(self):
        self.origin_hosts = open('/etc/hosts').read()
        new_hosts = []
        for host in self.hosts: 
            new_hosts.append(f'{host.IP()} {host.name}')
        new_hosts = '\n'.join(new_hosts)
        print('=============== Origin Hosts ===============')
        print(self.origin_hosts)
        print('=============== New Hosts ===============')
        print(new_hosts)
        for host in self.hosts:
            host.cmd(f'echo "{self.origin_hosts + new_hosts}" > /etc/hosts')


    def teardown_host_alias(self):
        for host in self.hosts:
            host.cmd(f'echo "{self.origin_hosts}" > /etc/hosts')

    def setup_arp(self):
        ...
    
    def teardown_arp(self):
        ...

    def setup_ssh(self):
        for host in self.hosts:
            host.cmd('mkdir -p /run/sshd')
            host.cmd('/usr/sbin/sshd')

    def teardown_ssh(self):
        for host in self.hosts:
            host.cmd('pkill sshd')

    def start(self):
        super().start()
        self.setup_host_alias()
        self.setup_arp()
        self.setup_ssh()

    def stop(self):
        self.teardown_ssh()
        self.teardown_arp()
        self.teardown_host_alias()
        super().stop()


def main():
    setLogLevel('info')
    topo = VHostTopo(config=config)
    net = VHostNet(config=config, topo=topo, switch=OVSSwitch, link=TCLink, controller=VHostController)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()