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


def int_to_mac(addr: int):
    addr = hex(addr)[2:]
    assert len(addr) <= 12
    addr = '0' * (12 - len(addr)) + addr
    assert int(addr[1], base=16) % 2 == 0
    addr = ':'.join([addr[i:i+2] for i in range(0, 12, 2)])
    return addr

def mac_to_bytes(addr: str):
    addr = int(''.join(addr.split(':'), base=16))
    return int.to_bytes(addr, length=6, byteorder='big')


def int_to_ipv4(addr: int):
    addr = hex(addr)[2:]
    assert len(addr) <= 8
    addr = '0' * (8 - len(addr)) + addr
    assert int(addr[1], base=16) % 2 == 0
    addr = [int(addr[i:i+2], base=16) for i in range(0, 8, 2)]
    for i in addr:
        assert 0 <= i < 256
    addr = '.'.join([str(i) for i in addr])
    return addr



class VHostTopo(Topo):
    def build(self, config):
        switch = self.addSwitch('s1', log_file='s1.log')
        for name, attr in config.hosts.items():
            self.addHost(name=name, ip=attr['ip'])
            self.addLink(name, switch, 
                         addr1=attr['mac'], addr2=attr['sw_mac0'],
                         intfName1=attr['iface_name'], intfName2=attr['sw_iface0_name'])
        


class VHostController(OVSController):
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.processes = []
        self.config = Config(config_path)

    def sniff_and_forward(self, in_iface):
        # whenever receive a package, we check whether it is an `arp`,
        # if it is, then reply with an `arp` reply
        # otherwise, we can directly send this packet to  model switch
        am = ARP_am()
        def handle_pkt(pkt):
            if ARP in pkt:
                # info('接受时')
                # pkt.show2()
                pdst = pkt[ARP].pdst
                mac = self.config.ip_to_mac[pdst]
                reply = am.make_reply(pkt)
                reply[Ether].src = mac
                reply[ARP].hwsrc = mac
                # info(f'修改后经由 {in_iface} 发出\n')
                # reply.show2()
                sendp(reply, iface=in_iface, verbose=False)
            else:
                # for now, this is a normal forward logic
                try:
                    ether = pkt[Ether]
                    # if ether.dst == "aa:00:00:00:00:01":
                    #     sendp(pkt, iface='s1-eth01', verbose=False)
                    # else:
                    #     sendp(pkt, iface='s1-eth02', verbose=False)
                    if ether.dst == 'ff:ff:ff:ff:ff:ff':
                        assert IP in pkt
                        dst_host = self.config.ip_to_host[pkt[IP].dst]
                        pkt[Ether].dst = dst_host.mac
                        iface = self.config.ip_to_host[pkt[IP].dst]['sw_iface0_name']
                    else:
                        iface = self.config.mac_to_host[pkt[Ether].dst]['sw_iface0_name']
                    sendp(pkt, iface=iface, verbose=False)
                except KeyError:
                    ...
        while True:
            try:
                sniff(iface=in_iface, filter='inbound', prn=lambda x: handle_pkt(x))
            except:
                import traceback
                traceback.print_exc()

    def start(self):
        for name, attr in self.config.hosts.items():
            p = mp.Process(target=self.sniff_and_forward, args=(attr['sw_iface0_name'],))
            p.start()
            self.processes.append(p)
        self.cmd('arp -s 10.1.0.1 aa:00:00:00:00:01')
        self.cmd('arp -s 10.1.0.2 aa:00:00:00:00:02')
        ...
        # super().start()

    def stop(self):
        for p in self.processes:
            p.join()


if __name__ == '__main__':
    setLogLevel('info')
    topo = VHostTopo(config=config)
    net = Mininet(topo=topo, switch=OVSSwitch, link=TCLink, controller=VHostController)
    net.start()
    CLI(net)
    net.stop()
