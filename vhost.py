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

    def reply_if_ctrl_arp(self, pkt, in_iface):
        am = ARP_am()
        ctrl_config = self.config.controller
        if ARP in pkt:
            if ctrl_config['ip'] == pkt[ARP].pdst:
                mac = ctrl_config['mac']
                reply = am.make_reply(pkt)
                reply[Ether].src = mac
                reply[ARP].hwsrc = mac
                sendp(reply, iface=in_iface, verbose=False)
                print(f'--> {in_iface}: {reply.summary()}')
                return True
        return False

    def reply_if_ctrl_msg(self, pkt, in_iface):
        ctrl_config = self.config.controller
        if IP in pkt and UDP in pkt:
            print(f"{ctrl_config['ip']} == {pkt[IP].dst} and {ctrl_config['port']} == {pkt[UDP].dport}: {ctrl_config['ip'] == pkt[IP].dst and ctrl_config['port'] == pkt[UDP].dport}")
            if ctrl_config['ip'] == pkt[IP].dst and ctrl_config['port'] == pkt[UDP].dport:
                out_iface = ctrl_config["sw_iface_name"]
                sendp(pkt, iface=in_iface, verbose=False)
                print(f'{in_iface} --> {out_iface}: {pkt.summary()}')
                return True
        return False
    
    def handle_pkt(self, pkt, in_iface):
        try:
            if IP in pkt:
                del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            if UDP in pkt:
                del pkt[UDP].chksum
            if Ether in pkt and pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff':
                # if control arp
                if self.reply_if_ctrl_arp(pkt, in_iface):
                    return
                # broadcast (recognized by ether dst addr)
                for iface in self.config.sw_iface_names:
                    if iface == in_iface:
                        continue
                    sendp(pkt, iface=iface, verbose=False)
                    print(f'{in_iface} --> {iface}: {pkt.summary()}')
            else:
                # if control message
                if self.reply_if_ctrl_msg(pkt, in_iface):
                    return
                out_iface = self.config.map_iface(in_iface)
                sendp(pkt, iface=out_iface, verbose=False)
                print(f'{in_iface} --> {out_iface}: {pkt.summary()}')
        except KeyError:
            ...

    def sniff_and_forward(self, in_iface):
        while True:
            try:
                sniff(iface=in_iface, filter='inbound', prn=lambda x: self.handle_pkt(x, in_iface))
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
        new_hosts.append(f'192.168.195.140 ctrl')
        new_hosts = '\n'.join(new_hosts)
        print('=============== Origin Hosts ===============')
        print(self.origin_hosts)
        print('=============== New Hosts ===============')
        print(new_hosts)
        for host in self.hosts:
            host.cmd(f'echo "{self.origin_hosts + new_hosts}" > /etc/hosts')
            break


    def teardown_host_alias(self):
        for host in self.hosts:
            host.cmd(f'echo "{self.origin_hosts}" > /etc/hosts')
            break

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

    def setup_controller(self):
        host = self.getNodeByName(self.config.controller_name)
        host.cmd("/home/hank/tools/veth_setup.sh")

    def teardown_controller(self):
        host = self.getNodeByName(self.config.controller_name)
        host.cmd("/home/hank/tools/veth_teardown.sh")

    def setup_route(self):
        for host in self.hosts:
            host_config = self.config.hosts[host.name]
            # host.cmd(f"ip route add default via {host_config['ip']} dev {host_config['host_iface_name']}")
            host.cmd(f"ip route add 192.168.195.0/24 via {host_config['ip']}")

    def teardown_route(self):
        ...

    def start(self):
        super().start()
        self.setup_host_alias()
        self.setup_arp()
        self.setup_ssh()
        # self.setup_controller()
        self.setup_route()

    def stop(self):
        self.teardown_route()
        # self.teardown_controller()
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
