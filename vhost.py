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
import traceback
import socket


config_path = osp.join(osp.dirname(__file__), 'config.json')
config = Config(config_path)


class VHostTopo(Topo):
    def build(self, config):
        switch = self.addSwitch('s1', log_file='s1.log')
        for name, attr in config.hosts.items():
            self.addHost(name=name, ip=attr['ip'])
            # bw Mbps, 5ms delay, 0% loss, 10000 packet queue
            self.addLink(name, switch, 
                         addr1=attr['mac'], addr2=attr['sw_mac'],
                         intfName1=attr['host_iface_name'], intfName2=attr['sw_iface_name'],
                         bw=10000, delay='50us', loss=0, max_queue_size=10000)
                         
        
class VHostController(OVSController):
    def __init__(self, name, **params):
        super().__init__(name, **params)
        self.processes = []
        self.config = Config(config_path)

    def reply_if_to_ctrl_arp(self, pkt, in_iface):
        am = ARP_am()
        ctrl_config = self.config.controller
        if ARP in pkt:
            if ctrl_config['ip'] == pkt[ARP].pdst:
                mac = ctrl_config['mac']
                reply = am.make_reply(pkt)
                reply[Ether].src = mac
                reply[ARP].hwsrc = mac
                sendp(reply, iface=in_iface, verbose=False)
                print(f'\033[1;33mARP\033[0m \033[1;34m--> {in_iface}\033[0m: {list(reply)}')
                return True
        return False

    def forward_if_from_ctrl_pkt(self, pkt, in_iface):
        ctrl_config = self.config.controller
        if IP in pkt:
            print(f'\033[1;31mFrom Ctrl forward\033[0m \033[1;34m{pkt[IP].src} --> {pkt[IP].dst}\033[0m : {list(pkt)}')
        if in_iface == ctrl_config['sw_iface_name']:
            # from ctrl
            out_iface = None
            if Ether in pkt and pkt[Ether].dst in self.config.macs:
                # to virtual hosts
                out_iface = self.config.mac_to_host[pkt[Ether].dst]['sw_iface_name']
            if IP in pkt and pkt[IP].dst in self.config.ips:
                dst_host = self.config.ip_to_host[pkt[IP].dst]
                out_iface = dst_host['sw_iface_name']
                pkt[Ether].dst = dst_host['mac']                
            if out_iface:
                if IP in pkt:
                    del pkt[IP].chksum
                if TCP in pkt:
                    del pkt[TCP].chksum
                if UDP in pkt:
                    del pkt[UDP].chksum
                sendp(pkt, iface=out_iface, verbose=False)
                print(f'\033[1;31mFrom Ctrl forward\033[0m \033[1;34m{in_iface} --> {out_iface}\033[0m : {list(pkt)}')
            
    def handle_to_ctrl_pkt(self, pkt, in_iface):
        try:
            if IP in pkt:
                del pkt[IP].chksum
            if UDP in pkt:
                del pkt[UDP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            ctrl_config = self.config.controller
            out_iface = ctrl_config["sw_iface_name"]
            sendp(pkt, iface=out_iface, verbose=False)
            if UDP in pkt:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                dst_ip = pkt[IP].dst
                dst_udp_port = pkt[UDP].dport
                sock.sendto(pkt[UDP].payload.build(), (dst_ip, dst_udp_port))
                sock.close()
            print(f'\033[1;31mTo Ctrl\033[0m \033[1;34m{in_iface} --> {out_iface}\033[0m : {list(pkt)}')
        except:
            traceback.print_exc()
    
    def handle_pkt(self, pkt, in_iface):
        try:
            if IP in pkt:
                del pkt[IP].chksum
            if TCP in pkt:
                del pkt[TCP].chksum
            # if UDP in pkt:
            #     del pkt[UDP].chksum
            # if control arp
            if self.reply_if_to_ctrl_arp(pkt, in_iface):
                return
            # other messages
            if False and Ether in pkt and pkt[Ether].dst == 'ff:ff:ff:ff:ff:ff' and in_iface != self.config.controller['veth']:
                # broadcast (recognized by ether dst addr)
                for iface in self.config.sw_iface_names:
                    if iface == in_iface:
                        continue
                    sendp(pkt, iface=iface, verbose=False)
                    print(f'\033[1;35mBroadcast\033[0m ({len(pkt)=}) \033[1;34m{in_iface} --> {iface}\033[0m: {list(pkt)}')
                return
            else:
                out_iface = self.config.map_iface(in_iface)
                sendp(pkt, iface=out_iface, verbose=False)
                print(f'\033[1;32mForward \033[0m ({len(pkt)=}) \033[1;34m{in_iface} --> {out_iface}\033[0m: {list(pkt)}')
                return
        except KeyError:
            ...
        except OSError:
            traceback.print_exc()
            print(f'pkt too long: {len(pkt)=}')

    def sniff_loop(self, in_iface, handler, filter='inbound'):
        print(f'sniff on {in_iface}')
        while True:
            try:
                sniff(iface=in_iface, filter=filter, prn=handler)
            except:
                traceback.print_exc()

    def start(self):
        # sniff on sw_ifaces
        for iface in self.config.sw_iface_names:
            p = mp.Process(target=self.sniff_loop, args=(iface, lambda x: self.handle_pkt(x, iface)))
            p.start()
            self.processes.append(p)
        # sniff on veths
        for iface in self.config.veths:
            p = mp.Process(target=self.sniff_loop, args=(iface, lambda x: self.handle_pkt(x, iface)))
            p.start()
            self.processes.append(p)
        # sniff on ctrl sw_iface
        ctrl_config = self.config.controller
        ctrl_sw_iface_name = ctrl_config['sw_iface_name']
        p = mp.Process(target=self.sniff_loop, args=(ctrl_sw_iface_name, lambda x: self.forward_if_from_ctrl_pkt(x, ctrl_sw_iface_name), 'outbound'))
        p.start()
        self.processes.append(p)
        # sniff on ctrl veth
        ctrl_veth = ctrl_config['veth']
        p = mp.Process(target=self.sniff_loop, args=(ctrl_veth, lambda x: self.handle_to_ctrl_pkt(x, ctrl_veth)))
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
        new_hosts = '\n'.join(new_hosts) + '\n'
        print('=============== Origin Hosts ===============')
        print(self.origin_hosts)
        print('=============== New Hosts ===============')
        print(new_hosts)
        self.hosts[0].cmd(f'echo -n "{self.origin_hosts + new_hosts}" > /etc/hosts')

    def teardown_host_alias(self):
        self.hosts[0].cmd(f'echo -n "{self.origin_hosts}" > /etc/hosts')

    def setup_arp(self):
        for i, host_i in enumerate(self.hosts):
            for j, host_j in enumerate(self.hosts):
                host_j_config = self.config.hosts[host_j.name]
                host_i.cmd(f"arp -i {host_j_config['host_iface_name']} -s {host_j_config['ip']} {host_j_config['mac']}")
    
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
