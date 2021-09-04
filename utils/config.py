import os.path as osp
import json

from mininet.node import Controller


class Config:
    def __init__(self, path=None):
        if not path:
            path = osp.join(osp.dirname(__file__), 'config.json')
        raw = json.load(open(path))
        # hosts
        self.ips = []
        self.macs = []
        self.ip_to_mac = {}
        self.mac_to_ip = {}
        self.ip_to_host = {}
        self.mac_to_host = {}
        self.sw_iface_names = []
        self.veth_to_sw_iface = {}
        self.sw_iface_to_veth = {}
        self.hosts = raw['hosts']
        self.veths = []
        for name, attr in self.hosts.items():
            host_id = name[1:]
            ip = attr['ip']
            mac = attr['mac']
            self.ips.append(ip)
            self.macs.append(mac)
            self.ip_to_mac[ip] = mac
            self.mac_to_ip[mac] = ip
            self.ip_to_host[ip] = attr
            self.mac_to_host[mac] = attr
            # |h1 - h1-eth0|-- |s1-eth01 - switch - veth0 - tofino model switch|
            host_iface_name = f'{name}-eth0'
            sw_iface_name = f's1-eth-{name}'
            self.hosts[name]['host_iface_name'] = host_iface_name
            self.hosts[name]['sw_iface_name'] = sw_iface_name
            self.sw_iface_names.append(sw_iface_name)
            veth = attr['veth']
            self.veth_to_sw_iface[veth] = sw_iface_name
            self.veths.append(veth)
            self.sw_iface_to_veth[sw_iface_name] = veth
        # controller
        self.controller_name = raw['controller']['name']
        self.controller = raw['controller']
        self.controller['port'] = int(self.controller['port'])
        veth = self.controller['veth']
        self.veths.append(veth)
        self.veth_to_sw_iface[veth] = self.controller['sw_iface_name']
        # veth = self.controller['veth']
        # host_iface_name = self.controller['host_iface_name']
        # sw_iface_name = self.controller['sw_iface_name']
        # self.controller['sw_iface_name'] = sw_iface_name
        # self.veth_to_sw_iface[veth] = sw_iface_name
        # self.sw_iface_to_veth[sw_iface_name] = veth
        # self.veths.append(veth)
        # # I disable sniffing pkt sent from controller for now.
        # self.sw_iface_names.append(sw_iface_name)

    def get_controller(self):
        return self.hosts[self.controller_name]

    def map_iface(self, iface: str) -> str:
        if iface[0] == 'v':
            return self.veth_to_sw_iface[iface]
        elif iface[0] == 's':
            return self.sw_iface_to_veth[iface]
    
    def get_ip(self, name: str):
        return self.hosts[name]['ip']
    
    def get_mac(self, name: str):
        return self.hosts[name]['mac']

    def get_sw_iface_name(self, name:str):
        return self.hosts[name]['sw_iface_name']

    def get_sw_mac(self, name:str):
        return self.hosts[name]['sw_mac']

        