import os.path as osp
import json


class Config:
    def __init__(self, path=None):
        if not path:
            path = osp.join(osp.dirname(__file__), 'config.json')
        raw = json.load(open(path))
        # hosts
        self.ip_to_mac = {}
        self.mac_to_ip = {}
        self.ip_to_host = {}
        self.mac_to_host = {}
        self.sw_iface0_names = []
        self.sw_iface1_names = []
        self.hosts = raw['hosts']
        for name, attr in self.hosts.items():
            host_id = name[1:]
            ip = attr['ip']
            mac = attr['mac']
            self.ip_to_mac[ip] = mac
            self.mac_to_ip[mac] = ip
            self.ip_to_host[ip] = attr
            self.mac_to_host[mac] = attr
            # |h1 - h1-eth0|-- |s1-eth01 - switch - s1-eth11| -- |veth0 - tofino model switch|
            self.hosts[name]['iface_name'] = f'h{host_id}-eth0'
            self.hosts[name]['sw_iface0_name'] = f's1-eth0{host_id}'
            self.hosts[name]['sw_iface1_name'] = f's1-eth1{host_id}'
            self.sw_iface0_names.append(f's1-eth0{host_id}')
            self.sw_iface1_names.append(f's1-eth1{host_id}')
        # veths
        self.veths = raw['veths']
        #links
        self.links = raw['links']
    
    def get_ip(self, name: str):
        return self.hosts[name]['ip']
    
    def get_mac(self, name: str):
        return self.hosts[name]['mac']

    def get_sw_iface0_name(self, name:str):
        return self.hosts[name]['sw_iface0_name']

    def get_sw_iface1_name(self, name:str):
        return self.hosts[name]['sw_iface1_name']

    def get_sw_mac0(self, name:str):
        return self.hosts[name]['sw_mac0']

    def get_sw_mac1(self, name:str):
        return self.hosts[name]['sw_mac1']

        