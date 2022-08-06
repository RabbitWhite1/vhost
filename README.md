# VHost

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/RabbitWhite1/vhost/blob/master/LICENSE)

This project aims to provide virtual hosts for testing Barefoot Tofino Switches running on the Tofino Model.

## Requirements

- packages:
```shell
sudo apt-get install mininet openssh-client openssh-server openvswitch-testcontroller
sudo ln /usr/bin/ovs-testcontroller /usr/bin/controller 
pip3 install mininet
```


## VHost

Run `vhost.py` will create hosts according to `config.json`, whose format is as following:

```json
{
    "hosts": {
        "h1": {
            "ip": "10.1.0.1",
            "mac": "aa:00:00:00:00:01",
            "sw_mac": "cc:00:00:00:00:01",
            "veth": "veth1"
        },
        "h2": {
            "ip": "10.1.0.2",
            "mac": "aa:00:00:00:00:02",
            "sw_mac": "cc:00:00:00:00:02",
            "veth": "veth3"
        }
    }
}
```

Each host is a dict, whose key is the host's name. Inside the dict:
- `ip`: is the IP address of this host
- `mac`: is the MAC address of this host
- `sw_mac`: is the MAC address used in this mininet switch (for now it can be any valid MAC address)
- `veth`: is the tofino model veth, to which the host's packets will be forward

With this configuration, `vhost` will do as following. 
1. switch `s1` will be created as a central switch connecting hosts and veth.
2. host `h1` with ip and mac specified in `config.json` will be created
3. `h1` will be connected to interface on `s1` (call it `s1-eth1`, and its mac is `sw_mac` specified in `config.json`)
4. take `h1` as an example. `s1` sniffs on `veth1` and `s1-eth1`. 
    - when a packet is received from `veth1`, it will be forwarded to `s1-eth1`
    - when a packet is received from `s1-eth1`, it will be forwarded to `veth1`
    - if the `dst` of `packet[Ether]` is `ff:ff:ff:ff:ff:ff`, for now, I broadcast this packet.

```
---------------+                            +---------------------+
     Model     |                            |        vhost        |
     =====     |                            |        =====        |
               | veth0                veth1 |                     | s1-eth1         h1-eth0
       Port 0  +----------------------------+---------------------+------------------------+ h1
               |                            |                     |
               | veth2                veth3 |                     | s2-eth1         h2-eth0
       Port 1  +----------------------------+---------------------+------------------------+ h2
               |                            |                     |
               | veth4                veth5 |                     | s3-eth1         h3-eth0
       Port 2  +----------------------------+---------------------+------------------------+ h3
               |                            |                     |
            
     . . .                                          . . .

               | veth16              veth17 |                     | s8-eth1         h8-eth0
       Port 8  +----------------------------+---------------------+------------------------+ h8
               |                            |                     |
     . . .                                          . . .

               | veth250            veth251 |                     | ens33           
 Port 64 (CPU) +----------------------------+---------------------+------------------------+ controller
               |                            |                     |
---------------+                            +---------------------+
```

https://github.com/secdev/scapy/issues/896

## l2switch

Files in `l2switch` are to test the feasibility of my idea. I will later build the real virtual hosts for the target mentioned above.

r --size 2  --rank 0 --redis-host 10.0.1.1 --redis-port 6379 --prefix 377 --transport udp  send_any
r --size 2  --rank 1 --redis-host 10.0.1.1 --redis-port 6379 --prefix 377 --transport udp  send_any
