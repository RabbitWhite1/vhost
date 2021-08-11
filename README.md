# VHost

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/RabbitWhite1/vhost/blob/master/LICENSE)

This project aims to provide virtual hosts for testing Barefoot Tofino Switches running on the Tofino Model.

## l2switch

Files in `l2switch` are to test the feasibility of my idea. I will later build the real virtual hosts for the target mentioned above.

## VHost

Run `vhost.py` will create hosts according to config.json, whose format is as following:

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

