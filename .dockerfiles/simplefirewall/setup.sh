#!/bin/sh

# eth0 is the public network interface
# eth1 is the local network interface 

echo "Setting up your amazing firewall..."

echo 1 > /proc/sys/net/ipv4/ip_forward
# forward requests

iptables -F OUTPUT

# Allow outcoming ICMP traffic
iptables \
    --append OUTPUT \
    --proto icmp \
    --jump ACCEPT
    
# Accept incoming ICMP traffic
iptables \
    --append INPUT \
    --proto icmp \
    --jump ACCEPT 

iptables \
    --append INPUT \
    --proto tcp \
    -i eth0 \
    --jump DROP

exec "$@"