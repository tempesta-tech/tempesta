#! /bin/bash
sudo iptables -A PREROUTING -t mangle -i enp1s0 -p tcp --dport 80 -j MARK --set-mark 1
