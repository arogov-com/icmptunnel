# Copyright (C) 2024 Aleksei Rogov <alekzzzr@gmail.com>. All rights reserved.

#!/bin/sh

CLIENT_NS=client
SERVER_NS=server
GATEWAY_NS=gateway

ip netns add ${CLIENT_NS}
ip netns add ${GATEWAY_NS}
ip netns add ${SERVER_NS}

ip netns exec ${CLIENT_NS} ip link set lo up
ip netns exec ${GATEWAY_NS} ip link set lo up
ip netns exec ${SERVER_NS} ip link set lo up

ip link add veth1 type veth peer name veth1-gw
ip link set veth1 netns ${CLIENT_NS}
ip link set veth1-gw netns ${GATEWAY_NS}

ip link add veth1 type veth peer name veth1-srv
ip link set veth1 netns ${GATEWAY_NS}
ip link set veth1-srv netns ${SERVER_NS}

ip netns exec ${CLIENT_NS} ip link set veth1 up
ip netns exec ${GATEWAY_NS} ip link set veth1-gw up
ip netns exec ${GATEWAY_NS} ip link set veth1 up
ip netns exec ${SERVER_NS} ip link set veth1-srv up

ip netns exec ${CLIENT_NS} ip a a 10.0.1.2/24 dev veth1
ip netns exec ${GATEWAY_NS} ip a a 10.0.1.1/24 dev veth1-gw
ip netns exec ${GATEWAY_NS} ip a a 10.0.2.1/24 dev veth1
ip netns exec ${SERVER_NS} ip a a 10.0.2.2/24 dev veth1-srv

ip netns exec ${GATEWAY_NS} sysctl net.ipv4.ip_forward=1
ip netns exec ${GATEWAY_NS} sysctl net.ipv4.icmp_echo_ignore_all=1
ip netns exec ${GATEWAY_NS} iptables -t nat -A POSTROUTING -s 10.20.30.0/24 -o veth1 -j MASQUERADE

ip netns exec ${CLIENT_NS} ./icmptunnel -c 10.0.1.1 -a 10.20.30.2 -i veth1&
CLIENT_TUNNEL=$!

ip netns exec ${GATEWAY_NS} ./icmptunnel -s -a 10.20.30.1 -i veth1-gw&
SERVER_TUNNEL=$!

ip netns exec ${SERVER_NS} iperf3 -s&
SERVER_IPERF=$!

sleep 3

ip netns exec ${CLIENT_NS} iperf3 -c 10.0.2.2

kill ${CLIENT_TUNNEL}
kill ${SERVER_TUNNEL}
kill ${SERVER_IPERF}

ip netns delete ${SERVER_NS}
ip netns delete ${GATEWAY_NS}
ip netns delete ${CLIENT_NS}
