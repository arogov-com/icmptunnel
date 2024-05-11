# icmptunnel
IPv4 over ICMP echo

### Build
make

### Arguments
<code>-s - run as server
-c <server ip> - run as client
-i - outside interface
-a <tun ip> - assign address to tunnel interface
-z - compress packets with zlib
-r - enable ping reply
-d - enable debug prints. May be specified twice for full packet printing</code>

### Handled signals
SIGUSR1 - Print statistic to stdout

SIGUSR2 - Enable/increase debug level of running application

### Run server
Ignore replys for ICMP requests:

`sudo echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all`

Add MASQUERADE rule to firewall. iface - output interface, network - tunnel network:

`sudo iptables -t nat -A POSTROUTING -s <network> -o <iface> -j MASQUERADE`

Enable IP forwarding in kernel

`sudo echo 1 > /proc/sys/net/ipv4/ip_forward`

Run server

`sudo ./icmptunnel -s -i eth0 -a 10.20.30.1`

### Run client
`sudo ./icmptunnel -c <server ip> -i eth0 -a 10.20.30.2`

### Local test
The script will create 3 namespaces (client, gateway, server) and transfer traffic between the client's and server's namespaces

`make test`
