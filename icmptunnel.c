// Copyright (C) 2024 Aleksei Rogov <alekzzzr@gmail.com>. All rights reserved.

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <linux/if_tun.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/select.h>
#include <sys/time.h>
#include <stdarg.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <time.h>
#include <signal.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <zlib.h>

#define CLIENT              1
#define SERVER              2
#define CLIENTS_TABLE_SIZE  256
#define DIRECTION_SEND      0
#define DIRECTION_RECV      1
#define ZLIB_SIGNATURE      0xda78
#define BUFFER_SIZE         2000
#define ZBUFFER_SIZE        2000

typedef struct {
    uint8_t  type;             // ICMP Type
    uint8_t  code;             // ICMP Code
    uint16_t crc;              // RFC 1071 checksum
    uint16_t id;               // Identifier
    uint16_t seq;              // Sequence number
    uint8_t  data[];           // ICMP payload data
}icmp_echo_t;

typedef struct {
    in_addr_t client_ip;
    in_addr_t client_virt;
    uint16_t  seq;
    uint16_t  id;
    uint8_t   uses_zlib;
    time_t    last_activity;
}client_node_t;

struct counters {
    uint64_t packets_sent;
    uint64_t bytes_sent;
    uint64_t packets_recvd;
    uint64_t bytes_recvd;

    uint64_t icmp_packets_sent;
    uint64_t icmp_bytes_sent;
    uint64_t tcp_packets_sent;
    uint64_t tcp_bytes_sent;
    uint64_t udp_packets_sent;
    uint64_t udp_bytes_sent;

    uint64_t icmp_packets_recvd;
    uint64_t icmp_bytes_recvd;
    uint64_t tcp_packets_recvd;
    uint64_t tcp_bytes_recvd;
    uint64_t udp_packets_recvd;
    uint64_t udp_bytes_recvd;

    time_t time_started;
}counters;

int debug = 0;

// Print statistics by SIGUSR1 signal
void sigusr1_handler(int signum) {
    time_t now = time(NULL);
    time_t since_start = now - counters.time_started;
    struct tm tm = *localtime(&now);
    printf("ICMP tunnel is runnning since %04i-%02i-%02i %02i:%02i:%02i (%lu seconds)\n",
            tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec, since_start);
    printf("Total bytes received:   %lu\n", counters.bytes_recvd);
    printf("Total packets received: %lu\n", counters.packets_recvd);
    printf("Total bytes sent:       %lu\n", counters.bytes_sent);
    printf("Total packets sent:     %lu\n", counters.packets_sent);
    printf("ICMP bytes received:    %lu\n", counters.icmp_bytes_recvd);
    printf("ICMP packets received:  %lu\n", counters.icmp_packets_recvd);
    printf("ICMP bytes sent:        %lu\n", counters.icmp_bytes_sent);
    printf("ICMP packets sent:      %lu\n", counters.icmp_packets_sent);
    printf("TCP bytes received:     %lu\n", counters.tcp_bytes_recvd);
    printf("TCP packets received:   %lu\n", counters.tcp_packets_recvd);
    printf("TCP bytes sent:         %lu\n", counters.tcp_bytes_sent);
    printf("TCP packets sent:       %lu\n", counters.tcp_packets_sent);
    printf("UDP bytes received:     %lu\n", counters.udp_bytes_recvd);
    printf("UDP packets received:   %lu\n", counters.udp_packets_recvd);
    printf("UDP bytes sent:         %lu\n", counters.udp_bytes_sent);
    printf("UDP packets sent:       %lu\n", counters.udp_packets_sent);
}

// Toggle debug mode by SIGUSR2 signal
void sigusr2_handler(int signum) {
    ++debug;
    if(debug > 2) {
        debug = 0;
    }
    printf("Current debug level is %i\n", debug);
}

// Calculate RFC 1071 checksum
uint16_t checksum(char *data, int len, uint16_t init) {
    uint32_t sum = ~init;
    int i = 0;
    while(i < len - 1) {
        sum += *(uint16_t *)(data + i);
        i += 2;
    }
    if(len & 1) {
        sum += (uint8_t)(data[len - 1]);
    }
    while(sum > 0xffff) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum - 1;
}

// Allocate tun device
int tun_alloc(char *dev, int flags) {
    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    fd = open(clonedev, O_RDWR);
    if(fd < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = flags | IFF_NO_PI;

    if(*dev) {
        strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }

    err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if(err < 0) {
        close(fd);
        return err;
    }
    strcpy(dev, ifr.ifr_name);

    return fd;
}

// Print data as hex
void print_hex(char *data, int size) {
    char ascii[17];
    ascii[16] = '\x0';

    printf("     | 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F |      ASCII     |\n");
    printf("-----|-------------------------------------------------|----------------|");

    for(int i = 0; i != size; ++i) {
        if(!(i & 0xf)) {
            printf("\n%04X | ", (i >> 4) << 4);
        }
        printf("%02hhX ", data[i]);
        if(data[i] >= 0x20 && data[i] <= 0x7e) {
            ascii[i & 0xf] = data[i];
        }
        else {
            ascii[i & 0xf] = '.';
        }
        if((i & 0xf) == 0xf) {
            printf("|%s|", ascii);
        }
    }
    printf("\n");
}

// Update counters
void update_counters(int proto, int direction, int bytes) {
    if(direction == 0) {
        switch(proto) {
            case IPPROTO_ICMP:
                counters.icmp_bytes_sent += bytes;
                ++counters.icmp_packets_sent;
                break;
            case IPPROTO_TCP:
                counters.tcp_bytes_sent += bytes;
                ++counters.tcp_packets_sent;
                break;
            case IPPROTO_UDP:
                counters.udp_bytes_sent += bytes;
                ++counters.udp_packets_sent;
                break;
            default:
                break;
        }
        ++counters.packets_sent;
        counters.bytes_sent += bytes;
    }
    else {
        switch(proto) {
            case IPPROTO_ICMP:
                counters.icmp_bytes_recvd += bytes;
                ++counters.icmp_packets_recvd;
                break;
            case IPPROTO_TCP:
                counters.tcp_bytes_recvd += bytes;
                ++counters.tcp_packets_recvd;
                break;
            case IPPROTO_UDP:
                counters.udp_bytes_recvd += bytes;
                ++counters.udp_packets_recvd;
                break;
            default:
                break;
        }
        ++counters.packets_recvd;
        counters.bytes_recvd += bytes;
    }
}

void debud_log(int line, int type, struct iphdr *ip, int nread, char *device, in_addr_t server_client, int id, int seq) {
    if(debug == 0 || type > 3) {
        return;
    }

    char proto[5];
    switch(ip->protocol) {
        case IPPROTO_ICMP:
            strcpy(proto, "icmp");
            break;
        case IPPROTO_TCP:
            strcpy(proto, "tcp");
            break;
        case IPPROTO_UDP:
            strcpy(proto, "udp");
            break;
        default:
            break;
    }

    char src[16], dst[16], srv_cli[16];
    struct timeval te;
    struct udphdr *udp = (struct udphdr *)((void *)ip + sizeof(struct iphdr));

    strncpy(src, inet_ntoa(*(struct in_addr *)&ip->saddr), 16);
    strncpy(dst, inet_ntoa(*(struct in_addr *)&ip->daddr), 16);
    strncpy(srv_cli, inet_ntoa(*(struct in_addr *)&server_client), 16);

    gettimeofday(&te, NULL);
    struct tm tm = *localtime(&te.tv_sec);

    printf("%i: %02i:%02i:%02i.%06lu Read %i bytes from device %s; proto: %s; %s:%i -> %s:%i; ", line, tm.tm_hour, tm.tm_min, tm.tm_sec, te.tv_usec,
            nread, device, proto, src, htons(udp->source), dst, htons(udp->dest));
    switch(type) {
        case 2:
            printf("Send to %s, id: %i; seq: %i", srv_cli, id, seq);
            break;
        case 3:
            printf("Send back to %s", srv_cli);
            break;
    }
    putchar('\n');
    if(debug == 2) {
        print_hex((char *)ip, nread);
    }

}

void usage(char *progname) {
    fprintf(stderr, "Usage: %s -i <iface> [-s|-c <server ip>] -a <tun ip> [-d]\n", progname);
    fprintf(stderr, "  -i <iface>: outside interface to listen to\n");
    fprintf(stderr, "  -s: run in server mode\n");
    fprintf(stderr, "  -c <server ip>: run in client mode\n");
    fprintf(stderr, "  -a <tun ip>: assign address to the tun interface\n");
    fprintf(stderr, "  -z: compress packets with zlib\n");
    fprintf(stderr, "  -r: enable ping reply\n");
    fprintf(stderr, "  -d: show debug messages. You can increace debug level of running app by sending signal SIGUSR2\n");
    fprintf(stderr, "Statistic is available by sending SIGUSR1\n");
}

int main(int argc, char **argv) {
    char *buffer = NULL;
    char *zbuffer = NULL;
    int opt;
    int mode = 0;
    char iface[IFNAMSIZ] = "\0";
    char tundev[IFNAMSIZ] = "\0";
    char tunaddr[16] = "\0";
    in_addr_t tunaddrn;
    int zlib = 0;
    int reply = 0;

    int pid;
    char server_ipa[16];
    in_addr_t server_ipn;
    client_node_t *clients;

    int raw_sock_icmp = 0;
    int tun_fd = 0;

    uint16_t sequence = 1;
    extern char *optarg;
    while((opt = getopt(argc, argv, "i:sc:d::a:zrh")) > 0) {
        switch(opt) {
            case 's':
                if(mode == CLIENT) {
                    usage(argv[0]);
                    return 1;
                }
                mode = SERVER;
                break;
            case 'c':
                if(mode == SERVER) {
                    usage(argv[0]);
                    return 1;
                }
                mode = CLIENT;
                struct hostent *h = gethostbyname(optarg);
                if(h == NULL) {
                    fprintf(stderr, "error: invalid server address %s\n", optarg);
                    return 1;
                }
                server_ipn = *(in_addr_t*)h->h_addr_list[0];
                strncpy(server_ipa, optarg, sizeof(server_ipa));
                break;
            case 'i':
                strncpy(iface, optarg, sizeof(iface));
                break;
            case 'a':
                struct in_addr inp;
                int ret = inet_aton(optarg, &inp);
                if(ret == 0) {
                    fprintf(stderr, "error: invalid tun interface address %s\n", optarg);
                    return 1;
                }
                tunaddrn = inp.s_addr;
                strncpy(tunaddr, optarg, sizeof(tunaddr));
                break;
            case 'd':
                debug = 1;
                if(optarg) {
                    debug += optarg[0] == 'd' ? 1 : 0;
                }
                break;
            case 'z':
                printf("Use zlib compression\n");
                zlib = 1;
                break;
            case 'r':
                reply = 1;
                break;
            case 'h':
                usage(argv[0]);
                return 0;
            default:
                usage(argv[0]);
                return 1;
        }
    }
    if(mode == 0) {
        fprintf(stderr, "error: operation mode is not specified\n");
        usage(argv[0]);
        return 1;
    }
    if(iface[0] == '\0') {
        fprintf(stderr, "error: outside interface is not specified\n");
        usage(argv[0]);
        return 1;
    }
    if(tunaddr[0] == '\0') {
        fprintf(stderr, "error: tun address is not specified\n");
        usage(argv[0]);
        return 1;
    }

    counters.time_started = time(NULL);
    pid = getpid();
    signal(SIGUSR1, sigusr1_handler);
    signal(SIGUSR2, sigusr2_handler);

    printf("Starting ICMP tunnel with PID %d, in %s mode\n", pid, mode == SERVER ? "server" : "client");

    clients = malloc(sizeof(client_node_t) * CLIENTS_TABLE_SIZE);
    if(clients == NULL) {
        fprintf(stderr ,"error: could not allocate %lu bytes of memory\n", sizeof(client_node_t) * CLIENTS_TABLE_SIZE);
        return 1;
    }
    memset(clients, 0, sizeof(client_node_t) * CLIENTS_TABLE_SIZE);

    buffer = malloc(BUFFER_SIZE);
    if(buffer == NULL) {
        fprintf(stderr, "error: could not allocate %i bytes of memory\n", BUFFER_SIZE);
        goto buffer_alloc_error;
    }

    zbuffer = malloc(ZBUFFER_SIZE);
    if(zbuffer == NULL) {
        fprintf(stderr, "error: could not allocate %i bytes of memory\n", BUFFER_SIZE);
        goto zbuffer_alloc_error;
    }

    printf("Create raw icmp socket\n");
    raw_sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if(raw_sock_icmp < 0) {
        fprintf(stderr, "error: could not create raw ICMP socket\n");
        goto raw_sock_error;
    }

    printf("Bind icmp raw socket to %s\n", iface);
    if(setsockopt(raw_sock_icmp, SOL_SOCKET, SO_BINDTODEVICE, iface, strlen(iface)) < 0) {
        fprintf(stderr, "error: could not bind the socket to the device\n");
        goto raw_sock_error;
    }

    printf("Create %s TUN device\n", tundev);
    tun_fd = tun_alloc(tundev, IFF_TUN);
    if(tun_fd < 0) {
        fprintf(stderr, "error: could not allocate tun device\n");
        goto tun_fd_error;
    }

    printf("Assign address %s to %s\n", tunaddr, tundev);
    sprintf(buffer, "ip address add %s/24 dev %s", tunaddr, tundev);
    if(system(buffer)) {
        fprintf(stderr, "error: could not assign address %s to the interface %s\n", tunaddr, tundev);
        goto release_all;
    }

    printf("Set link %s up\n", tundev);
    sprintf(buffer, "ip link set dev %s up", tundev);
    if(system(buffer)) {
        fprintf(stderr, "error: could not set link %s up\n", tundev);
        goto release_all;
    }

    printf("Set MTU to 1472\n");
    sprintf(buffer, "ip l set mtu 1472 dev %s", tundev);
    if(system(buffer)) {
        fprintf(stderr, "error: could not set mtu for link %s\n", tundev);
        goto release_all;
    }

    if(mode == CLIENT) {
        printf("Add default route via %s\n", tunaddr);
        sprintf(buffer, "ip route add default via %s", tunaddr);
        if(system(buffer)) {
            fprintf(stderr, "error: could not add default route via %s\n", tunaddr);
            goto release_all;
            return 1;
        }
    }

    int ret;
    fd_set rd_set;
    int nfds = (raw_sock_icmp > tun_fd ? raw_sock_icmp : tun_fd) + 1;

    // pid_t fid = fork();
    // if(fid == 0) {
    //     printf("fork=%i, pid=%i\n", fid, getpid());
    // }

    printf("Serving connections...\n");
    while(1) {
        FD_ZERO(&rd_set);
        FD_SET(tun_fd, &rd_set);
        FD_SET(raw_sock_icmp, &rd_set);

        ret = select(nfds, &rd_set, NULL, NULL, NULL);
        if(ret > 0) {
            // Packet from the TUN interface
            if(FD_ISSET(tun_fd, &rd_set)) {
                // Read a packet into the buffer with offset for an ICMP header
                int nread = read(tun_fd, buffer + sizeof(icmp_echo_t), BUFFER_SIZE - sizeof(icmp_echo_t));

                icmp_echo_t *outer_icmp = (icmp_echo_t *)buffer;
                struct iphdr *inner_ip = (struct iphdr *)&outer_icmp->data;
                char *out_buffer = buffer;

                // If client uses zlib or server knows that client uses zlib compress packet
                if((zlib && mode == CLIENT) || (mode == SERVER && clients[inner_ip->daddr >> 24].uses_zlib)) {
                    uLongf zbuff_len = ZBUFFER_SIZE - sizeof(icmp_echo_t);
                    int zstatus = compress2((Bytef *)(zbuffer + sizeof(icmp_echo_t)), &zbuff_len, (Bytef *)inner_ip, nread, Z_BEST_COMPRESSION);
                    if(zstatus != Z_OK) {
                        struct timeval te;
                        gettimeofday(&te, NULL);
                        struct tm tm = *localtime(&te.tv_sec);
                        fprintf(stderr, "[%s] %i: %02i:%02i:%02i.%06lu could not compress packet. Error %d\n",
                                mode == SERVER ? "SERVER" : "CLIENT", __LINE__, tm.tm_hour, tm.tm_min, tm.tm_sec, te.tv_usec, zstatus);
                        continue;
                    }
                    outer_icmp = (icmp_echo_t *)zbuffer;
                    out_buffer = zbuffer;
                    nread = zbuff_len;
                }

                outer_icmp->code = 0;
                outer_icmp->crc = 0;

                // Check packet, encapsulate, send to the server
                struct sockaddr_in dst;
                dst.sin_family = AF_INET;
                dst.sin_port = 0;

                // If mode is client and packet is not multicast and inner address is tunnel interface address
                if(mode == CLIENT && (inner_ip->daddr & 0xf0) != 0xe0 && inner_ip->saddr == tunaddrn) {
                    // Encapsulate packet into ICMP and send it to the server
                    if(inner_ip->protocol == IPPROTO_UDP || inner_ip->protocol == IPPROTO_TCP || inner_ip->protocol == IPPROTO_ICMP ) {
                        // Make outer ICMP echo header
                        outer_icmp->type = ICMP_ECHO;
                        outer_icmp->id = ntohs(pid);
                        outer_icmp->seq = ntohs(sequence++);
                        outer_icmp->crc = checksum(out_buffer, nread + sizeof(icmp_echo_t), 0);

                        dst.sin_addr.s_addr = server_ipn;

                        debud_log(__LINE__, 2, inner_ip, nread, tundev, server_ipn, pid, sequence);
                    }
                }
                // Encapsulate the packet into ICMP, send back to the client
                else if(mode == SERVER) {
                    // Check if packet has a record in the clients table
                    if(clients[inner_ip->daddr >> 24].client_ip) {
                        outer_icmp->type = ICMP_ECHOREPLY;
                        outer_icmp->id = clients[inner_ip->daddr >> 24].id;
                        outer_icmp->seq = clients[inner_ip->daddr >> 24].seq;
                        outer_icmp->crc = checksum(out_buffer, nread + sizeof(icmp_echo_t), 0);

                        dst.sin_addr.s_addr = clients[inner_ip->daddr >> 24].client_ip;

                        debud_log(__LINE__, 3, inner_ip, nread, tundev, dst.sin_addr.s_addr, 0, 0);
                    }
                }
                update_counters(inner_ip->protocol, DIRECTION_SEND, nread + sizeof(icmp_echo_t));
                int ret = sendto(raw_sock_icmp, out_buffer, nread + sizeof(icmp_echo_t), 0, (const struct sockaddr *)&dst, sizeof(dst));
                if(ret < 0) {
                    perror("server sendto error\n");
                }
            }
            // ICMP packet from Internet
            if(FD_ISSET(raw_sock_icmp, &rd_set)) {
                int nread = recvfrom(raw_sock_icmp, buffer, BUFFER_SIZE, 0, NULL, NULL);

                struct iphdr *outer_ip = (struct iphdr *)buffer;

                if(outer_ip->protocol == IPPROTO_ICMP) {
                    icmp_echo_t *outer_icmp = (icmp_echo_t *)((void *)outer_ip + (outer_ip->ihl << 2));
                    struct iphdr *inner_ip = (struct iphdr *)&outer_icmp->data;
                    char *out_buff = (char *)inner_ip;
                    uint8_t uses_zlib = 0;

                    // Check if ICMP echo data field starts with zlib signature
                    if(*(uint16_t *)outer_icmp->data == ZLIB_SIGNATURE) {
                        uLongf zbuff_len = ZBUFFER_SIZE;
                        uLongf buff_len = nread - (outer_ip->ihl << 2) - sizeof(icmp_echo_t);

                        int zstatus = uncompress2((Bytef *)zbuffer, &zbuff_len, (Bytef *)&outer_icmp->data, &buff_len);
                        if(zstatus != Z_OK) {
                            struct timeval te;
                            gettimeofday(&te, NULL);
                            struct tm tm = *localtime(&te.tv_sec);
                            fprintf(stderr, "[%s] %i: %02i:%02i:%02i.%06lu could not uncompress packet. Error %d\n",
                                    mode == SERVER ? "SERVER" : "CLIENT", __LINE__, tm.tm_hour, tm.tm_min, tm.tm_sec, te.tv_usec, zstatus);
                            continue;
                        }
                        nread = zbuff_len + (outer_ip->ihl << 2) + sizeof(icmp_echo_t);
                        out_buff = zbuffer;
                        inner_ip = (struct iphdr *)zbuffer;
                        uses_zlib = 1;
                    }

                    // Receive ICMP echo request on the server side, decapsulate, send via tun interface
                    if(outer_icmp->type == ICMP_ECHO && mode == SERVER) {
                        // ICMP packet contains inner IP packet
                        if(inner_ip->version == 4 && (inner_ip->protocol == IPPROTO_ICMP || inner_ip->protocol == IPPROTO_UDP || inner_ip->protocol == IPPROTO_TCP)) {
                            // Save packet information in the table
                            clients[inner_ip->saddr >> 24].client_ip = outer_ip->saddr;
                            clients[inner_ip->saddr >> 24].seq = outer_icmp->seq;
                            clients[inner_ip->saddr >> 24].id = outer_icmp->id;
                            clients[inner_ip->saddr >> 24].client_virt = inner_ip->saddr;
                            clients[inner_ip->saddr >> 24].uses_zlib = uses_zlib;
                            clients[inner_ip->saddr >> 24].last_activity = time(NULL);

                            update_counters(inner_ip->protocol, DIRECTION_RECV, nread - (outer_ip->ihl << 2));
                            debud_log(__LINE__, 1, inner_ip, nread, "raw_sock_icmp", 0, 0, 0);

                            write(tun_fd, out_buff, nread - (outer_ip->ihl << 2) - sizeof(icmp_echo_t));
                        }
                        // Send reply to echo request
                        else if(reply == 1) {
                            struct sockaddr_in dst;
                            dst.sin_family = AF_INET;
                            dst.sin_port = 0;
                            dst.sin_addr.s_addr = outer_ip->saddr;

                            outer_icmp->type = ICMP_ECHOREPLY;
                            outer_icmp->crc = 0;
                            outer_icmp->crc = checksum((char *)outer_icmp, nread - (outer_ip->ihl << 2), 0);

                            int ret = sendto(raw_sock_icmp, (char *)outer_icmp, nread - (outer_ip->ihl << 2), 0, (const struct sockaddr *)&dst, sizeof(dst));
                            if(ret < 0) {
                                perror("server ping reply sendto error\n");
                            }
                        }
                    }

                    // Receive ICMP echo reply on the client side, decapsulate, write to tun interface
                    else if(outer_icmp->type == ICMP_ECHOREPLY && mode == CLIENT) {
                        if(inner_ip->version == 4 && (inner_ip->protocol == IPPROTO_ICMP || inner_ip->protocol == IPPROTO_UDP || inner_ip->protocol == IPPROTO_TCP)) {
                            update_counters(inner_ip->protocol, DIRECTION_RECV, nread - (outer_ip->ihl << 2));
                            debud_log(__LINE__, 1, inner_ip, nread, "raw_sock_icmp", 0, 0, 0);

                            write(tun_fd, out_buff, nread - (outer_ip->ihl << 2) - sizeof(icmp_echo_t));
                        }
                    }
                }
            }
        }
        else if(ret == -1) {
            perror("select() error\n");
            continue;
        }
        else if(ret == 0) {
            perror("select() timeout\n");
            continue;
        }
    }

    release_all:
        close(tun_fd);
    tun_fd_error:
        close(raw_sock_icmp);
    raw_sock_error:
        free(zbuffer);
    zbuffer_alloc_error:
        free(buffer);
    buffer_alloc_error:
        free(clients);

    return 1;
}
