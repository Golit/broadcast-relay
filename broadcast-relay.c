#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <pcap.h>
#include <getopt.h>

#define LOG_LEVEL_ERROR 0
#define LOG_LEVEL_WARN 1
#define LOG_LEVEL_NOTICE 2
#define LOG_LEVEL_INFO 3

#define LOG_X(_level, _fd, NEW_LINE, _message, ...) if(_g_log_level >= _level) fprintf(_fd, "%s:%s:%d: " _message NEW_LINE, __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_ERROR(_message, ...) LOG_X(LOG_LEVEL_ERROR, stderr, "\n", _message, ##__VA_ARGS__)
#define LOG_WARN(_message, ...) LOG_X(LOG_LEVEL_WARN, stderr, "\n", _message, __VA_ARGS__)
#define LOG_NOTICE(_message, ...) LOG_X(LOG_LEVEL_NOTICE, stderr, "\n", _message, __VA_ARGS__)
#define LOG_INFO(_message, ...) LOG_X(LOG_LEVEL_INFO, stderr, "\n", _message, ##__VA_ARGS__)
#define LOG_INFO_NO_NL(_message, ...) LOG_X(LOG_LEVEL_INFO, stderr, "", _message, ##__VA_ARGS__)
#define LOG_INFO2(_message, ...) if(_g_log_level >= LOG_LEVEL_INFO) fprintf(stderr, _message, ##__VA_ARGS__)

#define FATAL_ERROR(_message, ...) { LOG_ERROR(_message, ##__VA_ARGS__); exit(-1); }

struct Options {
    const char *interface_in;
    const char *interface_out;
};

static int _g_log_level = LOG_LEVEL_WARN;

static u_char* packet_dup(const u_char* packet) {
    const struct ip* ip;
    ip = (struct ip*)(packet + sizeof(struct ether_header));
    uint16_t len = ntohs(ip->ip_len) + sizeof(struct ether_header);
    
    size_t lengthMin64 = (len<64?64:len);
    u_char* dup = (u_char*) malloc(lengthMin64 * sizeof(u_char));
    if(dup == NULL)
        return 0;
    memset(dup, 0, lengthMin64);
    memcpy(dup, packet, len);
    return dup;
}

static int getmacaddr(const char *interface, uint8_t *srcmac) {
    struct ifreq ifreq_c;
    memset(&ifreq_c, 0, sizeof(ifreq_c));
    strncpy(ifreq_c.ifr_name, interface, strlen(interface));//giving name of Interface
    
    int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_socket == -1)
        FATAL_ERROR("Raw socket could not be opened");
    
    if((ioctl(raw_socket, SIOCGIFHWADDR, &ifreq_c)) < 0) {//getting MAC Address
        fprintf(stderr, "error in SIOCGIFHWADDR ioctl reading\n");
        return -1;
    }
    memcpy(srcmac, (uint8_t*) ifreq_c.ifr_hwaddr.sa_data, 6 * sizeof (uint8_t));
    close(raw_socket);
    return 0;
}

static int relay_packet(const u_char* packet, u_char *args) {
    struct Options *options = (struct Options *)args;
    int raw_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(raw_socket == -1)
        FATAL_ERROR("Raw socket could not be opened");
    
    LOG_INFO("Raw socket opened");
    
    const char *interface = options->interface_out;

    struct sockaddr_ll saddr_ll;
    if ((saddr_ll.sll_ifindex = if_nametoindex (interface)) == 0) {
        perror ("if_nametoindex() failed to obtain interface index ");
        exit (EXIT_FAILURE);
    }
    LOG_INFO("Index for interface %s is %i", interface, saddr_ll.sll_ifindex);
    saddr_ll.sll_family = AF_PACKET;
    saddr_ll.sll_halen = ETH_ALEN;
    
    uint8_t srcmac[6];
    getmacaddr(interface, srcmac);
    
    LOG_INFO_NO_NL("MAC address for interface %s is ", interface);
    for (int i=0; i<6; i++) {
        if(i != 0)
            LOG_INFO2(":");
        LOG_INFO2("%02X", (uint8_t) srcmac[i]);
    }
    LOG_INFO2("\n");
    
    u_char *packet2 = packet_dup(packet);
    struct ip* ip;
    struct ether_header *etherhdr;
    etherhdr = (struct ether_header*) packet2;
    ip = (struct ip*) (packet2 + sizeof(struct ether_header));
    uint16_t len = ntohs(ip->ip_len) + sizeof(struct ether_header);
    
    memcpy(etherhdr->ether_shost, srcmac, 6);
    memset(etherhdr->ether_dhost, 0xFF, 6);     // we want to broadcast
    
    if(sendto(raw_socket, packet2, (len<60?60:len), 0, (const struct sockaddr*) &saddr_ll, sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "Error sending: %s\n", strerror(errno));
        return -1;
    }
    
    close(raw_socket);
    free(packet2);
    
    LOG_INFO("Packet relayed successfully to %s", interface);
    
    return 0;
}

static void handle_udp (u_char *args, const u_char* packet, const u_char* udp_data, int has_udp_header) {
    if(has_udp_header) {
        struct udphdr *udp = (struct udphdr*) udp_data;
        uint16_t sport = ntohs(udp->uh_sport);
        uint16_t dport = ntohs(udp->uh_dport);
        uint16_t len = ntohs(udp->uh_ulen);
        uint16_t length = (len - sizeof(struct udphdr));
        
        LOG_INFO("UDP SRC: %d DEST: %d LEN: %d DLEN: %d", sport, dport, len, length);
        
//         const u_char *payload = (udp_data + sizeof(struct udphdr));
//         LOG_INFO_NO_NL("UDP PLAYLOAD: ");
//         for(int i = 0; i < length; ++i) { // FIXME: length is wrong if IPv4 packet is fragmentet
//             LOG_INFO2("%X ", payload[i]);
//         }
//         for(int i = 0; i < length; ++i) {
//             LOG_INFO2("%c", payload[i]);
//         }
//         LOG_INFO2("\n");
//         fflush(stderr);
    }
    
    relay_packet(packet, args);
}

static u_char* handle_ip (u_char *args, const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    const struct ip* ip;
    u_int length = pkthdr->len;
    u_int hlen, off, version;
    int len;
    /* jump pass the ethernet header */
    ip = (struct ip*)(packet + sizeof(struct ether_header));
    length -= sizeof(struct ether_header);
    /* check to see we have a packet of valid length */
    if (length < sizeof(struct ip)) {
        fprintf(stderr, "truncated ip %d", length);
        return NULL;
    }
    len = ntohs(ip->ip_len);
    hlen = ip->ip_hl; /* header length */
    version = ip->ip_v; /* ip version */
    /* check version */
    if(version != 4) {
        fprintf(stderr, "Unknown version %d\n",version);
        return NULL;
    }
    /* check header length */
    if(hlen < 5 ) {
        fprintf(stderr, "bad-hlen %d \n",hlen);
    }
    /* see if we have as much packet as we should */
    if(length < len) {
        fprintf(stderr, "\ntruncated IP - %d bytes missing\n",len - length);
    }
    
    LOG_INFO_NO_NL("IP: ");
    LOG_INFO2("%s ", inet_ntoa(ip->ip_src));
    LOG_INFO2("IP DEST: %s HLEN: %d VER: %d LEN: %d\n", inet_ntoa(ip->ip_dst), hlen, version, len - (4 * hlen));

    LOG_INFO_NO_NL("IP DUMP: ");
    for(int j = 0; j < len; ++j) {
        LOG_INFO2("%X ", (packet + sizeof(struct ether_header))[j]);
        fflush(stderr);
    }
    LOG_INFO2("\n");

    if(ip->ip_p == IPPROTO_UDP) {
        const u_char* udp_data = (packet + sizeof(struct ether_header) + (4 * hlen));
        off = ntohs(ip->ip_off);
        int has_udp_header = (off & 0x1fff) == 0;
        handle_udp(args, packet, udp_data, has_udp_header);
    }
    return NULL;
} 

static u_int16_t handle_ethernet(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
    struct ether_header *eptr;
    eptr = (struct ether_header *) packet;
    u_int type = ntohs(eptr->ether_type);
    return type;
}

static void callback_ethernet_package(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    u_int16_t type = handle_ethernet(args,pkthdr,packet);
    if(type == ETHERTYPE_IP) { /* handle IP packet */
        handle_ip(args, pkthdr, packet);
    }
}

static int getopts(int argc, char* argv[], struct Options *options) {
    int c;
    
//     options->interface_in = NULL;
    options->interface_out = "tap0";

   while (1) {
        int option_index = 0;
        static struct option long_options[] = {
            {"help",           no_argument,       0, 'h'},
            {"interface-in",   required_argument, 0, 'i'},
            {"interface-out",  required_argument, 0, 'o'},
            {"log",            required_argument, 0, 'l'},
            {0,                0,                 0,  0 }
        };

       c = getopt_long(argc, argv, "i:o:l:h",
                 long_options, &option_index);
        if (c == -1)
            break;

       switch (c) {
        case 0:
            break;
       case 'h':
            printf("usage %s [-i <interface with broadcasts>] [-o <interface where to relay broadcasts>] [-h] [-l <loglevel>]\n", argv[0]);
            exit(0);
            break;
       case 'i':
            options->interface_in = optarg;
            break;
       case 'o':
            options->interface_out = optarg;
            break;
       case 'l':
            _g_log_level = atoi(optarg);
            break;
       case '?':
            break;
       default:
            printf("?? getopt returned character code 0%o ??\n", c);
        }
    }

   if (optind < argc) {
        printf("unrecognized option: ");
        printf("%s ", argv[optind]);
        printf("\n");
        exit(1);
    }
    
    return 0;
}

int main(int argc, char* argv[]) {
    struct Options options;
    memset(&options, 0, sizeof(struct Options));
    if(getopts(argc, argv, &options) != 0)
        return 1;
    
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    struct bpf_program fp; /* hold compiled program */ 
    bpf_u_int32 mask; /* subnet mask */
    bpf_u_int32 net; /* ip */ 
    
    if(options.interface_in == NULL) {
        options.interface_in = pcap_lookupdev(errbuf);
        if(options.interface_in == NULL) {
            FATAL_ERROR("Iinterface not specified and cannot get default interface: %s\n", errbuf);
        }
    }
    const char *interface = options.interface_in;
    
    LOG_INFO("Interface: %s", interface);
    
    /* open device for reading */
//     handle = pcap_open_live(interface, BUFSIZ, 1, -1, errbuf);
    handle = pcap_open_live(interface, BUFSIZ, 0, -1, errbuf);
    if(handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
        exit(1);
    }
    
    /* ask pcap for the network address and mask of the device */
    if(pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
        LOG_NOTICE("Can't get netmask for device %s\n", interface);
        net = 0;
        mask = 0;
    }
    
    char filter_program_template[] = "udp and ip multicast and dst host 255.255.255.255 and not ether src %s";
//     char filter_program_template[] = "not ether src %s";
    
    char macstr[18];
    uint8_t srcmac[6];
    if(getmacaddr(options.interface_out, srcmac) < 0)
        FATAL_ERROR("Cannot get mac address of interface %s", options.interface_out);
    snprintf(macstr, sizeof(macstr), "%02x:%02x:%02x:%02x:%02x:%02x", srcmac[0], srcmac[1], srcmac[2], srcmac[3], srcmac[4], srcmac[5]);
    LOG_INFO("Mac address: %s", macstr);
    
    char filter_program[sizeof(filter_program_template) + sizeof(macstr)];
    snprintf(filter_program, sizeof(filter_program), filter_program_template, macstr);
    LOG_INFO("using pcap filter program: %s", filter_program);
    
    if(pcap_compile(handle, &fp, filter_program, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter: %s\n", pcap_geterr(handle));
        exit(1);
    }
    
    if(pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter: %s\n", pcap_geterr(handle));
        exit(1);
    } 
    
    pcap_loop(handle, -1, callback_ethernet_package, (u_char *) &options);
    
    pcap_close(handle);
    
    return 0;
}
