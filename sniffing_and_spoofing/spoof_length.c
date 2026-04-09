// q4_min.c – minimal code to answer Question 4

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <sys/socket.h>

#define PACKET_SIZE 1024

unsigned short csum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <src_ip> <dst_ip>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *src_ip = argv[1];
    const char *dst_ip = argv[2];

    int sd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    if (setsockopt(sd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("setsockopt");
        close(sd);
        exit(EXIT_FAILURE);
    }

    char buffer[PACKET_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct ip   *iph   = (struct ip *)buffer;
    struct icmp *icmph = (struct icmp *)(buffer + sizeof(struct ip));

    const char *data = "Q4 test";
    int data_len = strlen(data);

    // ICMP
    icmph->icmp_type = ICMP_ECHO;
    icmph->icmp_code = 0;
    icmph->icmp_id   = htons(1234);
    icmph->icmp_seq  = htons(1);
    memcpy(buffer + sizeof(struct ip) + sizeof(struct icmp), data, data_len);

    int ip_header_len = sizeof(struct ip);
    int icmp_len      = sizeof(struct icmp) + data_len;
    int real_len      = ip_header_len + icmp_len;

    icmph->icmp_cksum = 0;
    icmph->icmp_cksum = csum((unsigned short *)icmph, icmp_len);

    // Base IP header
    iph->ip_hl  = ip_header_len >> 2;
    iph->ip_v   = 4;
    iph->ip_tos = 0;
    iph->ip_id  = htons(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p   = IPPROTO_ICMP;
    iph->ip_src.s_addr = inet_addr(src_ip);
    iph->ip_dst.s_addr = inet_addr(dst_ip);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = iph->ip_dst.s_addr;

    // Case 1: correct length
    iph->ip_len = htons(real_len);
    iph->ip_sum = 0;
    iph->ip_sum = csum((unsigned short *)iph, ip_header_len);
    printf("Sending CORRECT packet: ip_len=%d, bytes_sent=%d\n", real_len, real_len);
    sendto(sd, buffer, real_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    sleep(1);

    // Case 2: header claims larger length than real
    int fake_big = real_len + 20;
    iph->ip_len = htons(fake_big);
    iph->ip_sum = 0;
    iph->ip_sum = csum((unsigned short *)iph, ip_header_len);
    printf("Sending FAKE packet: ip_len=%d, bytes_sent=%d\n", fake_big, real_len);
    sendto(sd, buffer, real_len, 0, (struct sockaddr *)&sin, sizeof(sin));

    close(sd);
    return 0;
}

