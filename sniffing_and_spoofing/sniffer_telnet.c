#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>


void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    const struct ether_header *eth;
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;
    const u_char *payload;
    u_int ip_hdr_len;
    u_int tcp_hdr_len;
    u_int payload_len;

    eth = (struct ether_header*) packet;
    ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    ip_hdr_len = ip_hdr->ip_hl * 4;

    tcp_hdr = (struct tcphdr*)((u_char*)ip_hdr + ip_hdr_len);
    tcp_hdr_len = tcp_hdr->th_off * 4;

    payload = (u_char*)tcp_hdr + tcp_hdr_len;
    payload_len = header->len - (sizeof(struct ether_header) + ip_hdr_len + tcp_hdr_len);

    printf("Telnet packet %s:%d -> %s:%d\n",
           inet_ntoa(ip_hdr->ip_src), ntohs(tcp_hdr->th_sport),
           inet_ntoa(ip_hdr->ip_dst), ntohs(tcp_hdr->th_dport));

    if (payload_len > 0) {
        printf("Data (%u bytes): ", payload_len);
        for (u_int i = 0; i < payload_len; i++) {
            unsigned char c = payload[i];
            if (c >= 32 && c <= 126)   // printable ASCII
                putchar(c);
            else
                putchar('.');
        }
        printf("\n\n");
    }
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp and port 23";
  bpf_u_int32 net;

  // Step 1: Open live pcap session on NIC with name br-493cf1c43792
  handle = pcap_open_live("br-493cf1c43792", BUFSIZ, 1, 1000, errbuf);

  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, net);
  if (pcap_setfilter(handle, &fp) !=0) {
      pcap_perror(handle, "Error:");
      exit(EXIT_FAILURE);
  }
  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}
