#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>    // struct ip
#include <arpa/inet.h>     // inet_ntoa

void got_packet(u_char *args, const struct pcap_pkthdr *header,
                const u_char *packet)
{
    const struct ip *ip_hdr;
    const int ethernet_header_length = 14;  // assuming Ethernet
    // Point to the start of the IP header (after Ethernet header)
    ip_hdr = (struct ip *)(packet + ethernet_header_length);
    // Convert and print source and destination IP addresses
    printf("Src IP: %-15s ", inet_ntoa(ip_hdr->ip_src));
    printf("Dst IP: %-15s\n", inet_ntoa(ip_hdr->ip_dst));
}

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "icmp and host 10.9.0.5 and host 10.9.0.6";
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
