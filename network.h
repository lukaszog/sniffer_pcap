#ifndef PCAP_SNIFF_NETWORK_H
#define PCAP_SNIFF_NETWORK_H

#define ETHER_ADDR_LEN 6
#define ETHER_HDR_LEN 14

struct ether_hdr{
    unsigned char ether_dest_addr[ETHER_ADDR_LEN];
    unsigned char ether_src_addr[ETHER_ADDR_LEN];
    unsigned short ether_type;
};

struct ip_hdr{
    unsigned char ip_v_hdr_len;
    unsigned char ip_tos;
    unsigned short ip_len;
    unsigned short ip_id;
    unsigned short ip_frag_offset;
    unsigned char ip_ttl;
    unsigned char ip_type;
    unsigned short ip_checksum;
    struct in_addr ip_src_addr;
    struct in_addr ip_dest_addr;
};

struct tcp_hdr{
    unsigned short tcp_src_port;
    unsigned short tcp_dest_port;
    unsigned int tcp_seq;
    unsigned int tcp_ack;
    unsigned char reserved:4;
    unsigned char tcp_offset:4;
    unsigned char tcp_flags;
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PUSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

    unsigned short tcp_window;
    unsigned short tcp_checksum;
    unsigned short tcp_urgent;

};
#endif //PCAP_SNIFF_NETWORK_H
