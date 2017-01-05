#include <stdio.h>
#include <pcap/pcap.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "network.h"

void pcap_error(const char *, const char *);
void decode_eth(const char *);
void decode_ip(const char *);
int decode_tcp(const char *);

void caught_packet(char *, const struct pcap_pkthdr *, const char *);

int main() {

    struct pcap_pkthdr header;
    const char *packet;
    char errorbuffer[PCAP_ERRBUF_SIZE];
    char *device;
    pcap_t *pcap_handle;
    int i;

    device = pcap_lookupdev(errorbuffer);

    if(device == NULL)
    {
        pcap_error("pcap_lookupdev", errorbuffer);
    }

    printf("Nasluchuje z urzadzenia %s\n", device);

    pcap_handle = pcap_open_live(device, 4096, 1, 0, errorbuffer);

    pcap_loop(pcap_handle, 100, caught_packet, NULL);

    pcap_close(pcap_handle);



    return 0;
}

void caught_packet(char *args, const struct pcap_pkthdr *cap_header, const char *packet)
{
    int tcp_header_len, total_header_size, pkt_data_len;
    char *pkt_data;

    printf("Pakiet %d bajtowy \n", cap_header->len);

    decode_eth(packet);
    decode_ip(packet+ETHER_HDR_LEN);
    tcp_header_len = decode_tcp(packet+ETHER_HDR_LEN+sizeof(struct ip_hdr));

    total_header_size = ETHER_HDR_LEN+sizeof(struct ip_hdr)+tcp_header_len;
    pkt_data = (char *)packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;

    if(pkt_data_len > 0)
    {
        printf("\t\t %u bajtow  w pakiecie\n", pkt_data_len);
        printpacket(pkt_data, pkt_data_len);
    }else{
        printf("\t\tBrak danych \n");
    }
}

void pcap_error(const char *err, const char *errorbuffor)
{
    printf("Blad %s: %s\n", err, errorbuffor);
    exit(1);
}

void decode_eth(const char *header_start) {
    int i;
    const struct ether_hdr *ethernet_header;

    ethernet_header = (const struct ether_hdr *)header_start;
    printf("==  Layer 2 ::  Ethernet ==\n");
    printf("= Źródło: %02x", ethernet_header->ether_src_addr[0]);
    for(i=1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", ethernet_header->ether_src_addr[i]);

    printf("\tCel: %02x", ethernet_header->ether_dest_addr[0]);
    for(i=1; i < ETHER_ADDR_LEN; i++)
        printf(":%02x", ethernet_header->ether_dest_addr[i]);
    printf("\tTyp: %hu =\n", ethernet_header->ether_type);
}

void decode_ip(const char *header_start) {
    const struct ip_hdr *ip_header;

    ip_header = (const struct ip_hdr *)header_start;
    printf("\t==  Layer 3 ::: Header IP ==\n");
    printf("\t= Source: %s\t", inet_ntoa(ip_header->ip_src_addr));
    printf("Dest: %s =\n", inet_ntoa(ip_header->ip_dest_addr));
    printf("\t= Type: %u\t", (u_int) ip_header->ip_type);
    printf("ID: %hu\tLen: %hu =\n", ntohs(ip_header->ip_id), ntohs(ip_header->ip_len));
}

int decode_tcp(const char *header_start)
{
    int header_size;
    const struct tcp_hdr *tcp_header;

    tcp_header = (const struct tcp_hdr *)header_start;
    header_size = 4 * tcp_header->tcp_offset;

    printf("\t\t==  Layer 4 :::: TCP Header  ==\n");
    printf("\t\t= Src port: %hu\t", ntohs(tcp_header->tcp_src_port));
    printf("Port docelowy: %hu =\n", ntohs(tcp_header->tcp_dest_port));
    printf("\t\t= Seq #: %u\t", ntohl(tcp_header->tcp_seq));
    printf("Ack #: %u }\n", ntohl(tcp_header->tcp_ack));
    printf("\t\t= Header size: %u\tmakreks: ", header_size);
    if(tcp_header->tcp_flags & TCP_FIN)
        printf("FIN ");
    if(tcp_header->tcp_flags & TCP_SYN)
        printf("SYN ");
    if(tcp_header->tcp_flags & TCP_RST)
        printf("RST ");
    if(tcp_header->tcp_flags & TCP_PUSH)
        printf("PUSH ");
    if(tcp_header->tcp_flags & TCP_ACK)
        printf("ACK ");
    if(tcp_header->tcp_flags & TCP_URG)
        printf("URG ");
    printf(" =\n");

    return header_size;

}

void printpacket(const unsigned char *data, const unsigned int length)
{
    unsigned char byte;
    unsigned int i=0, j=0;

    for(i; i<length; i++)
    {

        printf("%02x ", data[i]);

        if(((i%16)==15) || (i==length-1))
        {
            for(j=0; j<15-(i%16); j++)
            {
                printf("   ");
            }
            printf("| ");

            for(j=(i-(i%16)); j <= i; j++)
            {
                byte = data[j];
                if((byte > 31) && (byte < 127)) {
                    printf("%c", byte);
                }
                else {
                    printf(".");
                }
            }
            printf("\n");
        }
    }
}


