#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <string.h>
#include <math.h>

#include <sys/socket.h>
#include <arpa/inet.h> // for inet_ntoa()
#include <net/ethernet.h>
#include <netinet/ip_icmp.h>   //Provides declarations for icmp header
#include <netinet/udp.h>   //Provides declarations for udp header
#include <netinet/tcp.h>   //Provides declarations for tcp header
#include <netinet/ip.h>    //Provides declarations for ip header

#define ETHER_TYPE_IP (0x0800)

void print_hex(const unsigned char *p, int len);
void process_packet_kerb(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);
void process_packet_count(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);


int ICMP_COUNT = 0;
int IGMP_COUNT = 0;
int TCP_COUNT = 0;
int UDP_COUNT = 0;
int OTHER_COUNT = 0;
int TOTAL_COUNT = 0;


int ETHER_IP_OFFSET = 14;
int IP_V4 = 4;
int IP_HDR_LEN = 20;
int UDP_HDR_LEN = 8;
int KRB_PORT = 88;
int RECORD_MARK_LEN = 4;

int KRB_PKT_CNT = 0;


typedef struct tlvdata {
    int type;
    int constructed;
    int class; // universal, application, context-specific, private
    int tl_len; // len of just the tl bytes
    int tot_len; // length plus the bytes for type and length 
} tlvdata;


int main(int argc, char **argv)
{
    int i, dont_process, myptr, pkt_num, tcp_hdr_len, num, jump_len;
    struct pcap_pkthdr header;
    const u_char *packet = NULL;
    pcap_t *FH = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    char SRC[16];
    char DST[16];
    int ether_type = 0;
    int ether_offset = 0;    
    unsigned int proto_version = 0;
    u_char *pkt_ptr = NULL;
    struct ip *ip_hdr = NULL;
    int packet_length = 0;
    int ip_header_len = 0;
    int proto = 0; 
    int src_port = 0;
    int dst_port = 0;
    struct tlvdata tlv;

    if(argc < 2)
    {
        fprintf(stderr, "Usage: %s [tracefile]\n",argv[0]);
        exit(1);
    }

    FH = pcap_open_offline(argv[1], errbuf);

    if(FH == NULL)
    {
        fprintf(stderr,"Couldn't open file %s: %s\n",argv[1],errbuf);
        exit(1);
    }

    pkt_num = 0;
    pcap_loop(FH , -1 , process_packet_count , NULL);

    fprintf(stdout,"\n");
    return 0;
}

int get_tlv_length(u_char *pyld_strt, int str_ptr, struct tlvdata *tlv)
{
    tlv->type = 0;
    tlv->constructed = 0;
    tlv->class = 0;
    tlv->tl_len = 0;
    tlv->tot_len = 0;
    
    //printf("[get_tlv_length()] start: validity offset (str_ptr): %x, first 6 bytes at that offset: %x %x %x %x %x %x\n",str_ptr,pyld_strt[str_ptr],pyld_strt[str_ptr+1],pyld_strt[str_ptr+2],pyld_strt[str_ptr+3],pyld_strt[str_ptr+4],pyld_strt[str_ptr+5]);
    int type, len, tlv_len, ptr, i, temp;
    len = tlv_len = ptr = i = temp =  0;
    /* TODO: make get_tlv_type it's own function */
        type = pyld_strt[str_ptr + ptr];
    tlv->constructed = type & 32 / 32; // 5th bit
    tlv->class = type & 192 / 64; // 6th and 7th bit
    if((type << 3) / 8 == 31) // get only right 5 bits to see if there are more octets
    {
        //printf("[get_tlv_length()] (type << 3) / 8 == 31, more type octets. type: %x\n",type);
        len++; /* first type byte */
        while(pyld_strt[str_ptr + ptr] >> 7) /* get the most sig bit */
        {
            /* TODO: validate type construction code */
            len++;
            ptr++;
                        type += pyld_strt[str_ptr + ptr] - 128; /* get 7 LSBs*/
        }
        tlv->type = type;
    }
    else
    {
        /* one byte type */
        len++;
        ptr++;
        tlv->type = type & 31; //5 LSBs
        //printf("[get_tlv_length()] 5 bits of type != 31. type: %x, type & 31: %x\n",type,tlv->type);
    }
    tlv_len = pyld_strt[str_ptr + ptr];
    //printf("[get_tlv_length()] tlv_len raw: %x\n",tlv_len);
    if((tlv_len & 128) >> 7) /* MSB = 1*/
    {
        //printf("[get_tlv_length()] tlv_len & 128 >> 7 (MSB = 1): %x\n",tlv_len / 128); 
        /* handle definite long case */
        /* sanity check that we're not indefinite (0) or reserved (127) */
        if((tlv_len == 128) || (tlv_len == 255))
        {
            printf("[get_tlv_length()] tl_len sanity check failed. tlv_len: %x\n",tlv_len);
            return 0;
        }
        tlv_len = tlv_len - 128; //remove MSB to get how bytes to read
        for(i=tlv_len-1; i>=0; i--)
        {
            ptr++;
            temp += pyld_strt[str_ptr + ptr] * pow(2,i*8); // use i to multiply byte places
        }
        tlv_len = temp;
        ptr ++;
    }
    else /* MSB = 0 */
    {
        //printf("[get_tlv_length()] tlv_len (MSB = 0): %x\n",tlv_len);
        /* handle definite case */
        tlv_len = tlv_len; /* no need to shift since MSB is 0 anyway */
        ptr++;
    }
    tlv->tl_len = ptr;
    tlv->tot_len = tlv_len + ptr;
    //printf("[get_tlv_length()] returning: tl_len: %x, tot_len: %x, ptr: %x\n",tlv->tl_len,tlv->tot_len,ptr);
    return 1;
        
/*
struct tlvdata {
        int type;
        int constructed;
        int class; // universal, application, context-specific, private
        int tl_len;
        int tot_len; // length plus the bytes for type and length
*/
}

void process_packet_kerb(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int dont_process=0, myptr=0, pkt_num=0, tcp_hdr_len=0, jump_len=0, tlv_len=0;
    char SRC[16];
    char DST[16];
    int ether_type = 0;
    int ether_offset = 0;
    unsigned int proto_version = 0;
    u_char *pkt_ptr = NULL;
    struct ip *ip_hdr = NULL;
    int packet_length = 0;
    int ip_header_len = 0;
    int proto = 0;
    int src_port = 0;
    int dst_port = 0;
    unsigned char krb_type = 0;
    struct tlvdata tlv;

    pkt_num += 1;
    dont_process = 0;
    myptr = 0;
    pkt_ptr = buffer;
    ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];

    if(ether_type == ETHER_TYPE_IP)
    {
        // jump over the ethernet header
        pkt_ptr += ETHER_IP_OFFSET;
    }
    else
    {
        //fprintf(stderr, "Can't process ether_type = %04X...\n",ether_type);
        dont_process = 1;
    }

    proto_version = pkt_ptr[myptr] >> 4;

    if(proto_version != IP_V4)
    {
        //fprintf(stderr, "Error: Can only process IPv4 headers at the moment\n");
        dont_process = 1;
    }
    if(dont_process == 0)
    {
        ip_hdr = NULL;
        ip_hdr = (struct ip *)pkt_ptr;
        packet_length = ntohs(ip_hdr->ip_len);
        ip_header_len = (pkt_ptr[myptr] - 0x40) * 4;
        proto = pkt_ptr[myptr+9];
        sprintf(SRC, "%d.%d.%d.%d", pkt_ptr[12], pkt_ptr[13], pkt_ptr[14], pkt_ptr[15]);
        sprintf(DST, "%d.%d.%d.%d", pkt_ptr[16], pkt_ptr[17], pkt_ptr[18], pkt_ptr[19]);

        // jump up to layer 4 headers
        myptr += ip_header_len;
        //printf("[%d] myptr + ip_header_len: [%x]\n",pkt_num,pkt_ptr[myptr]);
        if(proto == 6)
        {
            src_port = (256 * pkt_ptr[myptr]) + pkt_ptr[myptr+1];
            dst_port = (256 * pkt_ptr[myptr+2]) + pkt_ptr[myptr+3];
            tcp_hdr_len = pkt_ptr[myptr+12] / 4;
            // handle packet with no payload
            if(IP_HDR_LEN + tcp_hdr_len >= packet_length)
            {
                //continue;
            }

            if((dst_port == KRB_PORT) || (src_port == KRB_PORT))
            {
                KRB_PKT_CNT++;
                myptr += tcp_hdr_len;
                fprintf(stdout, "[*] %3d Found KRB Packet: %s => %s\n",KRB_PKT_CNT,SRC,DST);
                pkt_ptr += IP_HDR_LEN + tcp_hdr_len + RECORD_MARK_LEN;
                myptr += RECORD_MARK_LEN;
                print_hex(pkt_ptr, 10);
                krb_type = pkt_ptr[0];
                fprintf(stdout,"krb_type: %2x\n",krb_type);
                switch(krb_type)
                {
                    case 0x6a:
                        tlv_len = get_tlv_length(buffer, myptr, &tlv);
                        fprintf(stdout," -> AS-REQ, len: %d\n",tlv_len);
                        break;
                    case 0x6b:
                        fprintf(stdout," -> AS-REP\n");
                        break;
                    case 0x6c:
                        fprintf(stdout," -> TGS-REQ\n");
                        break;
                    case 0x6d:
                        fprintf(stdout," -> TGS-REP\n");
                        break;
                    case 0x7e:
                        fprintf(stdout," -> KRB-ERROR\n");
                        break;
                }
            }
        }
    }
}

void process_packet_count(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = 0;
    size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++TOTAL_COUNT;
    switch(iph->protocol)
    {
        case 1: //ICMP
            ++ICMP_COUNT;
            break;
        case 2: //IGMP
            ++IGMP_COUNT;
            break;
        case 6: // TCP
            ++TCP_COUNT;
            process_packet_kerb(args, header, buffer);
            break;
        case 17: // UDP
            ++UDP_COUNT;
            break;
        default:
            ++OTHER_COUNT;
            break;
    }
    fprintf(stdout, "TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", TCP_COUNT, UDP_COUNT, ICMP_COUNT, IGMP_COUNT, OTHER_COUNT, TOTAL_COUNT);

}

void print_hex(const unsigned char *p, int len)
{
    int i = 0;
    for(i = 0; i < len; i++)
    {
        fprintf(stderr, "%02x:",p[i]);
    }
    fprintf(stderr, "\n");
}

