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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

#define ETHER_TYPE_IP (0x0800)

void print_hex(const unsigned char *p, int len);
void process_packet_kerb(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer, int size);
void process_packet_count(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer);

// Sources:
// rfc4120 https://tools.ietf.org/html/rfc4120
// rfc1510 https://tools.ietf.org/html/rfc1510
// https://www.blackhat.com/docs/eu-15/materials/eu-15-Beery-Watching-The-Watchdog-Protecting-Kerberos-Authentication-With-Network-Monitoring.pdf
// https://www.blackhat.com/docs/eu-15/materials/eu-15-Beery-Watching-The-Watchdog-Protecting-Kerberos-Authentication-With-Network-Monitoring-wp.pdf

int AS_REQ_COUNT = 0;
int AS_REP_COUNT = 0;
int TGS_REQ_COUNT = 0;
int TGS_REP_COUNT = 0;
int KRB_ERR_COUNT = 0;
int AP_REQ_COUNT = 0;
int AP_REP_COUNT = 0;
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
    pcap_t *FH = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

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

    pcap_loop(FH , -1 , process_packet_count , NULL);

    fprintf(stdout,"\n");
    return 0;
}

int get_tlv_length(const u_char *pyld_strt, int str_ptr, struct tlvdata *tlv)
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

void process_packet_kerb(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer, int size)
{
    int dont_process=0, myptr=0, pkt_num=0, tcp_hdr_len=0, tlv_len=0;
    char SRC[16];
    char DST[16];
    int ether_type = 0;
    unsigned int proto_version = 0;
    const u_char *pkt_ptr = NULL;
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
                ++TOTAL_COUNT;
                switch(krb_type)
                {
                    case 0x6a:
                        tlv_len = get_tlv_length(buffer, myptr, &tlv);
                        fprintf(stdout," -> AS-REQ, len: %d\n",tlv_len);
                        ++AS_REQ_COUNT;
                        break;
                    case 0x6b:
                        fprintf(stdout," -> AS-REP\n");
                        ++AS_REP_COUNT;
                        break;
                    case 0x6c:
                        fprintf(stdout," -> TGS-REQ\n");
                        ++TGS_REQ_COUNT;
                        break;
                    case 0x6d:
                        fprintf(stdout," -> TGS-REP\n");
                        ++TGS_REP_COUNT;
                        break;
                    case 0x6e:
                        fprintf(stdout," -> AP-REQ\n");
                        ++AP_REQ_COUNT;
                        break;
                    case 0x64:
                        fprintf(stdout," -> AP-REP\n");
                        ++AP_REP_COUNT;
                        break;
                    case 0x7e:
                        fprintf(stdout," -> KRB-ERROR\n");
                        ++KRB_ERR_COUNT;
                        break;
                    default:
                        ++OTHER_COUNT;
                }
            }
        }
    }
    fprintf(stdout, "AS-REQ : %d   AS-REP : %d   TGS-REQ : %d   TGS-REP : %d   KRB-ERROR : %d   AP-REQ : %d   AP-REP : %d   OTHER: %d   Total : %d\r", AS_REQ_COUNT, AS_REP_COUNT, TGS_REQ_COUNT, TGS_REP_COUNT, KRB_ERR_COUNT, AP_REQ_COUNT, AP_REP_COUNT, OTHER_COUNT, TOTAL_COUNT);
}

void process_packet_count(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
    int size = 0;
    size = header->len;
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    switch(iph->protocol)
    {
        case 1: //ICMP
            break;
        case 2: //IGMP
            break;
        case 6: // TCP
            process_packet_kerb(args, header, buffer, size);
            break;
        case 17: // UDP
            break;
        default:
            break;
    }

}

int check_golden_ticket()
{
    //record every cname, sname, cipher and enc-part from AS-REP and TGS-REQ
    // make sure there's a corresponding cipher for AS-REP and TGS-REQ
    // if not? report golden ticket attack
    return 0;
}

int check_silver_ticket()
{
    //see check_golden_ticket, but do it for TGS-REP and AP-REQ.
    return 0;
}

int check_ms14_068()
{
    //check for AS-REQ with PA-PAC-REQUEST set to false
    //AND a TGS-REQ with enc-authorization-data added.
    //also, target service has NA bit of userAccountControl attribute set to false
    //      KERB_VALIDATION_INFO structure from PAC (also in AD)
    return 0;
}

int check_dcsync()
{
    //this doesn't really go here. you need to detect DRSUAPI dcerpc calls
    return 0;
}

int check_skeleton_key()
{
    // figure out AD functional level (s/b at least 2008)
    // AS-REQ etypes should include AES128 or AES256 (they won't in the attack)
    //KRB-ERROR for PA-ETYPE-INFO2 should occur
    return 0;
}

int check_bad_username()
{
    // As-REQ
    // KRB-ERROR with error code 6 err-principal-unknown
    return 0;
}

int check_bad_password()
{
    //AS-REQ
    //KRB-Error error code 24 err-preauth-failed or 25 err-preauth-required
    return 0;
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

