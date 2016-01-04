#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniff_error.h"
#include "sniff.h"
#include "sniff_conf.h"
#include "sniff_parser.h"

#define UDP_PORTTYP_START  0x0
#define TCP_PORTTYP_START  0x40

#define VLAN_FLAG           0x8000

//  程序中仅关注常用的端口,完整的端口影射可看 /etc/services 文件
#define UDP_PORTTYP_UNKNOWN (UDP_PORTTYP_START+1)
#define TCP_PORTTYP_UNKNOWN (TCP_PORTTYP_START)

#define UDPPORTTYP_TFTP     (UDP_PORTTYP_START +10) //  69  端口

#define TCPPORTTYP_FTPDATA  (TCP_PORTTYP_START +1)  //  20  端口
#define TCPPORTTYP_FTPCMD   (TCP_PORTTYP_START +2)  //  21  端口
#define TCPPORTTYP_SSH      (TCP_PORTTYP_START +3)  //  22  端口
#define TCPPORTTYP_TELNET   (TCP_PORTTYP_START +4)  //  23  端口
#define TCPPORTTYP_SMTP     (TCP_PORTTYP_START +5)  //  25  端口
#define TCPPORTTYP_DNS      (TCP_PORTTYP_START +10) //  53  端口
#define TCPPORTTYP_BOOTPS   (TCP_PORTTYP_START +11) //  67  端口
#define TCPPORTTYP_BOOTPC   (TCP_PORTTYP_START +12) //  68  端口
#define TCPPORTTYP_HTTP     (TCP_PORTTYP_START +20) //  80  端口
#define TCPPORTTYP_POP3     (TCP_PORTTYP_START +21) //  110  端口
#define TCPPORTTYP_RPC      (TCP_PORTTYP_START +22) //  111  端口
#define TCPPORTTYP_SFTP     (TCP_PORTTYP_START +23) //  115  端口
#define TCPPORTTYP_NTP      (TCP_PORTTYP_START +24) //  123  端口
#define TCPPORTTYP_NETBIOSNS    (TCP_PORTTYP_START +25) //  137  端口
#define TCPPORTTYP_NETBIOSDGM   (TCP_PORTTYP_START +26) //  138  端口
#define TCPPORTTYP_NETBIOSSSN   (TCP_PORTTYP_START +27) //  139  端口
#define TCPPORTTYP_SNMP     (TCP_PORTTYP_START +30) //  161  端口
#define TCPPORTTYP_BGP      (TCP_PORTTYP_START +35) //  179  端口
#define TCPPORTTYP_IRC      (TCP_PORTTYP_START +36) //  194  端口
#define TCPPORTTYP_IMAP3    (TCP_PORTTYP_START +37) //  220  端口
#define TCPPORTTYP_HTTPS    (TCP_PORTTYP_START +38) //  443  端口



struct TcpIpInfo{
    char            srcip[16];
    char            dstip[16];
    uint16_t        srcport;
    uint16_t        dstport;

    const struct iphdr    *iphdr;
    union{
        const struct tcphdr   *tcphdr;
        const struct udphdr   *udphdr;
    };
    const unsigned char *content;
    int             contentlen;
};


static int  s_bDecEthMac    = 0;
static int  s_ucShowmode    = SNIFF_SHOWMODE_MATCH;
static char s_strMatchMode[SNIFF_MATCH_MAX];


static char     s_strShowBuf[PER_PACKET_SIZE *2];
static uint16_t s_wShowBufOffset;

#define RESET_SHOWBUF()         do{     \
    s_wShowBufOffset    = 0;    s_strShowBuf[0] = 0;    \
}while(0)

#define PRN_SHOWBUF(fmt,arg...) do{     \
    int len = sprintf(s_strShowBuf + s_wShowBufOffset,fmt,##arg);   \
    s_wShowBufOffset += len;    \
}while(0)

#define DUMP_SHOWBUF()          do{ \
    if( s_strMatchMode[0] == 0 \
            || (s_ucShowmode == SNIFF_SHOWMODE_MATCH && strstr(s_strShowBuf,s_strMatchMode) )   \
            || (s_ucShowmode == SNIFF_SHOWMODE_UNMATCH && !strstr(s_strShowBuf,s_strMatchMode) )){   \
        puts(s_strShowBuf);   \
    }   \
}while(0)


static void ShowTime(const struct timeval *ts)
{
    time_t  when    = ts->tv_sec;
    struct  tm  day = *localtime(&when);
    PRN_SHOWBUF("%02d %02d:%02d:%02d-%03d ",
            day.tm_mday,day.tm_hour,day.tm_min,day.tm_sec,ts->tv_usec/1000);
}


#define ASSERT_PORTTYPE(portnum,retval)     if( ptTcpIp->srcport == portnum || ptTcpIp->dstport == portnum )  return retval
static uint8_t  GetTcpIpInfo( struct TcpIpInfo *ptTcpIp,const struct iphdr    *piphdr,const unsigned char *content,int contentlen)
{
    struct tcphdr   *ptcphdr    = (struct tcphdr*)(content);

    memset(ptTcpIp,0,sizeof(*ptTcpIp));
    ptTcpIp->iphdr              = piphdr;
    ip2str(htonl(piphdr->saddr),ptTcpIp->srcip);
    ip2str(htonl(piphdr->daddr),ptTcpIp->dstip);

    if( piphdr->protocol == IPPROTO_UDP ){
        ptTcpIp->udphdr         = (struct udphdr *)(content);
        ptTcpIp->srcport        = htons(ptTcpIp->udphdr->source); 
        ptTcpIp->dstport        = htons(ptTcpIp->udphdr->dest); 
        ptTcpIp->content        = content + sizeof(struct udphdr);
        ptTcpIp->contentlen     = contentlen - sizeof(struct udphdr);

        ASSERT_PORTTYPE(69,UDPPORTTYP_TFTP);
        return UDP_PORTTYP_UNKNOWN;
    }

    if( piphdr->protocol != IPPROTO_TCP )
        return 0;

    ptTcpIp->tcphdr             = (struct tcphdr *)(content);
    ptTcpIp->srcport            = htons(ptTcpIp->tcphdr->source); 
    ptTcpIp->dstport            = htons(ptTcpIp->tcphdr->dest); 
    ptTcpIp->content            = content + ptTcpIp->tcphdr->doff * 4;
    ptTcpIp->contentlen         = contentlen - ptTcpIp->tcphdr->doff * 4;

    ASSERT_PORTTYPE(20,TCPPORTTYP_FTPDATA);
    ASSERT_PORTTYPE(21,TCPPORTTYP_FTPCMD);
    ASSERT_PORTTYPE(22,TCPPORTTYP_SSH);
    ASSERT_PORTTYPE(23,TCPPORTTYP_TELNET);
    ASSERT_PORTTYPE(25,TCPPORTTYP_SMTP);
    ASSERT_PORTTYPE(53,TCPPORTTYP_DNS);
    ASSERT_PORTTYPE(67,TCPPORTTYP_BOOTPS);
    ASSERT_PORTTYPE(68,TCPPORTTYP_BOOTPC);
    ASSERT_PORTTYPE(80,TCPPORTTYP_HTTP);
    ASSERT_PORTTYPE(110,TCPPORTTYP_POP3);
    ASSERT_PORTTYPE(111,TCPPORTTYP_RPC);
    ASSERT_PORTTYPE(115,TCPPORTTYP_SFTP);
    ASSERT_PORTTYPE(123,TCPPORTTYP_NTP);
    ASSERT_PORTTYPE(137,TCPPORTTYP_NETBIOSNS);
    ASSERT_PORTTYPE(138,TCPPORTTYP_NETBIOSDGM);
    ASSERT_PORTTYPE(139,TCPPORTTYP_NETBIOSSSN);
    ASSERT_PORTTYPE(161,TCPPORTTYP_SNMP);
    ASSERT_PORTTYPE(179,TCPPORTTYP_BGP);
    ASSERT_PORTTYPE(194,TCPPORTTYP_IRC);
    ASSERT_PORTTYPE(220,TCPPORTTYP_IMAP3);
    ASSERT_PORTTYPE(443,TCPPORTTYP_HTTPS);

    return TCP_PORTTYP_UNKNOWN;
}


#define PORTTYPE2STR(name)  case TCPPORTTYP_ ##name:    return #name;

static const char *EthProto2Str(uint32_t proto,char *cache)
{
    uint16_t    ipflag      = (proto >> 16) & 0x7f;
    uint16_t    ethproto    = proto & 0xffff;

    //  对认识的 tcp/ip端口返回协议类型
    switch( ipflag ){
        PORTTYPE2STR(FTPDATA);
        PORTTYPE2STR(FTPCMD);
        PORTTYPE2STR(SSH);
        PORTTYPE2STR(TELNET);
        PORTTYPE2STR(SMTP);
        PORTTYPE2STR(DNS);
        PORTTYPE2STR(BOOTPS);
        PORTTYPE2STR(BOOTPC);
        PORTTYPE2STR(HTTP);
        PORTTYPE2STR(POP3);
        PORTTYPE2STR(RPC);
        PORTTYPE2STR(SFTP);
        PORTTYPE2STR(NTP);
        PORTTYPE2STR(NETBIOSNS);
        PORTTYPE2STR(NETBIOSDGM);
        PORTTYPE2STR(NETBIOSSSN);
        PORTTYPE2STR(SNMP);
        PORTTYPE2STR(BGP);
        PORTTYPE2STR(IRC);
        PORTTYPE2STR(IMAP3);
        PORTTYPE2STR(HTTPS);

        case UDPPORTTYP_TFTP:       return "TFTP";
        case UDP_PORTTYP_UNKNOWN:   return "UDP";
        case TCP_PORTTYP_UNKNOWN:   return "TCP";
        default:                 break;
    }

    //  如果不认识,再按以太网头返回
    switch( ethproto ){
        case ETH_P_IP:          return "TCPIP";
        case ETH_P_IPV6:        return "IPv6";
        case ETH_P_ARP:         return "ARP";
        case ETH_P_RARP:        return "RARP";
        case ETH_P_PPP_DISC:    return "PPPOE_Discover";
        case ETH_P_PPP_SES:     return "PPPOE_SESSION";
        default:
                                sprintf(cache,"0x%4x",proto);
                                break;
    }
    return cache;
}

static void ShowEthHead(int decmac,const struct ethhdr *eth,uint32_t ethproto)
{
    char    cache[8]    = "";

    PRN_SHOWBUF("%s%s ",ethproto & VLAN_FLAG ? "VLAN:":"",EthProto2Str(ethproto,cache));
    if( decmac ){
        PRN_SHOWBUF("%02X%02X%02X%02X%02X%02X -> %02X%02X%02X%02X%02X%02X ",
                eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],
                eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
                eth->h_source[0],eth->h_source[1],eth->h_source[2],
                eth->h_source[3],eth->h_source[4],eth->h_source[5]
               );
    }
}


static void ShowTcpIpInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    PRN_SHOWBUF("%s:%d => %s:%d <",
            ptTcpIp->srcip,ptTcpIp->srcport,
            ptTcpIp->dstip,ptTcpIp->dstport);

    PRN_SHOWBUF("data sz:%d ",ptTcpIp->contentlen);

    //  只解 TCP包
    if( ptTcpIp->contentlen < 0 ){
        PRN_SHOWBUF(" CONTENT LEN ERROR>\n");
        return ;
    }

    if( ptTcpIp->iphdr->protocol == IPPROTO_TCP ){
        PRN_SHOWBUF("seq: %u ack:%u %s%s%s%s%s ",
                ptTcpIp->tcphdr->seq,ptTcpIp->tcphdr->ack_seq,
                ptTcpIp->tcphdr->syn ? "syn ":"",
                ptTcpIp->tcphdr->ack ? "ack ":"",
                ptTcpIp->tcphdr->fin ? "fin ":"",
                ptTcpIp->tcphdr->rst ? "rst ":"",
                ptTcpIp->tcphdr->psh ? "psh ":""
                );
        if( ptTcpIp->contentlen > 0 
                && (ipflag == TCPPORTTYP_FTPCMD || ipflag == TCPPORTTYP_TELNET 
                    || ipflag == TCPPORTTYP_SMTP || ipflag == TCPPORTTYP_HTTP)
          ){
            char    buf[PER_PACKET_SIZE];
            int     len = ptTcpIp->contentlen < PER_PACKET_SIZE ? ptTcpIp->contentlen : PER_PACKET_SIZE -1;
            memcpy(buf,ptTcpIp->content,len);
            buf[PER_PACKET_SIZE-1]  = 0;
            if( ipflag != TCPPORTTYP_HTTP || strstr(buf,"HTTP")){
                PRN_SHOWBUF("content <%s>",(const char *)buf);
            }
        }
    } 

    PRN_SHOWBUF(">");
}

static int TcpParser_Decode(void *param,const struct timeval *ts,const unsigned char* data,int len)
{
    struct TcpIpInfo        tTcpIp;
    const struct ethhdr*    heth        = (struct ethhdr*)data;
    uint32_t                ethproto    = htons(heth->h_proto);
    uint16_t                ipflag      = 0;
    const struct iphdr      *piphdr     = NULL;
    int                     contentlen  = len;

    RESET_SHOWBUF();

    data            +=          ETH_HLEN;
    contentlen      -=          ETH_HLEN;

    if( ethproto == ETH_P_8021Q ){
        ethproto    = htons(*(uint16_t *)data) | VLAN_FLAG;
        data        += 2;
        contentlen  -= 2;
    }

    if( (ethproto & 0xffff) == ETH_P_IP ){
        piphdr      = (const struct iphdr    *)(data);
        data        += 4 * piphdr->ihl;
        contentlen  -= 4 * piphdr->ihl;

        ipflag      = GetTcpIpInfo(&tTcpIp,piphdr,data,contentlen);
        ethproto    |= ipflag << 16;
    }

    ShowTime(ts);
    ShowEthHead(s_bDecEthMac,heth,ethproto);

    if( contentlen < 0 ){
        PRN_SHOWBUF("WRONG ETH FRAME, eth frame len:%d ",len);
        DUMP_SHOWBUF();
        return 0;
    }

    if( piphdr != NULL ){
        ShowTcpIpInfo(&tTcpIp,ipflag);
    }

    DUMP_SHOWBUF();
    return 0;
}



int TcpParser_Init(const struct SniffConf *ptConf)
{
    s_bDecEthMac    = ptConf->bDecEth;
    s_ucShowmode    = ptConf->ucShowmode;
    strncpy(s_strMatchMode,ptConf->strMatch,sizeof(s_strMatchMode)-1);
    return SniffParser_Register(NULL,TcpParser_Decode,NULL);
}




