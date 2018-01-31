#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
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
#include "proto_pub.h"
#include "proto_tcpip.h"

#define MAX_IP_ALIAS_NUM    32


#define IS_QUIC_PORT(port)   ((port == 443 || ((port) >= s_iVncPort && (port) <= (s_iVncPort + 1024) ))


struct IPAlias{
    uint32_t    ipaddr;
    uint16_t    port;
    uint16_t    pad;
    char        alias[IP_STR_LEN];
};



struct IPAlias  s_atIPAlias[MAX_IP_ALIAS_NUM];


static int  s_bDecEthMac    = 0;
static int  s_bDecHex       = 0;
static int  s_bOnlyTcpData  = 0;
static int  s_iVncPort      = 0;


static inline const char* ip2alias(uint32_t ip,uint16_t port,char *cache){
    int     i = 0;
    for( ; i < MAX_IP_ALIAS_NUM && s_atIPAlias[i].ipaddr != 0; i ++ ){
        if( s_atIPAlias[i].ipaddr == ip && ( s_atIPAlias[i].port == 0 ||  s_atIPAlias[i].port == port ) ){
            if(  s_atIPAlias[i].port == 0 ){
                snprintf(cache,IP_STR_LEN -1,"%s:%d",s_atIPAlias[i].alias,port);
            }
            else{
                strncpy(cache,s_atIPAlias[i].alias,IP_STR_LEN -1);
            }
            return cache;
        }
    }

    return ip2str(ip,port,cache);
}

static void ParseIpAlias(const char *conf)
{
    int     count           = 0;
    char    *cache          = strdup(conf);

    char            *lasts  = NULL;
    char *token             = strtok_r(cache,",",&lasts);
    while( token && count < MAX_IP_ALIAS_NUM ) {
        char    *p          = strchr(token,'=');
        if( p ){
            char    *pport  = strchr(p+1,':');
            uint32_t    ip  = 0;
            uint32_t    port= 0;
            *p++            = 0;
            if( pport ){
                *pport++    = 0;
                port        = strtoul(pport,NULL,0);
            }

            ip              = inet_addr(p);
            if( ip && token[0] ){
                s_atIPAlias[count].ipaddr  = ntohl(ip);
                s_atIPAlias[count].port    = port;
                strncpy( s_atIPAlias[count].alias,token,IP_STR_LEN-1);
                count ++;
            }
            else{
                printf("ip alias [%s] has some error(%s ip = 0 invalid or no name), skip it\n",conf,token);
            }
        }
        else{
            printf("ip alias [%s] has some error(%s unable to parse), skip it\n",conf,token);
        }
        token   = strtok_r(NULL,",",&lasts);
    }

    free(cache);
}

static inline int GetProtoColorVal(uint32_t ethproto)
{
    uint16_t    ipflag      = (ethproto >> 16) & 0xff;
    switch( ipflag ){
        case UDPPORTTYP_TFTP:   return 42;
        case TCPPORTTYP_FTPDATA:    return 44;
        case TCPPORTTYP_FTPCMD:	return 45;
        case TCPPORTTYP_HTTP:	return 100;
        case TCPPORTTYP_NTP:	return 102;
        case TCPPORTTYP_HTTPS:	return 103;
        case TCPPORTTYP_VNC:	return 104;
        default:        
                                break;
    }

    return 49;
}

static inline int GetIPShowColorVal(const struct TcpIpInfo *ptTcpIp)
{
    const static int    colorcfg[10]    = {32,33,34,35,36,  37,92,93,95,96};
    if( ptTcpIp->servport_side == 1 ){
        return colorcfg[ptTcpIp->dstport %10];
    }
    else if( ptTcpIp->servport_side == 2 ){
        return colorcfg[ptTcpIp->srcport %10];
    }
    else{
        return 39;
    }
}

#define ASSERT_PORTTYPE(portnum,retval)     do{ \
    if( ptTcpIp->srcport == portnum || ptTcpIp->dstport == portnum ){           \
        ptTcpIp->servport_side      = ((ptTcpIp->srcport == portnum) ? 1 :2);   \
        return retval;                          \
    }}while(0)
static uint8_t  GetTcpIpInfo( struct TcpIpInfo *ptTcpIp,const struct iphdr    *piphdr,const unsigned char *content,int contentlen)
{
    int istcpip = 0;

    memset(ptTcpIp,0,sizeof(*ptTcpIp));
    ptTcpIp->iphdr              = piphdr;

    if( piphdr->protocol == IPPROTO_UDP ){
        istcpip                 = 1;

        ptTcpIp->udphdr         = (struct udphdr *)(content);
        ptTcpIp->content        = content + sizeof(struct udphdr);
        ptTcpIp->contentlen     = contentlen - sizeof(struct udphdr);

        ptTcpIp->srcport        = htons(ptTcpIp->udphdr->source); 
        ptTcpIp->dstport        = htons(ptTcpIp->udphdr->dest); 
    }
    else if( piphdr->protocol == IPPROTO_TCP ){
        istcpip                 = 1;

        ptTcpIp->tcphdr         = (struct tcphdr *)(content);
        ptTcpIp->content        = content + ptTcpIp->tcphdr->doff * 4;
        ptTcpIp->contentlen     = contentlen - ptTcpIp->tcphdr->doff * 4;

        ptTcpIp->srcport        = htons(ptTcpIp->tcphdr->source); 
        ptTcpIp->dstport        = htons(ptTcpIp->tcphdr->dest);
    }

    ip2alias(htonl(piphdr->saddr),ptTcpIp->srcport,ptTcpIp->src);
    ip2alias(htonl(piphdr->daddr),ptTcpIp->dstport,ptTcpIp->dst);

    if( !istcpip ){
        return 0;
    }

    if( piphdr->protocol == IPPROTO_UDP ){

        ASSERT_PORTTYPE(69,UDPPORTTYP_TFTP);
        ASSERT_PORTTYPE(53,UDPPORTTYP_DNS);
        ASSERT_PORTTYPE(137,UDPPORTTYP_NETBIOSNS);
        ASSERT_PORTTYPE(138,UDPPORTTYP_NETBIOSDGM);

        return UDP_PORTTYP_UNKNOWN;
    }


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
    ASSERT_PORTTYPE(445,TCPPORTTYP_NETBIOSSSN);
    ASSERT_PORTTYPE(161,TCPPORTTYP_SNMP);
    ASSERT_PORTTYPE(179,TCPPORTTYP_BGP);
    ASSERT_PORTTYPE(194,TCPPORTTYP_IRC);
    ASSERT_PORTTYPE(220,TCPPORTTYP_IMAP3);
    ASSERT_PORTTYPE(443,TCPPORTTYP_HTTPS);
    ASSERT_PORTTYPE(3389,TCPPORTTYP_RDP);

    if( CFG_IS_VNCPORT(ptTcpIp->srcport,s_iVncPort) ){
        ptTcpIp->servport_side  = 1;
        return TCPPORTTYP_VNC;
    }
    if( CFG_IS_VNCPORT(ptTcpIp->dstport,s_iVncPort) ){
        ptTcpIp->servport_side  = 2;
        return TCPPORTTYP_VNC;
    }

    return TCP_PORTTYP_UNKNOWN;
}


#define PORTTYPE2STR(name)  case TCPPORTTYP_ ##name:    return #name;

static const char *EthProto2Str(uint32_t proto,char *cache)
{
    uint16_t    ipflag      = (proto >> 16) & 0xff;
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
        PORTTYPE2STR(VNC);


        case UDPPORTTYP_DNS:        return "DNS";
        case UDPPORTTYP_QUIC:       return "QUIC";
        case UDPPORTTYP_TFTP:       return "TFTP";
        case UDP_PORTTYP_UNKNOWN:   return "UDP";
        case TCP_PORTTYP_UNKNOWN:   return "TCP";
        default:                 break;
    }

    //  如果不认识,再按以太网头返回
    switch( ethproto ){
        case ETH_P_IP:          return "IP";
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

static const char *IPProto2Str(uint32_t proto)
{
    switch( proto ){
        case IPPROTO_ICMP:      return "ICMP";
        case IPPROTO_IGMP:      return "IGMP";
        case IPPROTO_IPIP:      return "IPIP";
        case IPPROTO_TCP:       return "TCP";
        case IPPROTO_UDP:       return "UDP";
        case IPPROTO_IPV6:      return "IPv6";
        case IPPROTO_SCTP:      return "SCTP";
        case IPPROTO_RAW:       return "RAWIP";
        case IPPROTO_UDPLITE:   return "UDPLITE";
        default:                return "UNKNOWN";
    }

}

static void ShowEthHead(int decmac,const struct ethhdr *eth,uint32_t ethproto)
{
    char    cache[8]    = "";

    PRN_SHOWBUF_COLOR(GetProtoColorVal(ethproto),"%s%6s ",
            ethproto & VLAN_FLAG ? "VLAN:":"",
            EthProto2Str(ethproto,cache));

    if( decmac ){
        PRN_SHOWBUF("%02X%02X%02X%02X%02X%02X -> %02X%02X%02X%02X%02X%02X ",
                eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],
                eth->h_dest[3],eth->h_dest[4],eth->h_dest[5],
                eth->h_source[0],eth->h_source[1],eth->h_source[2],
                eth->h_source[3],eth->h_source[4],eth->h_source[5]);
    }
}

static void ShowTcpIpInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    PRN_SHOWBUF_COLOR(GetIPShowColorVal(ptTcpIp),"%15s => %15s <",
            ptTcpIp->src,ptTcpIp->dst);

    PRN_SHOWBUF("data sz:%4d ",ptTcpIp->contentlen);

    //  只解 TCP包
    if( ptTcpIp->contentlen < 0 ){
        PRN_SHOWBUF(" CONTENT LEN ERROR>\n");
        return ;
    }

    if( ptTcpIp->iphdr->protocol == IPPROTO_TCP ){

        if( (!s_bOnlyTcpData) || ptTcpIp->contentlen == 0 ){
            PRN_SHOWBUF("seq: %10u ack:%10u %s%s%s%s%s ",
                    ptTcpIp->tcphdr->seq,ptTcpIp->tcphdr->ack_seq,
                    ptTcpIp->tcphdr->syn ? "syn ":"",
                    ptTcpIp->tcphdr->ack ? "ack ":"",
                    ptTcpIp->tcphdr->fin ? "fin ":"",
                    ptTcpIp->tcphdr->rst ? "rst ":"",
                    ptTcpIp->tcphdr->psh ? "psh ":""
                    );
        }
        TCP_DecInfo(ptTcpIp,ipflag,s_bDecHex);
    }
    else if( ptTcpIp->iphdr->protocol == IPPROTO_UDP ){
        UDP_DecInfo(ptTcpIp,ipflag,s_bDecHex);
    }
    else{
        PRN_SHOWBUF("ip type:0x%02x(%5s)",ptTcpIp->iphdr->protocol,IPProto2Str(ptTcpIp->iphdr->protocol));
    }

    PRN_SHOWBUF(">");
}


static inline int IsProtoFilter(uint16_t ipflag,struct TcpIpInfo *ptTcpIp)
{
    static int ignorelist[] = PROTO_IGNORE_LIST;
    if( ipflag != 0 ){
        int *p  = ignorelist;
        for( ; *p != 0; p ++ ){
            if( *p == ipflag )
                return 1;
        }
    }

    if( s_bOnlyTcpData && ptTcpIp->tcphdr ){
        if( ptTcpIp->contentlen == 0
                && !(ptTcpIp->tcphdr->syn || ptTcpIp->tcphdr->fin || ptTcpIp->tcphdr->rst) )
            return 1;
    }
    return 0;
}

static int TcpipParser_Decode(void *param,const struct timeval *ts,const unsigned char* data,int len)
{
    struct TcpIpInfo        tTcpIp;
    const struct ethhdr*    heth        = (struct ethhdr*)data;
    uint32_t                ethproto    = htons(heth->h_proto);
    uint16_t                ipflag      = 0;
    const struct iphdr      *piphdr     = NULL;
    int                     restlen     = len;


    data            +=          ETH_HLEN;
    restlen         -=          ETH_HLEN;

    if( ethproto == ETH_P_8021Q ){
        ethproto    = htons(*(uint16_t *)data) | VLAN_FLAG;
        data        += 2;
        restlen     -= 2;
    }

    if( (ethproto & 0xffff) == ETH_P_IP ){
        int         contentlen;
        piphdr      = (const struct iphdr    *)(data);
        contentlen  = htons(piphdr->tot_len) - (piphdr->ihl << 2);
        data        += (piphdr->ihl << 2);
        restlen     -= (piphdr->ihl << 2);
        if( restlen < contentlen ){
            PRN_SHOWBUF_ERRMSG("###### \tWRONG FRAME, recv restlen %d < protocol content len:%d \n",restlen,contentlen);
        }

        ipflag      = GetTcpIpInfo(&tTcpIp,piphdr,data,contentlen);
        if( IsProtoFilter(ipflag,&tTcpIp) ){
            DROP_SHOWBUF();
            return 0;
        }
        ethproto    |= ipflag << 16;
    }

    ShowEthHead(s_bDecEthMac,heth,ethproto);

    if( restlen < 0 ){
        PRN_SHOWBUF_ERRMSG("WRONG ETH FRAME, eth frame len:%d ",len);
    }

    if( piphdr != NULL ){
        ShowTcpIpInfo(&tTcpIp,ipflag);
    }
    else if( ((ethproto & 0xffff ) == ETH_P_ARP)
            || ((ethproto & 0xffff ) == ETH_P_RARP) ){
        Arp_DecInfo(data,restlen,s_bDecHex);
    }

    return 0;
}




int TcpIpParser_Init(const struct SniffConf *ptConf)
{
    s_bDecEthMac    = ptConf->bDecEth;
    s_bDecHex       = ptConf->ucDecHex;
    s_bOnlyTcpData  = ptConf->bOnlyTcpData;
    s_iVncPort      = ptConf->wVncPortStart;

    ParseIpAlias(ptConf->strAlias);
    TCPRMX_SetConf(ptConf);

    return SniffParser_Register(NULL,TcpipParser_Decode,NULL);
}




