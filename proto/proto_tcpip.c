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



static int  s_bDecEthMac    = 0;
static int  s_bDecHex       = 0;


#define ASSERT_PORTTYPE(portnum,retval)     if( ptTcpIp->srcport == portnum || ptTcpIp->dstport == portnum )  return retval
static uint8_t  GetTcpIpInfo( struct TcpIpInfo *ptTcpIp,const struct iphdr    *piphdr,const unsigned char *content,int contentlen)
{
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
        DecTCPInfo(ptTcpIp,ipflag,s_bDecHex);
    }
    else if( ptTcpIp->iphdr->protocol == IPPROTO_UDP ){
        DecUDPInfo(ptTcpIp,ipflag,s_bDecHex);
    }
    else{
        PRN_SHOWBUF("ip type:0x%02x(%s)",ptTcpIp->iphdr->protocol,IPProto2Str(ptTcpIp->iphdr->protocol));
    }

    PRN_SHOWBUF(">");
}

static int TcpipParser_Decode(void *param,const struct timeval *ts,const unsigned char* data,int len)
{
    struct TcpIpInfo        tTcpIp;
    const struct ethhdr*    heth        = (struct ethhdr*)data;
    uint32_t                ethproto    = htons(heth->h_proto);
    uint16_t                ipflag      = 0;
    const struct iphdr      *piphdr     = NULL;
    int                     contentlen  = len;


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

    ShowEthHead(s_bDecEthMac,heth,ethproto);

    if( contentlen < 0 ){
        PRN_SHOWBUF("WRONG ETH FRAME, eth frame len:%d ",len);
    }

    if( piphdr != NULL ){
        ShowTcpIpInfo(&tTcpIp,ipflag);
    }

    return 0;
}



int TcpIpParser_Init(const struct SniffConf *ptConf)
{
    s_bDecEthMac    = ptConf->bDecEth;
    s_bDecHex       = ptConf->ucDecHex;
    return SniffParser_Register(NULL,TcpipParser_Decode,NULL);
}




