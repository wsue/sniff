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


#define IS_QUIC_PORT(port)   (port == 443 )


struct IPAlias{
    uint32_t    ipaddr;
    uint16_t    port;
    uint16_t    pad;
    char        alias[IP_STR_LEN];
};




struct TcpIpShowMode{
    int             bDecEthMac;
    enum EOptMode   DecHex;
    enum EOptMode   ProtoDecMode;
    struct IPAlias  atIPAlias[MAX_IP_ALIAS_NUM];
};

static struct TcpIpShowMode sTcpShowMode;


static inline const char* ip2alias(uint32_t ip,uint16_t port,char *cache){
    int     i = 0;
    for( ; i < MAX_IP_ALIAS_NUM && sTcpShowMode.atIPAlias[i].ipaddr != 0; i ++ ){
        if( sTcpShowMode.atIPAlias[i].ipaddr == ip && ( sTcpShowMode.atIPAlias[i].port == 0 ||  sTcpShowMode.atIPAlias[i].port == port ) ){
            if(  sTcpShowMode.atIPAlias[i].port == 0 ){
                snprintf(cache,IP_STR_LEN -1,"%s:%d",sTcpShowMode.atIPAlias[i].alias,port);
            }
            else{
                strncpy(cache,sTcpShowMode.atIPAlias[i].alias,IP_STR_LEN -1);
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
                sTcpShowMode.atIPAlias[count].ipaddr  = ntohl(ip);
                sTcpShowMode.atIPAlias[count].port    = port;
                strncpy( sTcpShowMode.atIPAlias[count].alias,token,IP_STR_LEN-1);
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

static inline int GetIPShowColorVal(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pFrame)
{
    const static int    colorcfg[10]    = {32,33,34,35,36,  37,92,93,95,96};
    int port = pFrame->sport > pFrame->dport ? pFrame->sport : pFrame->dport;
    return pFrame->mapport != 0 ?colorcfg[port %10] : 39;
}

static uint8_t  GetTcpIpInfo( struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pFrame)
{
    memset(ptTcpIp,0,sizeof(*ptTcpIp));

    ip2alias(pFrame->saddr,pFrame->sport,ptTcpIp->src);
    ip2alias(pFrame->daddr,pFrame->dport,ptTcpIp->dst);

    if( pFrame->hip->protocol != IPPROTO_UDP &&  pFrame->hip->protocol != IPPROTO_TCP ){
        return 0;
    }

    if( pFrame->hip->protocol == IPPROTO_UDP ){
        switch( pFrame->mapport ){
            case 69:	return UDPPORTTYP_TFTP;
            case 53:	return UDPPORTTYP_DNS;
            case 137:	return UDPPORTTYP_NETBIOSNS;
            case 138:	return UDPPORTTYP_NETBIOSDGM;
            default:
            break;
        }
        return UDP_PORTTYP_UNKNOWN;
    }


    switch( pFrame->mapport ){
        case 20:	return TCPPORTTYP_FTPDATA;
        case 21:	return TCPPORTTYP_FTPCMD;
        case 22:	return TCPPORTTYP_SSH;
        case 23:	return TCPPORTTYP_TELNET;
        case 25:	return TCPPORTTYP_SMTP;
        case 53:	return TCPPORTTYP_DNS;
        case 67:	return TCPPORTTYP_BOOTPS;
        case 68:	return TCPPORTTYP_BOOTPC;
        case 80:	return TCPPORTTYP_HTTP;
        case 110:	return TCPPORTTYP_POP3;
        case 111:	return TCPPORTTYP_RPC;
        case 115:	return TCPPORTTYP_SFTP;
        case 123:	return TCPPORTTYP_NTP;
        case 137:	return TCPPORTTYP_NETBIOSNS;
        case 138:	return TCPPORTTYP_NETBIOSDGM;
        case 139:	return TCPPORTTYP_NETBIOSSSN;
        case 445:	return TCPPORTTYP_NETBIOSSSN;
        case 161:	return TCPPORTTYP_SNMP;
        case 179:	return TCPPORTTYP_BGP;
        case 194:	return TCPPORTTYP_IRC;
        case 220:	return TCPPORTTYP_IMAP3;
        case 443:	return TCPPORTTYP_HTTPS;
        case 3389:	return TCPPORTTYP_RDP;
        default:
                        break;
    }
    if( CFG_IS_VNCPORT(pFrame->mapport) ){
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

static void ShowTcpIpInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pFrame,uint16_t ipflag)
{
    PRN_SHOWBUF_COLOR(GetIPShowColorVal(ptTcpIp,pFrame),"%15s => %15s <",
            ptTcpIp->src,ptTcpIp->dst);

    PRN_SHOWBUF("data sz:%4d ",pFrame->datalen);

    //  只解 TCP包
    if( pFrame->datalen < 0 ){
        PRN_SHOWBUF(" CONTENT LEN ERROR>\n");
        return ;
    }

    if( pFrame->hip->protocol == IPPROTO_TCP ){
        int important = (pFrame->htcp->syn || pFrame->htcp->fin || pFrame->htcp->rst)? 1:0;
        if( sTcpShowMode.ProtoDecMode == EOptModeFull || important ){
            PRN_SHOWBUF("seq: %10u ack:%10u %s%s%s%s%s ",
                    pFrame->htcp->seq,pFrame->htcp->ack_seq,
                    pFrame->htcp->syn ? "syn ":"",
                    pFrame->htcp->ack ? "ack ":"",
                    pFrame->htcp->fin ? "fin ":"",
                    pFrame->htcp->rst ? "rst ":"",
                    pFrame->htcp->psh ? "psh ":""
                    );
        }
        TCP_DecInfo(ptTcpIp,pFrame,ipflag,sTcpShowMode.DecHex);
    }
    else if( pFrame->hip->protocol == IPPROTO_UDP ){
        UDP_DecInfo(ptTcpIp,pFrame,ipflag,sTcpShowMode.DecHex);
    }
    else{
        PRN_SHOWBUF("ip type:0x%02x(%5s)",pFrame->hip->protocol,IPProto2Str(pFrame->hip->protocol));
    }

    PRN_SHOWBUF(">");
}


static inline int WillShowFrame(const struct EthFrameInfo *pEthFrame)
{
    if( pEthFrame->hip->protocol == IPPROTO_TCP ){
        int important = (pEthFrame->htcp->syn || pEthFrame->htcp->fin || pEthFrame->htcp->rst)? 1:0;
        if( sTcpShowMode.ProtoDecMode == EOptModeDef )
            return (  important || pEthFrame->datalen > 0 )? TRUE:FALSE;
    }
    return TRUE;
}


void TcpipParser_ResetFrame(struct EthFrameInfo *pFrame)
{
    pFrame->framesize   = 0;
    pFrame->ethproto    = 0;
    pFrame->hip         = NULL;
    pFrame->htcp        = NULL;
    pFrame->saddr       = 0;
    pFrame->daddr       = 0;
    pFrame->sport       = 0;
    pFrame->dport       = 0;
    pFrame->mapport     = 0;
    pFrame->data        = NULL;
    pFrame->datalen     = 0;
}

int TcpipParser_SetFrame(struct EthFrameInfo *pframe)
{
    pframe->ethproto    = htons(pframe->heth->h_proto);

    pframe->data        = (uint8_t *)pframe->heth;
    pframe->datalen     = pframe->framesize;
    pframe->data[pframe->datalen]   = 0;
    pframe->data        += ETH_HLEN;
    pframe->datalen     -= ETH_HLEN;

    if( pframe->ethproto == ETH_P_8021Q ){
        if( pframe->datalen < 4 ){
            PRN_SHOWBUF_ERRMSG("WRONG ETH FRAME, eth frame len:%d ",pframe->datalen);
            return ERRCODE_SNIFF_BADFRAME;
        }

        pframe->ethproto = htons(*(unsigned short *)(pframe->data+2));
        pframe->data    += 4;
        pframe->datalen -= 4;
    }

    if( pframe->ethproto != ETH_P_IP )
        return 0;

    pframe->hip          =  (struct iphdr *)pframe->data;
    size_t   iplen       = pframe->hip->ihl << 2;
    size_t  totallen     = htons(pframe->hip->tot_len);
    if( pframe->datalen < totallen ){
        PRN_SHOWBUF_ERRMSG("###### \tWRONG FRAME, recv restlen %d < protocol content len:%d \n",pframe->datalen , totallen);
        return ERRCODE_SNIFF_BADFRAME;
    }

    pframe->saddr       = htonl(pframe->hip->saddr);
    pframe->daddr       = htonl(pframe->hip->daddr);

    pframe->data         += iplen;
    pframe->datalen      = totallen - iplen;

    switch( pframe->hip->protocol ){
        case IPPROTO_TCP:
            pframe->htcp         = (struct tcphdr*)(pframe->data);
            pframe->data         += pframe->htcp->doff * 4;
            pframe->datalen      -= pframe->htcp->doff * 4;
            pframe->sport        = htons(pframe->htcp->source); 
            pframe->dport        = htons(pframe->htcp->dest); 
            break;

        case IPPROTO_UDP:
            pframe->hudp         = (struct udphdr*)(pframe->data);
            pframe->data         += sizeof(struct udphdr);
            pframe->datalen      -= sizeof(struct udphdr);

            pframe->sport        = htons(pframe->hudp->source); 
            pframe->dport        = htons(pframe->hudp->dest); 
            break;

        default:
            break;
    }

    pframe->mapport      = SFilter_MapPort( pframe->dport < pframe->sport ? pframe->dport : pframe->sport);
    return 0;
}

static int TcpipParser_Decode(void *param,const struct EthFrameInfo *pEthFrame)
{
    struct TcpIpInfo        tTcpIp;
	uint8_t                 ipflag = 0;
    uint32_t                ethproto    = pEthFrame->ethproto;
    if( htons(pEthFrame->heth->h_proto) == ETH_P_8021Q )
         ethproto |= VLAN_FLAG;

    if( (ethproto & 0xffff) == ETH_P_IP ){
        if( !WillShowFrame(pEthFrame) ){
            DROP_SHOWBUF();
            return 0;
        }

        ipflag      = GetTcpIpInfo(&tTcpIp,pEthFrame);

        ethproto    |= ipflag << 16;
    }

    ShowEthHead(sTcpShowMode.bDecEthMac,pEthFrame->heth,ethproto);

    if( (ethproto & 0xffff) == ETH_P_IP )
        ShowTcpIpInfo(&tTcpIp,pEthFrame,ipflag);
    else if( ((ethproto & 0xffff ) == ETH_P_ARP)
            || ((ethproto & 0xffff ) == ETH_P_RARP) ){
        Arp_DecInfo(pEthFrame->data,pEthFrame->datalen,sTcpShowMode.DecHex);
    }

    return 0;
}


void TcpipParser_SetParam(char opcode,const char *optarg)
{
    switch(opcode){
        case SNIFF_OPCODE_ALIAS:
            ParseIpAlias(optarg);
            break;

        case SNIFF_OPCODE_HEX:
            sTcpShowMode.DecHex     = EOptModeLimit;
            break;

        case SNIFF_OPCODE_HEXALL:
            sTcpShowMode.DecHex     = EOptModeFull;
            break;

        case SNIFF_OPCODE_DECETH:
            sTcpShowMode.bDecEthMac = TRUE;
            break;

        case SNIFF_OPCODE_RMXPROTO:
            TCPRMX_SetParam(opcode,optarg);
            break;

        case SNIFF_OPCODE_TCPHEAD:
            sTcpShowMode.ProtoDecMode   = strtoul(optarg,0,0);
            if( sTcpShowMode.ProtoDecMode < EOptModeDef )
                sTcpShowMode.ProtoDecMode = EOptModeDef;
            else if( sTcpShowMode.ProtoDecMode > EOptModeFull )
                sTcpShowMode.ProtoDecMode = EOptModeFull;
            break;

        default:
            break;
    }
}


int TcpIpParser_Init()
{
    return SniffParser_Register(NULL,TcpipParser_Decode,NULL);
}




