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



static int DecShowableInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    if(ipflag == TCPPORTTYP_FTPCMD || ipflag == TCPPORTTYP_TELNET 
            || ipflag == TCPPORTTYP_SMTP || ipflag == TCPPORTTYP_HTTP 
            || (ipflag == TCPPORTTYP_VNC 
                && ptTcpIp->contentlen >= 4
                && isalnum(ptTcpIp->content[0])
                && ( memcmp(ptTcpIp->content,"RMX ",4) == 0 
                    || memcmp(ptTcpIp->content,"RFB ",4) == 0 
                    || memcmp(ptTcpIp->content,"CSR ",4) == 0 
                   )
                )
      ){
        char    buf[PER_PACKET_SIZE];
        int     len = ptTcpIp->contentlen < PER_PACKET_SIZE ? ptTcpIp->contentlen : PER_PACKET_SIZE -1;
        strncpy(buf,ptTcpIp->content,len);
        buf[PER_PACKET_SIZE-1]  = 0;
        if( ipflag != TCPPORTTYP_HTTP || strstr(buf,"HTTP")){
            PRN_SHOWBUF("BODY: %s",(const char *)buf);
            return 1;
        }
    }

    return 0;
}

void DecTCPInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag,int ucDecHex)
{
    PRN_SHOWBUF("seq: %10u ack:%10u %s%s%s%s%s ",
            ptTcpIp->tcphdr->seq,ptTcpIp->tcphdr->ack_seq,
            ptTcpIp->tcphdr->syn ? "syn ":"",
            ptTcpIp->tcphdr->ack ? "ack ":"",
            ptTcpIp->tcphdr->fin ? "fin ":"",
            ptTcpIp->tcphdr->rst ? "rst ":"",
            ptTcpIp->tcphdr->psh ? "psh ":""
            );
    if( ptTcpIp->contentlen > 0 )
    {
        if( !DecShowableInfo(ptTcpIp,ipflag) ){
            if( ipflag != TCPPORTTYP_HTTPS && ipflag != TCPPORTTYP_SSH && ucDecHex ){
                ProtoMisc_DecHex(ptTcpIp->content,ptTcpIp->contentlen);

                return ;
            }
        }

        if( ucDecHex == SNIFF_HEX_ALLPKG ){
                ProtoMisc_DecHex(ptTcpIp->content,ptTcpIp->contentlen);
        }
    }
}

