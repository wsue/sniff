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


static inline int DecStringInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    char    buf[PER_PACKET_SIZE];
    int     len = ptTcpIp->contentlen < PER_PACKET_SIZE ? ptTcpIp->contentlen : PER_PACKET_SIZE -1;
    strncpy(buf,(const char *)ptTcpIp->content,len);
    buf[len]  = 0;
    if( ipflag != TCPPORTTYP_HTTP || strstr(buf,"HTTP")){
        PRN_SHOWBUF("BODY: %s",(const char *)buf);
        return 1;
    }

    return 0;
}

static inline int RMXDecInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    if( ptTcpIp->contentlen < 4 ){
        return 0;
    }

    if(  ptTcpIp->content[2] == ' ' && isalpha(ptTcpIp->content[0])){  // not "RMX " "RFB " "CSR "
        return DecStringInfo(ptTcpIp,ipflag);
    }

    return 0;
}


static int DecShowableInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    switch( ipflag ){
        case TCPPORTTYP_FTPCMD:
        case TCPPORTTYP_TELNET:
        case TCPPORTTYP_SMTP:
        case TCPPORTTYP_HTTP:
        return DecStringInfo(ptTcpIp,ipflag);

        case TCPPORTTYP_VNC:
        return RMXDecInfo(ptTcpIp,ipflag);

        default:
        break;
    }

    return 0;
}

void TCP_DecInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag,int ucDecHex)
{
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

