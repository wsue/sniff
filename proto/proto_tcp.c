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


static int DecShowableInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,uint16_t ipflag)
{
    switch( ipflag ){
        case TCPPORTTYP_FTPCMD:
        case TCPPORTTYP_TELNET:
        case TCPPORTTYP_SMTP:
        return ProtoMisc_ShowString(pEthFrame->data,pEthFrame->datalen,NULL);

        case TCPPORTTYP_HTTP:
        return ProtoMisc_ShowString(pEthFrame->data,pEthFrame->datalen,"HTTP");

        case TCPPORTTYP_HTTPS:
        return TCPSSL_DecInfo(ptTcpIp,pEthFrame,ipflag);

        case TCPPORTTYP_VNC:
        return TCPRMX_DecInfo(ptTcpIp,pEthFrame,ipflag);

        default:
        break;
    }

    return 0;
}

void TCP_DecInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,uint16_t ipflag,enum EOptMode ucDecHex)
{
    if( pEthFrame->datalen > 0 )
    {
        if( !DecShowableInfo(ptTcpIp,pEthFrame,ipflag) ){
            if( ipflag != TCPPORTTYP_HTTPS && ipflag != TCPPORTTYP_SSH && (ucDecHex != EOptModeDef )){
                ProtoMisc_DecHex(pEthFrame->data,pEthFrame->datalen);

                return ;
            }
        }

        if( ucDecHex == EOptModeFull ){
                ProtoMisc_DecHex(pEthFrame->data,pEthFrame->datalen);
        }
    }
}

