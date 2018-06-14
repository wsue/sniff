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

#undef SUPPORT_RMX_PROTOCOL

#ifdef SUPPORT_RMX_PROTOCOL
#include "proto_rmx.h"
#endif



static int sOnlyRMXData = 1;




static const char* RMXGetChannelName(uint8_t id,size_t rmxlen,const uint8_t* body)
{
#ifdef SUPPORT_RMX_PROTOCOL
    switch( id ){
        case kConnection:	
            if( sOnlyRMXData ){
                DROP_SHOWBUF();
            }
            else{
                switch( body[0] ){
                    case 1: return "Ping";
                    case 2: return "Pong";
                    case 3: return "Shutdown";
                    default: return NULL;
                }
            }
            break;

        case kHttp:	        return  "Http";
        case kKey:	        return  "Key";
        case kMouse:	        return  "Mouse";
        case kIosCsrCommand:    return "IosCsr";
        case kQemu:	        return  "Qemu";
        case kMotion:	        return  "Motion";
        case kSetting:	        return  "Setting";
        case kRawData:	        return  "RawData";
        case kCsr:	        return  "Csr";
        //case kCustom:	        return  "Custom";

        default:
                                break;
    }
#endif
    return NULL;
}


int TCPRMX_SetParam(char opcode,const char *optarg)
{
    switch( opcode ){
        case SNIFF_OPCODE_RMXPROTO:
            sOnlyRMXData    = 0;
            break;

        default:
            break;
    }

    return 0;
}

int TCPRMX_DecInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,uint16_t ipflag)
{
    if( pEthFrame->datalen < 4 ){
        return 0;
    }

    if(  pEthFrame->data[2] == ' ' && isalpha(pEthFrame->data[0])){  // not "RMX " "RFB " "CSR "
        return ProtoMisc_ShowString(pEthFrame->data,pEthFrame->datalen,NULL);
    }

#ifdef SUPPORT_RMX_PROTOCOL
    const uint8_t   *data   = pEthFrame->data;
    int              restsz = (int)pEthFrame->datalen;
    int             printtitle  = 1;
    int             ret     = DecRMXHead(data,restsz,printtitle);
    if( ret <= 0 ){
        return -1;
    }
    printtitle  = 0;
    data    += ret;
    restsz  -= ret;
#endif

    return 0;
}

