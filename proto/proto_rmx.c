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


static int sOnlyRMXData = 0;


static inline const char* RMXGetChannelName(uint8_t id,const uint8_t* body)
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


int TCPRMX_SetConf(const struct SniffConf *ptConf)
{
    if( ptConf->bRMXOnlyData ){
        sOnlyRMXData    = 1;
    }

    return 0;
}

int TCPRMX_DecInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    if( ptTcpIp->contentlen < 4 ){
        return 0;
    }

    if(  ptTcpIp->content[2] == ' ' && isalpha(ptTcpIp->content[0])){  // not "RMX " "RFB " "CSR "
        return ProtoMisc_ShowString(ptTcpIp->content,ptTcpIp->contentlen,NULL);
    }
    else{
#ifdef SUPPORT_RMX_PROTOCOL

        struct RMXHead* head = (struct RMXHead*)ptTcpIp->content;
        const char*     channelname = RMXGetChannelName(head->channel_id,head->body);

        if( channelname ){
            int len = RMX_PACKET_GETSIZE(head);

            if( head->channel_id == kMouse 
                    || head->channel_id == kKey
                    || head->channel_id == kMotion ){
                if( len > RMX_PACKET_NORMALBODYSIZE || ptTcpIp->contentlen > RMX_PACKET_NORMALBODYSIZE)
                    return 0;
            }

            if( head->channel_id == kSetting && len > RMX_PACKET_SETTINGBODYMAX  ){
                return 0;
            }

            if( (len +RMX_PACKET_HEADSIZE ) == ptTcpIp->contentlen 
                    || (len > RMX_PACKET_TCPPDUMIN && len < RMX_PACKET_NORMALBODYMAX && ptTcpIp->contentlen > RMX_PACKET_TCPPDUMIN ) ){
                if( head->channel_id == kConnection ){
                    if( len < 10 ){
                        PRN_SHOWBUF("RMX: %s",channelname);
                        return 1;
                    }

                    return 0;
                }


                PRN_SHOWBUF("RMX: %s :%d/%d ",channelname,ptTcpIp->contentlen -RMX_PACKET_HEADSIZE ,len);
                return 1;
            }

            if( len != 0 
                    || ( len > RMX_PACKET_NORMALBODYSIZE 
                        && ptTcpIp->contentlen < (RMX_PACKET_NORMALBODYSIZE+RMX_PACKET_HEADSIZE) 
                        && len >= (ptTcpIp->contentlen - RMX_PACKET_HEADSIZE))
                    ){
                PRN_SHOWBUF("RMX?? %s :%d/%d ",channelname,ptTcpIp->contentlen -RMX_PACKET_HEADSIZE ,len);
            }
        }
#endif
    }

    return 0;
}

