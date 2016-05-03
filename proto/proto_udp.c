#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniff_error.h"
#include "sniff.h"
#include "sniff_conf.h"
#include "sniff_parser.h"
#include "proto_pub.h"
#include "proto_tcpip.h"


int DecDNSInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag)
{
    return 0;
}

void DecUDPInfo(const struct TcpIpInfo *ptTcpIp,uint16_t ipflag,int ucDecHex)
{
    if( ptTcpIp->contentlen > 0 )
    {
        if( ucDecHex ){
            ProtoMisc_DecHex(ptTcpIp->content,ptTcpIp->contentlen);
        }
    }
}


