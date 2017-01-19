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


static int sOnlyRMXData = 0;





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
    return 0;
}

