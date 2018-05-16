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


static int              s_relatimemode  = 0;
static struct timeval   s_tvstart;
static int              s_tvstartinit   = 0;


static int TimeInfo_Decode(void *param,const struct EthFrameInfo *pEthFrame)
{
    if( s_relatimemode ){
        if( !s_tvstartinit ){
           s_tvstart        = *(pEthFrame->ts);
           s_tvstartinit    = 1;
        }
        unsigned long           diff        = (pEthFrame->ts->tv_sec - s_tvstart.tv_sec)* 1000 + (pEthFrame->ts->tv_usec - s_tvstart.tv_usec)/1000;
        PRN_SHOWBUF("%ld.%03ld ",diff/1000,diff%1000);
    }
    else {
        time_t  when    = pEthFrame->ts->tv_sec;
        struct  tm  day = *localtime(&when);
        PRN_SHOWBUF("%02d %02d:%02d:%02d-%03ld ",
                day.tm_mday,day.tm_hour,day.tm_min,day.tm_sec,pEthFrame->ts->tv_usec/1000);
    }

    return 0;
}

int ShowTime_Init(const struct SniffConf *ptConf)
{
    s_relatimemode  = ptConf->ucRelateTimestamp;

    return SniffParser_Register(NULL,TimeInfo_Decode,NULL);
}


