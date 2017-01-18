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


struct ArpHead{
    uint16_t    hwtype;
    uint16_t    prototype;
    uint8_t     hwaddrlen;
    uint8_t     protoaddrlen;
    uint16_t    opcode;
    const uint8_t     *sha;   //  Sender Hardware Address:
    const uint8_t     *spa;   //  Sender Protocol Address
    const uint8_t     *tha;   //  Target Hardware Address
    const uint8_t     *tpa;   //  Target Protocol Address
};

static const char *ArpHwTyp2Str(int hwtype)
{
    switch( hwtype ){
        case    1:      return "Eth10Mb";
        case    6:      return "802Net";
        case    20:     return "Serial";
        default:        return "UNKNOWN";
    }
}

static const char *ArpProTyp2Str(int protype)
{
    switch( protype ){
        case    ETH_P_IP:   return "IPv4";
        case    ETH_P_IPV6: return "IPv6";
        default:            return "UNKNOWN";
    }
}

static const char *ArpOp2Str(int opcode)
{
    switch(opcode){
        case    1:      return  "ARPReq    ";
        case    2:      return  "ARPReply  ";
        case    3:      return  "RARPReq   ";
        case    4:      return  "RARPReply ";
        case    5:      return  "DRARPReq  ";
        case    6:      return  "DRARPReply";
        case    7:      return  "DRARPErr  ";
        case    8:      return  "INARPReq  ";
        case    9:      return  "INARPReply";
        default:        return  "UNKNOWN   ";
    }
}


void Arp_DecInfo(const uint8_t *data,int len,int ucDecHex)
{
    struct ArpHead  head    = {0};
    memcpy(&head,data,8);

    if( len < 8 + (head.hwaddrlen + head.protoaddrlen) * 2 ){
        PRN_SHOWBUF_ERRMSG("wrong arp frame sz: %d",len);
        return ;
    }

    head.hwtype         = htons(head.hwtype);
    head.prototype      = htons(head.prototype);
    head.opcode         = htons(head.opcode);
    head.sha            = data + 8;
    head.spa            = head.sha + head.hwaddrlen;
    head.tha            = head.spa + head.protoaddrlen;
    head.tpa            = head.tha + head.hwaddrlen;

    PRN_SHOWBUF("%s: type<%s/%s> src<%02x:%02x:%02x:%02x:%02x:%02x/%d.%d.%d.%d> dst<%02x:%02x:%02x:%02x:%02x:%02x/%d.%d.%d.%d>",ArpOp2Str(head.opcode),
            ArpHwTyp2Str(head.hwtype),ArpProTyp2Str(head.prototype),
            head.sha[0],head.sha[1],head.sha[2],head.sha[3],head.sha[4],head.sha[5],
            head.spa[0],head.spa[1],head.spa[2],head.spa[3],
            head.tha[0],head.tha[1],head.tha[2],head.tha[3],head.tha[4],head.tha[5],
            head.tpa[0],head.tpa[1],head.tpa[2],head.tpa[3]
            );

    if( ucDecHex == SNIFF_HEX_ALLPKG ){
        ProtoMisc_DecHex(data,len);
    }
}

