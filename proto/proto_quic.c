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


#define PUBLIC_FLAG_VERSION 0x01 // = PUBLIC_FLAG_VERSION.  客户端发送时表示包括 QUIC 版本号。客户端必须一直发送直到服务器确认接收这个版本号。服务端不设置这个版本号表示接受这个版本号。 设置时表示是版本协商报文。
#define PUBLIC_FLAG_RESET   0x02 // = .  设置时表示这是一个公共复位报文.

/*  Two bits at 0x0C indicate the size of the Connection ID that is
    present in the packet.  These bits must be set to 0x0C in all
    packets until negotiated to a different value for a given
    direction (e.g., client may request fewer bytes of the
    Connection ID be presented).
    +  0x0C indicates an 8-byte Connection ID is present
    +  0x08 indicates that a 4-byte Connection ID is present
    +  0x04 indicates that a 1-byte Connection ID is used
    +  0x00 indicates that the Connection ID is omitted
    */
/*
 *  Two bits at 0x30 indicate the number of low-order-bytes of the
 packet number that are present in each packet.  The bits are
 only used for Frame Packets.  For Public Reset and Version
 Negotiation Packets (sent by the server) which don't have a
 packet number, these bits are not used and must be set to 0.
 Within this 2 bit mask:
 +  0x30 indicates that 6 bytes of the packet number is present
 +  0x20 indicates that 4 bytes of the packet number is present
 +  0x10 indicates that 2 bytes of the packet number is present
 +  0x00 indicates that 1 byte of the packet number is present

 *  0x40 is reserved for multipath use.
 *  0x80 is currently unused, and must be set to 0.
 */
static void DecQuicFlag(uint8_t flag)
{
    const char  *cidstr     = "";
    const char  *pkgstr     = "";

    switch( flag & 0xC ){
        case 0xC:        cidstr     = "CID-8";     break;
        case 0x8:        cidstr     = "CID-4";     break;
        case 0x4:        cidstr     = "CID-1";     break;
        default:        break;
    }

    switch( flag & 0x30 ){
        case 0x30:      pkgstr      = "PKGNUM-6";   break;
        case 0x20:      pkgstr      = "PKGNUM-4";   break;
        case 0x10:      pkgstr      = "PKGNUM-2";   break;
        default:        pkgstr      = "PKGNUM-1";   break;
    }

    PRN_SHOWBUF("QUIC flag:< %s%s %s %s>", 
            flag & 1 ? "VER ":"", flag & 2 ? "RST ":"",cidstr,pkgstr );
}

static int DecQuichead(const uint8_t *content, int len)
{
    int     cidlen      = 0;
    char    cidstr[32]  = "";
    int     pnumlen     = 1;
    char    pnumstr[32] = "";
    uint8_t flag        = content[0];

    switch( flag & 0xC ){
        case 0xC:        cidlen     = 8;     break;
        case 0x8:        cidlen     = 4;     break;
        case 0x4:        cidlen     = 1;     break;
        default:        break;
    }

    switch( flag & 0x30 ){
        case 0x30:      pnumlen     = 6;     break;
        case 0x20:      pnumlen     = 4;     break;
        case 0x10:      pnumlen     = 2;     break;
        default:        break;
    }

    content ++;
    if( cidlen ){
        switch( cidlen ){
            case 8:         sprintf(cidstr," CID-%02X%02X%02X%02X%02X%02X%02X%02X ",
                                    content[0],content[1],content[2],content[3],
                                    content[4],content[5],content[6],content[7]
                                   );     
                            break;
            case 4:         sprintf(cidstr," CID-%02X%02X%02X%02X ",
                                    content[0],content[1],content[2],content[3]);     
                            break;
            case 1:         sprintf(cidstr," CID-%02X ",content[0]);     break;
            default:        break;
        }
        content += cidlen;
    }

    switch( pnumlen ){
        case 1:     sprintf(pnumstr," PKGNUM-%02X ",content[0]);     break;
        case 2:     sprintf(pnumstr," PKGNUM-%02X%02X ",
                            content[0], content[1]);     
                    break;
        case 4:     sprintf(pnumstr," PKGNUM-%02X%02X%02X%02X ",
                            content[0], content[1],content[2],content[3]);     
                    break;
        case 6:     sprintf(pnumstr," PKGNUM-%02X%02X%02X%02X%02X%02X ",
                            content[0], content[1],content[2],content[3],content[4],content[5]);     
                    break;
    }

    DecQuicFlag(flag);
    PRN_SHOWBUF("total len:%d %s %s bodylen:%d",
            len, cidstr,pnumstr,
            len - (1 + cidlen + pnumlen) );

    return 1 + cidlen + pnumlen;
}

void UDPQuic_DecInfo(const struct TcpIpInfo *ptTcpIp)
{
    DecQuichead(ptTcpIp->content,ptTcpIp->contentlen);

    return ;
}

