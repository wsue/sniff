#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

#include "sniff_error.h"
#include "sniff.h"
#include "sniff_conf.h"
#include "sniff_parser.h"
#include "proto_pub.h"
#include "proto_tcpip.h"

enum EDNSCntType{
    EDNSCntType_Question,
    EDNSCntType_ANSWER,
    EDNSCntType_AUTHORITY,
    EDNSCntType_ADDITIONAL,
    EDNSCntType_MAX
};

struct DNSName{
    int     len;
    char    buf[256];
};

/*      analyse a dns name splice
 *      return read num from content
 *      -1  means error
 */
static int DecDNSNameSplice(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,int offset,int isreq,struct DNSName *pout)
{
    const uint8_t *p    = pEthFrame->data + offset;
    uint8_t sz          = p[0];


    if( sz > 63 ){
        int tmp         = 0;
        if( isreq ){
            return -1;
        }

        if( (p[0] & 0xc0) != 0xc0 ){
            return -1;
        }

        tmp     = ((p[0] & 0x3f) << 8 )| p[1];
        do{
            int ret = DecDNSNameSplice(ptTcpIp,pEthFrame,tmp,isreq,pout);
            if( ret < 0 ){
                return ret;
            }

            tmp  += ret;
        }while(0);

        return 0x10002;
    }

    if(sz == 0 ){
        if( pout->len < 2){
            return -1;
        }

        pout->len --;
        pout->buf[pout->len]    = 0;

        return 0x10001;
    }

    if( (offset + sz +1 > pEthFrame->datalen) || (sz + pout->len +1>= 256 )){
        return -1;
    }

    p++;
    memcpy(pout->buf + pout->len,p,sz);
    pout->len   += sz;
    pout->buf[pout->len++]  = '.';

    return sz + 1;
}


static int  DecDNSName(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,int offset,int isreq,struct DNSName *pout)
{
    int         ret     = 0;
    pout->len           = 0;

    do{
        ret     = DecDNSNameSplice(ptTcpIp,pEthFrame,offset,isreq,pout);
        if( ret < 0 ){
            return ret;
        }

        offset  += (ret & 0xffff);
    }while(ret != 1 && ((ret & 0x10000) == 0 )); 


    return offset ;  
}

static void DecDNSInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame)
{
    uint16_t    flag    = htons(*(uint16_t *)(pEthFrame->data+2));
    uint16_t    infocnt[EDNSCntType_MAX];

    int         qr      = flag & 0xa000;
    int         opcode  = (flag >> 11 ) & 0xf;
    int         i       = 0;
    int         offset  = 12;
    int         isreq   = 0;
    struct DNSName      out;

    if( pEthFrame->datalen < 12 ){
        PRN_SHOWBUF_ERRMSG("ERROR: wrong DNS pkg len");
        return ;
    }

    infocnt[EDNSCntType_Question]   = htons(*(uint16_t *)(pEthFrame->data+4));
    infocnt[EDNSCntType_ANSWER]     = htons(*(uint16_t *)(pEthFrame->data+6));
    infocnt[EDNSCntType_AUTHORITY]  = htons(*(uint16_t *)(pEthFrame->data+8));
    infocnt[EDNSCntType_ADDITIONAL] = htons(*(uint16_t *)(pEthFrame->data+10));

    if( qr == 0 ){
        if( infocnt[EDNSCntType_Question] == 0 ){
            PRN_SHOWBUF_ERRMSG("ERROR: no DNS query info");
            return ;
        }

        isreq   = 1;
        PRN_SHOWBUF("DNS REQ op:%x ",opcode);
    }
    else{
        if( !infocnt[EDNSCntType_ANSWER] ){
            PRN_SHOWBUF_ERRMSG("ERROR: no DNS answer info");
            return ;
        }
        PRN_SHOWBUF("DNS ACK op:%x ",opcode);
    }

    if( infocnt[EDNSCntType_Question] != 0 ){
        PRN_SHOWBUF("query %d addr: <",infocnt[EDNSCntType_Question]);

        for( i = 0; i < infocnt[EDNSCntType_Question] ; i ++ ){
            offset  = DecDNSName(ptTcpIp,pEthFrame,offset,isreq,&out);
            if( offset < 0 ){
                PRN_SHOWBUF_ERRMSG("ERROR: get DNS name info failed\n");
                return ;
            }

            PRN_SHOWBUF("%s ",out.buf);

            offset      += 4;
        }
    }

    for( i = EDNSCntType_ANSWER; i < EDNSCntType_MAX ; i ++ ){
        if( infocnt[i] != 0 ){
            int j       = 0;

            switch( i ){
                case EDNSCntType_ANSWER:
                    PRN_SHOWBUF("recv %d answer: <",infocnt[EDNSCntType_ANSWER]);
                    break;

                case EDNSCntType_AUTHORITY:
                    PRN_SHOWBUF("recv %d Authority: <",infocnt[EDNSCntType_AUTHORITY]);
                    break;

                case EDNSCntType_ADDITIONAL:
                    PRN_SHOWBUF("recv %d Additional: <",infocnt[EDNSCntType_ADDITIONAL]);
                    break;

                default:
                    break;
            }

            for( ; j < infocnt[i]; j ++ ){
                unsigned int type   = 0;
                unsigned int class  = 0;
                unsigned int datalen= 0;
                offset      = DecDNSName(ptTcpIp,pEthFrame,offset,isreq,&out);
                if( offset < 0 ){
                    PRN_SHOWBUF_ERRMSG("ERROR: get DNS name info failed\n");
                    return ;
                }

                /*      ack type(2) ack class(2) ttl(4) */
                type        = htons(*(uint16_t *)(pEthFrame->data + offset));
                class       = htons(*(uint16_t *)(pEthFrame->data + offset+2));
                datalen     = htons(*(uint16_t *)(pEthFrame->data + offset+8));
                offset      += 10;

                if( datalen == 4 && type == 1 && class == 1 ){
                    PRN_SHOWBUF("(%s:%d.%d.%d.%d) ",out.buf,pEthFrame->data[offset],pEthFrame->data[offset+1]
                            ,pEthFrame->data[offset+2],pEthFrame->data[offset+3]
                            );
                }
                else{
                    PRN_SHOWBUF("(%s) ",out.buf);
                }

                offset      += datalen;
                if( offset > pEthFrame->datalen  ){
                    PRN_SHOWBUF_ERRMSG("DECODE DNS PKG FAIL,leng error");
                    return ;
                }
            }
        }
    }

    return ;
}

void DecQuicProto(const struct TcpIpInfo *ptTcpIp);
void UDP_DecInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,uint16_t ipflag,enum EOptMode ucDecHex)
{
    if( pEthFrame->datalen > 0 )
    {
        if( ipflag == UDPPORTTYP_DNS ){
            DecDNSInfo(ptTcpIp,pEthFrame);

            if( ucDecHex == EOptModeFull ){
                ProtoMisc_DecHex(pEthFrame->data,pEthFrame->datalen);
            }
        } 
        else if( ipflag == UDPPORTTYP_QUIC ){
            UDPQuic_DecInfo(ptTcpIp,pEthFrame);
            if( ucDecHex == EOptModeFull ){
                ProtoMisc_DecHex(pEthFrame->data,pEthFrame->datalen);
            }
        }
        else if( ucDecHex != EOptModeDef ){
            ProtoMisc_DecHex(pEthFrame->data,pEthFrame->datalen);
        }
    }
}


