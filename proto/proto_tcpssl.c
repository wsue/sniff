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

#define SERVER_HELLO      

#define HANDSHAKE_HELLO_REQUEST         0
#define HANDSHAKE_CLIENT_HELLO          1
#define HANDSHAKE_SERVER_HELLO          2
#define HANDSHAKE_CERTIFICATE           11
#define HANDSHAKE_SERVER_KEY_EXCHANGE   12
#define HANDSHAKE_CERTIFICATE_REQUEST   13
#define HANDSHAKE_SERVER_HELLO_DONE     14
#define HANDSHAKE_CERTIFICATE_VERIFY    15
#define HANDSHAKE_CLIENT_KEY_EXCHANGE   16
#define HANDSHAKE_FINISHED              20

struct TLSHead{
    uint8_t     contenttype;
    uint16_t    version;
    uint16_t    size;
    uint8_t     body[0];
} __attribute__((packed));


struct TLSFrag_Handshake{
    uint8_t     type;
    uint8_t     lens[3];
    uint8_t     body[0];
} __attribute__((packed));

static inline size_t lens2sz(uint8_t lens[3]){
    return (lens[0] << 16 )| (lens[1] << 8 ) || lens[2];
}

static const char* tlsver2str(uint16_t ver){
    const char* tlsver  = "Unkown";
    switch( ver ){
        case 0x0300:  tlsver  = "SSL 3.0"; break;
        case 0x0301:  tlsver  = "TLS 1.0"; break;
        case 0x0302:  tlsver  = "TLS 1.1"; break;
        case 0x0303:  tlsver  = "TLS 1.2"; break;
        default:      break;
    }
    return tlsver;
}



static int Handshake_Dec(const struct TLSHead *phead,int showhead)
{
    struct TLSFrag_Handshake *frag  = (struct TLSFrag_Handshake *)phead->body;
    const char* type = NULL;
#define HANDSHAKE_CASE(x)    case HANDSHAKE_ ## x: type = #x; break
    switch( frag->type ){
        HANDSHAKE_CASE(HELLO_REQUEST);       
        HANDSHAKE_CASE(CLIENT_HELLO);        
        HANDSHAKE_CASE(SERVER_HELLO);        
        HANDSHAKE_CASE(CERTIFICATE);         
        HANDSHAKE_CASE(SERVER_KEY_EXCHANGE); 
        HANDSHAKE_CASE(CERTIFICATE_REQUEST); 
        HANDSHAKE_CASE(SERVER_HELLO_DONE);   
        HANDSHAKE_CASE(CERTIFICATE_VERIFY);  
        HANDSHAKE_CASE(CLIENT_KEY_EXCHANGE); 
        HANDSHAKE_CASE(FINISHED);                
        default:    break;
    }
#undef HANDSHAKE_CASE

    if( type )
        PRN_SHOWBUF("%s%s ",showhead ? "Handshake ":"",type);
        //PRN_SHOWBUF("%sunknown type %d ",showhead ? "Handshake ":"",frag->type); not all handshake type in record
    return 0;
}

static int Alert_Dec(const struct TLSHead *phead,int showhead)
{
    PRN_SHOWBUF("%s%d ",showhead ? "Alert ":"+",htons(phead->size));
    return 0;
}

static int Cipher_Dec(const struct TLSHead *phead,int showhead)
{
    PRN_SHOWBUF("%s ",showhead ? "Cipher":"");
    return 0;
}

static int Data_Dec(const struct TLSHead *phead,int showhead)
{
    PRN_SHOWBUF("%s%d ",showhead ? "Data ":"+",htons(phead->size));
    return 0;
}

int TCPSSL_DecInfo(const struct TcpIpInfo *ptTcpIp,const struct EthFrameInfo *pEthFrame,uint16_t ipflag)
{
    int     showhead    = 1;
    int     lasttype    = 0;
    size_t  offset      = 0;
    while( offset < pEthFrame->datalen ){
        const struct TLSHead *phead   = (struct TLSHead *)(pEthFrame->data + offset );
        if( showhead ){
            showhead    = 0;
            const char  *tlsver  = tlsver2str(htons(phead->version));
            PRN_SHOWBUF("%s ",tlsver);
        }
        offset          += 5+ htons(phead->size);
        //printf(" off:%d %d %d\n",offset,htons(phead->size),pEthFrame->datalen);
        switch( phead->contenttype ){
            case 20:    //  change_cipher_spec(20)
                Cipher_Dec(phead,lasttype != 20 ? 1:0);
                lasttype    = 20;
                break;

            case 21:    //  alert(21)
                if(lasttype != 21)
                    PRN_SHOWBUF("Alert ");
                lasttype    = 21;
                break;

            case 22:    //  handshake(22)
                if(lasttype != 22)
                    Handshake_Dec(phead,0);
                lasttype    = 22;
                break;

            case 23:    //  application_data(23)
                if(lasttype != 23)
                    PRN_SHOWBUF("Data ");
                lasttype    = 23;
                break;

            default:    
                PRN_SHOWBUF("Unknown Record type %d,maybe a TCP reassemble segment",phead->contenttype); // TODO: some retransmit package decode fail
                break;
        }

        if( offset >  pEthFrame->datalen ){
            //printf("out of size:%d > %d %d\n",offset,pEthFrame->datalen,phead->size);
            break;
        }

    }
    return 0;
}

