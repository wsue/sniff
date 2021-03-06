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

uint16_t g_wShowBufOffset;
uint16_t g_wShowBufAvaliable;
char     g_strShowBuf[PER_PACKET_SIZE *8];


static inline char tochar(unsigned char c)
{
    return  isprint(c) ? (char )c : '.';
}


int ProtoMisc_ShowString(const unsigned char* content, int contentlen,const char* matchtoken)
{
    char    buf[PER_PACKET_SIZE];
    int     len = contentlen < PER_PACKET_SIZE ?contentlen : PER_PACKET_SIZE -1;
    strncpy(buf,(const char*)content,len);
    buf[len]  = 0;
    if( !matchtoken || strstr(buf,matchtoken)){
        PRN_SHOWBUF("BODY: %s",(const char *)buf);
        return 1;
    }

    return 0;
}

void ProtoMisc_DecHex(const unsigned char* content, int contentlen)
{
    int                 needtab         = 0;
    int                 offset          = 0;
    const unsigned char *p              = content ;
    const char          *pstr           = (char *)p;

    if( contentlen <= 0 || !content )
        return ;

    PRN_SHOWBUF("\n\tHEX: \t");
    for( ; offset < contentlen -4; ){
        if( needtab ){
            needtab = 0;
            PRN_SHOWBUF("\t\t");
        }
        PRN_SHOWBUF("%02x%02x%02x%02x ",p[0],p[1],p[2],p[3]);
        offset += 4;
        p      += 4;

        if( offset != 0 && (offset %16 == 0 ) ){
            PRN_SHOWBUF(": %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
                    tochar(pstr[0]),tochar(pstr[1]),tochar(pstr[2]),tochar(pstr[3]), tochar(pstr[4]),tochar(pstr[5]),tochar(pstr[6]),tochar(pstr[7]), tochar(pstr[8]),
                    tochar(pstr[9]),tochar(pstr[10]),tochar(pstr[11]), tochar(pstr[12]),tochar(pstr[13]),tochar(pstr[14]),tochar(pstr[15])
                    );
            pstr    = (char *)p;
            needtab = 1;
        }
        /*
           PRN_SHOWBUF("%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x :%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c\n",
           p[0],p[1],p[2],p[3], p[4],p[5],p[6],p[7], p[8],p[9],p[10],p[11], p[12],p[13],p[14],p[15],
           tochar(p[0]),tochar(p[1]),tochar(p[2]),tochar(p[3]), tochar(p[4]),tochar(p[5]),tochar(p[6]),tochar(p[7]), tochar(p[8]),
           tochar(p[9]),tochar(p[10]),tochar(p[11]), tochar(p[12]),tochar(p[13]),tochar(p[14]),tochar(p[15])
           );
           */
    }


    if( offset < contentlen ){
        if( needtab ){
            needtab = 0;
            PRN_SHOWBUF("\t\t");
        }

        for( ;offset < contentlen ; offset ++, p ++ ){
            PRN_SHOWBUF("%02x",*p);
        }

        if( contentlen%16 ){
            int     restnum         = 16 - (contentlen%16);
            char    spacebuf[32]    = "";
            if( restnum >= 12 ){
                restnum += 2;
            }
            else if ( restnum >= 8 ){
                restnum += 1;
            }
            /*else if ( restnum > 4 ){
              restnum += 0;
              }*/

            if( restnum %4 == 0 ){
                restnum --;
            }

            memset(spacebuf,' ',sizeof(spacebuf)-1);
            spacebuf[ restnum*2 ] = 0;

            PRN_SHOWBUF("%s",spacebuf);
        }
    }

    if( (void*)pstr != (void *)p ){
        PRN_SHOWBUF(" : ");
        for( ; (void *)pstr != (void *)p ; pstr ++ ){
            PRN_SHOWBUF("%c",tochar(*pstr));
        }
    }

    PRN_SHOWBUF("\t\t");
}
