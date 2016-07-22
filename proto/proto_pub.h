#ifndef     PROTO_PUB_H_
#define     PROTO_PUB_H_

extern char     g_strShowBuf[PER_PACKET_SIZE *8];
extern uint16_t g_wShowBufOffset;

#define PRN_SHOWBUF(fmt,arg...) do{     \
    int prnshowlen = sprintf(g_strShowBuf + g_wShowBufOffset,fmt,##arg);   \
    g_wShowBufOffset += prnshowlen;    \
}while(0)

#define RESET_SHOWBUF()         do{                     \
    g_wShowBufOffset    = 0;    g_strShowBuf[0] = 0;    \
}while(0)


#define DUMP_SHOWBUF()          do{ \
    if( s_ucShowmode != SNIFF_SHOWMODE_SILENT && g_wShowBufOffset != 0 ) { \
        if( s_strMatchMode[0] == 0  \
                || (s_ucShowmode == SNIFF_SHOWMODE_MATCH && strstr(g_strShowBuf,s_strMatchMode) )   \
                || (s_ucShowmode == SNIFF_SHOWMODE_UNMATCH && !strstr(g_strShowBuf,s_strMatchMode) )){   \
            puts(g_strShowBuf);     \
        }                           \
    }                               \
    g_wShowBufOffset    = 0;        \
}while(0)

#define PRN_SHOWBUF_ERRMSG(fmt,arg...)          PRN_SHOWBUF("\e[41m" fmt "\e[0m",##arg)
#define PRN_SHOWBUF_COLOR(color,fmt,arg...)     PRN_SHOWBUF("\e\[%dm" fmt "\e\[0m",(color),##arg)

void    ProtoMisc_DecHex(const unsigned char* content, int contentlen);
int     ShowTime_Init(const struct SniffConf *ptConf);
int     TcpIpParser_Init(const struct SniffConf *ptConf);


#endif
