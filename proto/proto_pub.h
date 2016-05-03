#ifndef     PROTO_PUB_H_
#define     PROTO_PUB_H_

extern char     g_strShowBuf[PER_PACKET_SIZE *8];
extern uint16_t g_wShowBufOffset;

#define PRN_SHOWBUF(fmt,arg...) do{     \
    int len = sprintf(g_strShowBuf + g_wShowBufOffset,fmt,##arg);   \
    g_wShowBufOffset += len;    \
}while(0)


void    ProtoMisc_DecHex(const unsigned char* content, int contentlen);
int     TcpIpParser_Init(const struct SniffConf *ptConf);


#endif
