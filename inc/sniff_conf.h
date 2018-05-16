/*
 * =====================================================================================
 *
 *       Filename:  sniff_conf.h
 *
 *    Description:  SNIFF 配置参数
 *
 * =====================================================================================
 */
#ifndef SNIFF_CONF_H_
#define SNIFF_CONF_H_

#include <stdio.h>
#include <arpa/inet.h>

//  getopt选项编号
#define SNIFF_OPCODE_DEVNAME    'i'
#define SNIFF_OPCODE_RDCAPFILE  'r'
#define SNIFF_OPCODE_WRCAPFILE  'w'
#define SNIFF_OPCODE_PROMISC    'p'

#define SNIFF_OPCODE_MMAP_QLEN  'f'
#define SNIFF_OPCODE_CAPNUM     'c'

#define SNIFF_OPCODE_SHOWMATCH  'm'
#define SNIFF_OPCODE_SHOWNOMATCH 'M'
#define SNIFF_OPCODE_HEX        'x'
#define SNIFF_OPCODE_HEXALL     'X'
#define SNIFF_OPCODE_RELATIMESTAMP  't'
#define SNIFF_OPCODE_SILENT     's'
#define SNIFF_OPCODE_DECETH     '0'

#define SNIFF_OPCODE_PROTO      'P'
#define SNIFF_OPCODE_FILTER     'F'
#define SNIFF_OPCODE_ALIAS      'A'

#define SNIFF_OPCODE_REMOTE     '2'
#define SNIFF_OPCODE_BCAST      '3'
#define SNIFF_OPCODE_DATA       '4'
#define SNIFF_OPCODE_TCPHEAD    '5'
#define SNIFF_OPCODE_RMXDATA    '6'
#define SNIFF_OPCODE_VNCPORT    '7'
#define SNIFF_OPCODE_VNCOK      '8'


#define SNIFF_SHOWMODE_MATCH    0
#define SNIFF_SHOWMODE_UNMATCH  1
#define SNIFF_SHOWMODE_SILENT   2
#define SNIFF_MATCH_MAX         64

#define SNIFF_HEX_UNKNOWNPKG    1
#define SNIFF_HEX_ALLPKG        2

#define CFG_DEF_VNCPORT_START   5901
#define CFG_DEF_VNCPORT_NUM     1024
#define CFG_IS_VNCPORT(port)    ((port) >= CFG_DEF_VNCPORT_START && (port) <= (CFG_DEF_VNCPORT_START + CFG_DEF_VNCPORT_NUM) )

struct SniffConf{
    char    strEthname[32];             //  网卡名
    char    strCapFileRd[256];          //  如果不使用网卡,从哪个文件读报文
    char    strCapFileWr[256];          //  抓包输出文件名
    char    strAlias[256];              //  IP别名机制，类型为name=x.y.z.a,name2=c.d.e.f

    uint32_t        dwCapNum;           //  抓包数,0表示不限
    uint16_t        wEthFrameType;      //  默认以太网帧类型,由ptFilter得到
    uint16_t        wMmapQLen;          //  mmap方式收包时mmap队列大小, 0表示不使用 mmap方式
    uint8_t         bPromisc;           //  是否使用混杂模式        

    uint8_t         ucRelateTimestamp;  //  显示相对第一帧的时间
    uint8_t         ucShowmode;         //  显示模式: 0 显示匹配 1: 显示不匹配 2:不显示
    char            strMatch[SNIFF_MATCH_MAX];      //  当ucShowmode = [0|1]时,对应的参数
};


#define FILTER_MODE_DENY_OR          0
#define FILTER_MODE_ALLOW_OR         1
#define FILTER_MODE_DENY_AND         2
#define FILTER_MODE_ALLOW_AND        3
#define FILTER_MODE_IS_ALLOW(mode)   ((mode) == FILTER_MODE_ALLOW_OR || (mode) ==FILTER_MODE_ALLOW_AND)


enum EProtoNum{
    EIGMPProto,     /*  重复帧类型  */
    ETCPProto,
    EUDPProto,
    EIPProto,       /*  必须是第一个独立的帧类型起始，在这后面不能有相同帧类型情况出现  */
    EARPProto,
    ERARPProto,
    EOtherProto,
    ELastProto      /*  最后一个协议    */
};

union filter_item{
    unsigned char   mac[8];             /*  mac[0-2]=0表示此mac无效 */
    uint32_t        val;                /*  值为0表示此值无效       */
};

struct filter_ctl{
    int                     mode;    /*  是否拒绝所有    */
    union filter_item      *excsrc;    /*  源例外列表 */
    union filter_item      *excdst;    /*  目的例外列表 */
};



#define FILTER_MAX_ITEM     256






int Sniff_ParseArgs(struct SniffConf *ptConf,int argc, char ** argv);

static inline const char* ip2str(uint32_t ip,uint16_t port,char *cache){
    ip  = htonl(ip);
    if( port == 0 ){
        struct in_addr  addr    = {ip};
        inet_ntop(AF_INET,&addr,cache,16);
    }
    else{
        const uint8_t* v = (const uint8_t *)&ip;
        snprintf(cache,24,"%d.%d.%d.%d:%d",v[0],v[1],v[2],v[3],port);
    }
    return cache;
}

#endif

