/*
 * =====================================================================================
 *
 *       Filename:  sniff_filter_bpf.c
 *
 *    Description:  设置常用的 BPF 过滤
 * =====================================================================================
 */
#define _GNU_SOURCE
#include <getopt.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
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

#define SET_BPF_FILTER(bpf,ret,errhint) do{                                          \
    struct sock_fprog  fprog;                                                           \
    fprog.len           = sizeof(bpf)/sizeof(struct sock_filter);                           \
    fprog.filter        = bpf;                                                      \
    ret = setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &fprog, sizeof(fprog));          \
    if( ret != 0 ) {                                                                    \
        PRN_MSG("set filter " #bpf " len:%d fail,errno:%d "errhint"\n",sizeof(bpf)/sizeof(struct sock_filter),errno);    \
    }else{                                                                                   \
        DBG_ECHO("set filter " #bpf " len:%d succ "errhint"\n",sizeof(bpf)/sizeof(struct sock_filter));    \
    } \
}while(0)

/*
 *  常用过滤规则(都是过滤 remote端口情况):
 *  1.  所有, 
 *      允许指定端口
 *      允许指定IP
 *  1.  只允许 udp
 *      允许udp指定端口
 *      允许udp指定IP
 *  2.  只允许tcp
 *      允许tcp指定端口
 *      允许指定ip
 *  3.  只允许 tcp/ip
 *      允许指定ip
 *
 *  其它的,后面考虑增加从文本中读取 bpf 过滤规则
 *      
 */
static int proto2frametype(int protoid)
{
    switch( protoid ){
        case EIPProto:              return ETH_P_IP;
        case EARPProto:             return ETH_P_ARP;
        case ERARPProto:            return ETH_P_RARP;

        default:
                                    break;
    }

    return 0;
}

static int proto2iptype(int protoid)
{
    switch( protoid ){
        case EIGMPProto:            return IPPROTO_IGMP;
        case ETCPProto:             return IPPROTO_TCP;
        case EUDPProto:             return IPPROTO_UDP;
        default:
                                    break;
    }

    return 0;
}

static struct sock_filter bpf_all[]    = {
    { 0x28, 0, 0, 0x0000000c },     //  0
    { 0x15, 0, 7, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 18, 0x00000006 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 15, 0, 0x00000016 },
    { 0x15, 14, 0, 0x00000017 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 12, 11, 0x00000016 },
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 10, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 8, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 4, 0, 0x00000016 },
    { 0x15, 3, 0, 0x00000017 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 1, 0, 0x00000016 },
    { 0x15, 0, 1, 0x00000017 },
    { 0x6, 0, 0, 0x00000000 },
    { 0x6, 0, 0, 0x00040000 }
};

#define FILTER_ALL(ret)        do{          \
    SET_BPF_FILTER(bpf_all,ret,"");    \
}while(0)

static struct sock_filter bpf_all_1port[]    = {
    { 0x28, 0, 0, 0x0000000c }, //  0
    { 0x15, 0, 8, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 17, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 14, 0, 0x00000050 },    //  7
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 12, 13, 0x00000050 },   //  9
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 2, 0, 0x00000084 },
    { 0x15, 1, 0, 0x00000006 },
    { 0x15, 0, 8, 0x00000011 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000050 },     //  19
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000050 },     //  22
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ALL_1PORT(ret,port)      do{ \
    bpf_all_1port[7].k = port;                  \
    bpf_all_1port[9].k = port;                  \
    bpf_all_1port[19].k = port;                 \
    bpf_all_1port[22].k = port;                 \
    SET_BPF_FILTER(bpf_all_1port,ret,"");       \
}while(0)






static struct sock_filter bpf_all_1ip[]    = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 15, 0x00000800 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 2, 0, 0x7e7f8081 },     //  3
    { 0x20, 0, 0, 0x0000001e },
    { 0x15, 0, 18, 0x7e7f8081 },     //  4,
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 15, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 13, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 11, 0, 0x00000016 },
    { 0x15, 10, 0, 0x00000017 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 8, 0, 0x00000016 },
    { 0x15, 7, 6, 0x00000017 },
    { 0x15, 1, 0, 0x00000806 },
    { 0x15, 0, 5, 0x00008035 },
    { 0x20, 0, 0, 0x0000001c },
    { 0x15, 2, 0, 0x7e7f8081 },     //  20
    { 0x20, 0, 0, 0x00000026 },
    { 0x15, 0, 1, 0x7e7f8081 },     //  22
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ALL_1IP(ret,ip)      do{   \
    bpf_all_1ip[3].k = ip;                  \
    bpf_all_1ip[4].k = ip;                  \
    bpf_all_1ip[20].k = ip;                 \
    bpf_all_1ip[22].k = ip;                 \
    SET_BPF_FILTER(bpf_all_1ip,ret,"");     \
}while(0)

static struct sock_filter bpf_udp[]    = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 5, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 6, 0, 0x00000011 },
    { 0x15, 0, 6, 0x0000002c },
    { 0x30, 0, 0, 0x00000036 },
    { 0x15, 3, 4, 0x00000011 },
    { 0x15, 0, 3, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 1, 0x00000011 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};

#define FILTER_ONLYUDP(ret)        do{          \
    SET_BPF_FILTER(bpf_udp,ret,"");             \
}while(0)



static struct sock_filter bpf_udp_1port[]    = {
    { 0x28, 0, 0, 0x0000000c },     //  0
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000011 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00001f90 },    //  5 端口号
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00001f90 },   //  端口号
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000011 },     //  10
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00001f90 },     //  15, 端口号
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00001f90 },     //  17,端口号
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ONLYUDP_1PORT(ret,port)      do{ \
    bpf_udp_1port[5].k = port;                  \
    bpf_udp_1port[7].k = port;                  \
    bpf_udp_1port[15].k = port;                 \
    bpf_udp_1port[17].k = port;                 \
    SET_BPF_FILTER(bpf_udp_1port,ret,"");       \
}while(0)

static struct sock_filter bpf_udp_1ip[]    = {
    { 0x28, 0, 0, 0x0000000c },     //  0
    { 0x15, 8, 0, 0x000086dd },
    { 0x15, 0, 7, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 5, 0x00000011 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 2, 0, 0x7f808182 },     //  6, ip
    { 0x20, 0, 0, 0x0000001e },
    { 0x15, 0, 1, 0x7f808182 },     //  8,ip
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ONLYUDP_1IP(ret,ip)      do{ \
    bpf_udp_1ip[6].k = ip;                  \
    bpf_udp_1ip[8].k = ip;                  \
    SET_BPF_FILTER(bpf_udp_1ip,ret,"");     \
}while(0)

static struct sock_filter bpf_tcp[]    = {
    { 0x28, 0, 0, 0x0000000c },     //  0
    { 0x15, 0, 10, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 5, 0x00000006 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 19, 0, 0x00000016 },    //  5
    { 0x15, 18, 0, 0x00000017 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 16, 14, 0x00000016 },
    { 0x15, 0, 15, 0x0000002c },
    { 0x30, 0, 0, 0x00000036 },     //  10
    { 0x15, 12, 13, 0x00000006 },
    { 0x15, 0, 12, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 10, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },     //  15
    { 0x45, 7, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 5, 0, 0x00000016 },
    { 0x15, 4, 0, 0x00000017 },     //  20
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 2, 0, 0x00000016 },
    { 0x15, 1, 0, 0x00000017 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }       //  25
};

#define FILTER_ONLYTCP(ret)        do{          \
    SET_BPF_FILTER(bpf_tcp,ret,"");             \
}while(0)

static struct sock_filter bpf_tcp_1port[]    = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000006 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00000050 },     // 5
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00000050 },    // 7
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000050 },      // 15
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000050 },      // 17
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ONLYTCP_1PORT(ret,port)      do{ \
    bpf_tcp_1port[5].k = port;                  \
    bpf_tcp_1port[7].k = port;                  \
    bpf_tcp_1port[15].k = port;                 \
    bpf_tcp_1port[17].k = port;                 \
    SET_BPF_FILTER(bpf_tcp_1port,ret,"");       \
}while(0)

static struct sock_filter bpf_tcp_1ip[]    = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 16, 0x00000800 },
    { 0x20, 0, 0, 0x0000001a },
    { 0x15, 2, 0, 0x7e7f8081 },     //  3
    { 0x20, 0, 0, 0x0000001e },
    { 0x15, 0, 12, 0x7e7f8081 },    //  5
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 10, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 7, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 5, 0, 0x00000016 },
    { 0x15, 4, 0, 0x00000017 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 2, 0, 0x00000016 },
    { 0x15, 1, 0, 0x00000017 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 }
};
#define FILTER_ONLYTCP_1IP(ret,ip)      do{ \
    bpf_tcp_1ip[3].k = ip;                  \
    bpf_tcp_1ip[5].k = ip;                  \
    SET_BPF_FILTER(bpf_tcp_1ip,ret,"");     \
}while(0)





static inline int filter_is_limitone(int protoallow, const struct filter_ctl *pctl)
{
    if( !protoallow )
        return 0;

    if( !FILTER_MODE_IS_ALLOW(pctl->mode))
        return -1;

    if( pctl->excsrc 
            && ( pctl->excsrc[0].val == 0 
                || pctl->excsrc[1].val != 0) ){
        return -1;
    }

    if( pctl->excdst 
            && ( pctl->excdst[0].val == 0 
                || pctl->excdst[1].val != 0 ) ){
        return -1;
    }

    //  到这里,只允许源
    if( !pctl->excsrc )
        return pctl->excdst[0].val;

    if( !pctl->excdst )
        return pctl->excsrc[0].val;

    if( pctl->excdst[0].val == pctl->excsrc[0].val )
        return pctl->excsrc[0].val;

    return -1;
}

/*  获取 允许的udp唯一端口号
 *  如果没有返回 0
 *  如果有多个返回 -1
 *  如果只有一个返回端口号
 */
static int get_udp_limit_1port(const struct SFilterCtl *filter)
{
    return filter_is_limitone(filter->protoallow[EUDPProto],&filter->udp);
}

static int get_tcp_limit_1port(const struct SFilterCtl *filter)
{
    return filter_is_limitone(filter->protoallow[ETCPProto],&filter->tcp);
}

static uint32_t get_ip_limit_1addr(const struct SFilterCtl *filter)
{
    return (uint32_t)filter_is_limitone(filter->protoallow[EIPProto],&filter->ip);
}

/*  判断过滤方式
 *  返回:
 *      -1  只过滤远程端口
 *      1   过滤ip
 *      2   过滤udp端口
 *      3   过滤tcp端口
 */
static int getlimittype(int allowudpport,int allowtcpport,uint32_t allowipaddr)
{
    //  先看是否可以通过 端口过滤,这样可以减少大量报文
    if( allowudpport != -1 && allowtcpport != -1 ){
        if( allowudpport == 0 )
            return 3;

        if( allowtcpport == 0 )
            return  2;

        if( allowtcpport == allowudpport )
            return 2;
    }

    //  如果不行,那判断是否可以通过 ip过滤
    if( allowipaddr > 0 && allowipaddr != (uint32_t) -1)
        return 1;

    return -1;
}

int SFilter_setBPF(const struct SFilterCtl *filter,int sd,int frametype)
{
    int allowudpport    = get_udp_limit_1port(filter);
    int allowtcpport    = get_tcp_limit_1port(filter);
    uint32_t allowipaddr= get_ip_limit_1addr(filter);
    int limittype       = getlimittype(allowudpport,allowtcpport,allowipaddr);
    int ret             = 0;
    int i               = 0;
    int protocnt        = 0;

    if( filter->remote ){
        return 0;
    }

    //  判断是否只允许 tcp/udp单协议
    for( ; i < ELastProto ; i ++ ){
        protocnt        += filter->protoallow[i];
    }

    if( protocnt == 1 ){
        if( filter->protoallow[EUDPProto] == 1){
            if( allowudpport > 0 ){
                FILTER_ONLYUDP_1PORT(ret,allowudpport);
                PRN_MSG("filter set udp filter port %d ret %d\n",allowudpport,ret);
            }
            else if( allowipaddr > 0 && allowipaddr != (uint32_t)-1 ){
                FILTER_ONLYUDP_1IP(ret,allowipaddr);
                PRN_MSG("filter set udp filter ip 0x%x ret %d\n",allowipaddr,ret);
            }
            else{
                FILTER_ONLYUDP(ret);
                PRN_MSG("filter set udp proto filter ret %d\n",ret);                
            }

            return ret;
        }

        if( filter->protoallow[ETCPProto] == 1){
            if( allowtcpport > 0 ){
                FILTER_ONLYTCP_1PORT(ret,allowtcpport);
                PRN_MSG("filter set tcp filter port %d ret %d\n",allowtcpport,ret);
            }
            else if( allowipaddr > 0 && allowipaddr != (uint32_t)-1 ){
                FILTER_ONLYTCP_1IP(ret,allowipaddr);
                PRN_MSG("filter set tcp filter ip 0x%x ret %d\n",allowipaddr,ret);
            }
            else{
                FILTER_ONLYTCP(ret);
                PRN_MSG("filter set tcp proto filter ret %d\n",ret);                
            }
            return ret;
        }
    }

    switch( limittype ){
        case 1:
            FILTER_ALL_1IP(ret,allowipaddr);
            PRN_MSG("filter ip  0x%x ret %d\n",allowipaddr,ret);
            break;

        case 2:
            FILTER_ALL_1PORT(ret,allowudpport);
            PRN_MSG("filter set port %d ret %d\n",allowudpport,ret);
            break;     

        case 3:
            FILTER_ALL_1PORT(ret,allowtcpport);
            PRN_MSG("filter set port %d ret %d\n",allowtcpport,ret);
            break;    

        default:
            FILTER_ALL(ret);
            PRN_MSG("filter remote port 22|23 ret %d\n",ret);
            break;
    }

    return ret;
}

#if 0
static int eth_proto_filter_allow1(int sd,int frametype)
{
    //  过滤语法为BPF格式,由tcpdump -dd ether proto 0x9090生成
    struct sock_fprog  filter;
    struct sock_filter code[]=
    {
        { 0x28, 0, 0, 0x0000000c }, // 判断位置
        { 0x15, 0, 1, frametype },    // 条件true时动作?
        { 0x6, 0, 0,  8000  },      // 注意：tcpdump生成的语法这里的长度偏小，这里改大成8000 byte保证返回整个以太网帧
        { 0x6, 0, 0,  0     },      // false时返回的长度
    };

    if( frametype == 0 )
        return -1;

    //  向内核注册BPF过滤器
    filter.len      = 4;
    filter.filter   = code;

    if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
        return 0;

    PRN_MSG("(%d) err[%d],skip\n",frametype,errno);
    return -1;
}

static int eth_proto_filter_allow2(int sd,
        int frametype1,
        int frametype2)
{
    //  过滤语法为BPF格式,由tcpdump -dd ether proto 0x9090生成
    struct sock_fprog  filter;
    struct sock_filter code[]=
    {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 1, 0, frametype1 },
        { 0x15, 0, 1, frametype2 },
        { 0x6, 0, 0, 0x00000060 },
        { 0x6, 0, 0, 0x00000000 },
    };

    if( frametype1 == 0 || frametype2 == 0)
        return -1;

    //  向内核注册BPF过滤器
    filter.len      = 5;
    filter.filter   = code;

    if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
        return 0;

    PRN_MSG("(%d,%d) err[%d],skip\n",frametype1,frametype2,errno);
    return -1;
}

static int ip_proto_filter_allow1(int sd,int type)
{
    //  过滤语法为BPF格式,由tcpdump -dd ether proto 0x9090生成
    struct sock_fprog  filter;

    if( type == 0 )
        return -1;

    if( type == IPPROTO_IGMP ){        //  IGMP类型
        struct sock_filter code[]=
        {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 3, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 1, 0x00000002 },
            { 0x6, 0, 0, 0x00001000 },
            { 0x6, 0, 0, 0x00000000 },
        };

        //  向内核注册BPF过滤器
        filter.len      = 6;
        filter.filter   = code;

        if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
            return 0;
    }
    else{       //  TCP/UDP
        struct sock_filter code[]=
        {
            { 0x28, 0, 0, 0x0000000c },
            { 0x15, 0, 2, 0x000086dd },
            { 0x30, 0, 0, 0x00000014 },
            { 0x15, 3, 4, type},
            { 0x15, 0, 3, 0x00000800 },
            { 0x30, 0, 0, 0x00000017 },
            { 0x15, 0, 1, type},
            { 0x6, 0, 0, 0x00002710 },
            { 0x6, 0, 0, 0x00000000 },
        };

        //  向内核注册BPF过滤器
        filter.len      = 9;
        filter.filter   = code;

        if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
            return 0;
    }

    PRN_MSG("(%d) err[%d],skip\n",type,errno);
    return -1;
}

static int ip_proto_filter_allow_igmp_and_other(int sd,int type)
{
    //  过滤语法为BPF格式,由tcpdump -dd ether proto 0x9090生成
    struct sock_fprog  filter;
    struct sock_filter code[]=
    {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 3, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 4, 0, 0x00000002 },
        { 0x15, 3, 4, type },
        { 0x15, 0, 3, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 1, type },
        { 0x6, 0, 0, 0x00001000 },
        { 0x6, 0, 0, 0x00000000 },

    };

    if( type == 0 )
        return -1;

    //  向内核注册BPF过滤器
    filter.len      = 10;
    filter.filter   = code;

    if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
        return 0;

    PRN_MSG("(%d) err[%d],skip\n",type,errno);
    return -1;
}

static int tcp_proto_deny_remote_ctrl(int sd)
{
    //  过滤语法为BPF格式,由tcpdump -dd tcp port not 22 and tcp port not 23生成
    struct sock_fprog  filter;
    struct sock_filter code[]=
    {
        { 0x28, 0, 0, 0x0000000c },
        { 0x15, 0, 7, 0x000086dd },
        { 0x30, 0, 0, 0x00000014 },
        { 0x15, 0, 18, 0x00000006 },
        { 0x28, 0, 0, 0x00000036 },
        { 0x15, 15, 0, 0x00000016 },
        { 0x15, 14, 0, 0x00000017 },
        { 0x28, 0, 0, 0x00000038 },
        { 0x15, 12, 11, 0x00000016 },
        { 0x15, 0, 12, 0x00000800 },
        { 0x30, 0, 0, 0x00000017 },
        { 0x15, 0, 10, 0x00000006 },
        { 0x28, 0, 0, 0x00000014 },
        { 0x45, 8, 0, 0x00001fff },
        { 0xb1, 0, 0, 0x0000000e },
        { 0x48, 0, 0, 0x0000000e },
        { 0x15, 4, 0, 0x00000016 },
        { 0x15, 3, 0, 0x00000017 },
        { 0x48, 0, 0, 0x00000010 },
        { 0x15, 1, 0, 0x00000016 },
        { 0x15, 0, 1, 0x00000017 },
        { 0x6, 0, 0, 0x00000000 },
        { 0x6, 0, 0, 0x00040000 },
    };

    //  向内核注册BPF过滤器
    filter.len      = 23;
    filter.filter   = code;

    if( setsockopt(sd, SOL_SOCKET, SO_ATTACH_FILTER, &filter, sizeof(filter)) == 0 )
        return 0;

    PRN_MSG(" err[%d],skip\n",errno);
    return -1;
}

#endif
