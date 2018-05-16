
#define _GNU_SOURCE
#include <getopt.h>

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

#define FILTER_NAME_TIME                "TIME"
#define FILTER_NAME_PROTO               "PROTO"
#define FILTER_NAME_MAC                 "ETH"
#define FILTER_NAME_MAP                 "MAP"
#define FILTER_PROTOTOKEN_DATAOK        "DATAOK"
#define FILTER_PROTOTOKEN_VNCMODE       "VNC"
#define FILTER_PROTOTOKEN_REMOTE        "REMOTE"
#define FILTER_MACTOKEN_BCASTOK         "MacBcast"
#define FILTER_MAPTOKEN_VNCPORT         "VNCPORT"
#define FILTER_PROTOTOKEN_VNCMODE       "VNC"
#define FILTER_IPTOKEN_ADDR             "IP"
#define FILTER_TCPTOKEN_NAME            "TCP"
#define FILTER_UDPTOKEN_NAME            "UDP"



struct FilterInfo{
    const char*     name;
    int             global;
    enum EOptMode   status;
    void            (*init_callback)(struct FilterInfo *filter);
    void            (*release_callback)(struct FilterInfo *filter);

    int             (*set_callback)(struct FilterInfo *filter,const char* token,const char* param);
    int             (*validate_callback)(struct FilterInfo *filter);
    int             (*check_callback)(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
};

static void deffilter_init(struct FilterInfo *filter);
static void deffilter_release(struct FilterInfo *filter);

static int timefilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int timefilter_validate(struct FilterInfo *filter);
static int timefilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);

static int protofilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int protofilter_validate(struct FilterInfo *filter);
static int protofilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static int protofilter_getethframetype();
static int protofilter_getbpfinfo(uint16_t *remote,uint16_t *ethframe,uint32_t *ipaddr,uint16_t *udpport,uint16_t *tcpport);

static int macfilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int macfilter_validate(struct FilterInfo *filter);
static int macfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static void macfilter_release(struct FilterInfo *filter);

static int mapfilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int mapfilter_validate(struct FilterInfo *filter);
static int mapfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static uint16_t mapfilter_convport(uint16_t port);

static int ipfilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int ipfilter_validate(struct FilterInfo *filter);
static int ipfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static void ipfilter_release(struct FilterInfo *filter);
static int ipfilter_getuniq();

static int tcpfilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int tcpfilter_validate(struct FilterInfo *filter);
static int tcpfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static void tcpfilter_release(struct FilterInfo *filter);
static int tcpfilter_getuniq();

static int udpfilter_set(struct FilterInfo *filter,const char* token,const char* param);
static int udpfilter_validate(struct FilterInfo *filter);
static int udpfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe);
static void udpfilter_release(struct FilterInfo *filter);
static int udpfilter_getuniq();

//  same index with sFilters
enum EFilterItemIndex{
    EFilterItemTime = 0,
    EFilterItemProto,
    EFilterItemMac,
    EFilterItemMap,
    EFilterItemIp,
    EFilterItemTcp,
    EFilterItemUdp,
    EFilterItemMax
};

static struct FilterInfo   sFilters[] = {
    {FILTER_NAME_TIME,      1,  EOptModeDef,  NULL,   NULL,     
        timefilter_set,     timefilter_validate,        timefilter_check},
    {FILTER_NAME_PROTO,     1,  EOptModeDef,  NULL,   NULL,
        protofilter_set, protofilter_validate,          protofilter_check},
    {FILTER_NAME_MAC,       1,  EOptModeDef,  NULL,   macfilter_release,     
        macfilter_set,      macfilter_validate,         macfilter_check},
    {"MAP",     1,  EOptModeDef,  NULL,               NULL,
        mapfilter_set,      mapfilter_validate,         mapfilter_check},
    {"IP",      0,  EOptModeDef,  NULL,               ipfilter_release,
        ipfilter_set,     ipfilter_validate,            ipfilter_check},
    {"TCP",     0,   EOptModeDef, NULL,               tcpfilter_release,
        tcpfilter_set,     tcpfilter_validate,          tcpfilter_check},
    {"UDP",     0,  EOptModeDef,  NULL,               udpfilter_release,
        udpfilter_set,     udpfilter_validate,          udpfilter_check},
    {NULL,      0,  EOptModeDef,  NULL,               NULL,
        NULL,               NULL,                   NULL}
};

static void deffilter_init(struct FilterInfo *filter)
{
    filter->status  = EOptModeDef;
}

static void deffilter_release(struct FilterInfo *filter)
{
    filter->status  = EOptModeDef;
}




static struct FilterInfo* filter_get(enum EFilterItemIndex index)
{
    return index < EFilterItemMax? sFilters + index : NULL;
}

static int filter_set(const char *name,const char* token, const char* param)
{
    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name && strcmp(name,pfilter->name); pfilter ++ ){
    }

    if( pfilter->name != NULL && pfilter->set_callback ){
        return pfilter->set_callback(pfilter,token,param);
    }

    //  unsupport filter ignore
    return 0;
}

static int filter_validate()
{
    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name ; pfilter ++ ){
        if( pfilter->status == EOptModeLimit && pfilter->validate_callback ){
            int ret = pfilter->validate_callback(pfilter);
            if( ret != 0 )
                return ret;
        }
    }

    return 0;
}



int SFilter_Init()
{
    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name ; pfilter ++ ){
        if( pfilter->init_callback  ){
            pfilter->init_callback(pfilter);
        }
    }

    return 0;
}

void SFilter_Release()
{
    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name ; pfilter ++ ){
        if( pfilter->release_callback  && pfilter->status != EOptModeDef){
            pfilter->release_callback(pfilter);
            pfilter->status = EOptModeDef;
        }
    }

    return ;
}

static int proto_setdetail(const char* syntax)
{
    char    *pstr;
    char    *token;
    char    *param;
    char    *lasts;

    int     i   = 0;
    int     len;
    int     ret = 0;
    if( !syntax || !*syntax )
        return ERRCODE_SNIFF_SUCCESS;

    PRN_MSG("FILTER PARAM is:%s, if incorrect, use '' to quote the param\n",syntax);

    len         = strlen(syntax);
    pstr        = malloc(len+1);
    if( !pstr ) {
        perror("filter_setfilter malloc fail");
        return ERRCODE_SNIFF_NOMEM;
    }

    /*  语法:
     *  TCP,UDP,ARP,RARP,DALL
     */
    for( i = 0; i < len && *syntax ; i ++ ) {
        while(isspace(*syntax) )   syntax++;
        if( *syntax )
            pstr[i]    = toupper(*syntax++);
    }

    token   = strtok_r(pstr,"{",&lasts);
    if( !token ) {
        free(pstr);
        return ERRCODE_SNIFF_SUCCESS;
    }

    while( token ) {
        param   = strtok_r(NULL,"}",&lasts);
        if( !param ) {
            break;
        }

        printf(" ANALYSE %s-%s|\n",token,param);
        ret = filter_set(token,token,param);
        token   = strtok_r(NULL,"{",&lasts);
        if( ret != 0 )
            break;
    }

    free(pstr);

    return ret;
}


/** 
 * @brief 分析参数信息
 * 
 * @param filter    [out]   保存分析结果
 * @param opcode    [in]    参数名对应的内部编码, 对应SFilter_GetOptions返回值的option.val
 * @param optarg    [in]    参数值
 * 
 * @return  0:  成功
 *          -1: 参数错误
 *          -2: 不认识的参数
 */
int     SFilter_Analyse(char opcode,const char *optarg)
{
    int val;
    switch( opcode ) {
        case    SNIFF_OPCODE_PROTO:     //  协议类型
            return filter_set(FILTER_NAME_PROTO,FILTER_NAME_PROTO,optarg);
            break;

        case    SNIFF_OPCODE_FILTER:    //  协议中的具体过滤参数
            if( proto_setdetail(optarg) ){
                PRN_MSG("wrong filter syntax\n");
                return -1;
            }
            return 0;

        case    SNIFF_OPCODE_REMOTE:
            return filter_set(FILTER_NAME_PROTO,FILTER_PROTOTOKEN_REMOTE,optarg);
            break;

        case    SNIFF_OPCODE_BCAST:
            return filter_set(FILTER_NAME_MAC,FILTER_MACTOKEN_BCASTOK,optarg);
            break;

        case SNIFF_OPCODE_DATA:
            return filter_set(FILTER_NAME_PROTO,FILTER_PROTOTOKEN_DATAOK,optarg);
            break;

        case SNIFF_OPCODE_VNCOK:
            return filter_set(FILTER_NAME_PROTO,FILTER_PROTOTOKEN_VNCMODE,optarg);
            break;

        case SNIFF_OPCODE_VNCPORT:
            return filter_set(FILTER_NAME_MAP,FILTER_MAPTOKEN_VNCPORT,optarg);
            break;

        default:
            break;
    }

    PRN_MSG("opt:%c %s unknown\n",opcode,optarg);
    return -2;
}

int     SFilter_Validate(unsigned short *pframetype)
{
    if( pframetype  )   
        *pframetype = 0xffff;

    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name ; pfilter ++ ){
        if( pfilter->status == EOptModeLimit && pfilter->validate_callback){
            int ret = pfilter->validate_callback(pfilter);
            if( ret != 0 )
                return ret;
        }
    }

    if( pframetype  )   
        *pframetype = protofilter_getethframetype();

    return 0;
}



int SFilter_GetBPFInfo(uint16_t *remote,uint16_t *ethframe,uint32_t *ipaddr,uint16_t *udpport,uint16_t *tcpport)
{
    return protofilter_getbpfinfo(remote,ethframe,ipaddr,udpport,tcpport);
}

/** 
 * @brief 判断一个报文是否会被过滤
 * 
 * @param filter    [in]    过滤器句柄
 * @param data      [in]    接收到的以太网帧
 * @param len       [in]    以太网帧长度
 * 
 * @return  0:  不过滤
 *          1:  过滤
 */
int SFilter_IsDeny(struct EthFrameInfo *pEthFrame)
{
    int ret = 0;
    struct FilterInfo   *pfilter = sFilters;
    for( ; pfilter->name && pfilter->global ; pfilter ++ ){
        if( pfilter->status == EOptModeLimit && pfilter->check_callback ){
            ret = pfilter->check_callback(pfilter,pEthFrame);
            if( ret != 0 )
                return ret;
        }
    }

    if( pEthFrame->hip ){
        pfilter = &sFilters[EFilterItemIp];
        switch( pfilter->status ){
            case EOptModeFull:
                ret =  ERRCODE_SNIFF_IGNORE;
                break;

            case EOptModeLimit:
                if( pfilter->check_callback )
                    ret = pfilter->check_callback(pfilter,pEthFrame);
                break;

            default:
                break;
        }

        if( ret != 0 )
            return ret;

        if( pEthFrame->hip->protocol == IPPROTO_TCP && pEthFrame->htcp ){
            static const int tcpignorelist[] = TCP_IGNORE_LIST;
            const int *p = tcpignorelist;
            for( ; *p != 0 && *p != pEthFrame->mapport; p ++) ;
            if( *p == pEthFrame->mapport )
                return ERRCODE_SNIFF_IGNORE;

            pfilter = &sFilters[EFilterItemTcp];
        }
        else if( pEthFrame->hip->protocol == IPPROTO_UDP && pEthFrame->hudp ){
            static const int udpignorelist[] = UDP_IGNORE_LIST;
            const int *p = udpignorelist;
            for( ; *p != 0 && *p != pEthFrame->mapport; p ++) ;
            if( *p == pEthFrame->mapport )
                return ERRCODE_SNIFF_IGNORE;

            pfilter = &sFilters[EFilterItemUdp];
        }
    }


    if( !pfilter ){
        return 0;
    }

    switch( pfilter->status ){
        case EOptModeFull:
            ret =  ERRCODE_SNIFF_IGNORE;
            break;

        case EOptModeLimit:
            if( pfilter->check_callback )
                ret = pfilter->check_callback(pfilter,pEthFrame);
            break;

        default:
            break;
    }

    return ret;
}

uint16_t SFilter_MapPort(uint16_t port)
{
    return mapfilter_convport(port);
}






#define CORRECT_PROTO_FILTER(protoname,filtername)   do{     \
    if( filter->protoallow[protoname] \
            && !filter->filtername.excsrc && !filter->filtername.excdst   \
            && FILTER_MODE_IS_ALLOW(filter->filtername.mode )) {    \
        filter->protoallow[protoname]    = 0;   \
    }}while(0)

#define DUMP_MAC_FILTERITEMS(items,name)  do{    \
    if( items ){ union filter_item *pitem  = (items);         \
        while( pitem->mac[0] && pitem->mac[1] && pitem->mac[2] ){                \
            printf("\t " name ":%02x:%02x:%02x:%02x:%02x:%02x\n",   \
                    pitem->mac[0] , pitem->mac[1] , pitem->mac[2],  \
                    pitem->mac[3] , pitem->mac[4] , pitem->mac[5]); pitem ++; \
        }        }  }while(0)

#define DUMP_IP_FILTERITEMS(items,name)  do{    \
    if( items ){    union filter_item  *pitem  = (items);       \
        while( pitem->val ){                \
            char cache[16]  = "";   \
            printf("\t" name ":%s\n",ip2str(pitem->val,0,cache));   pitem ++;   \
        }        }  }while(0)

#define DUMP_INT_FILTERITEMS(items,name)  do{   \
    if( items ){    union filter_item  *pitem  = (items);       \
        while( pitem->val ){                \
            printf("\t" name ":%d\n",pitem->val);   pitem ++;   \
        }        }  }while(0)

#define DUMP_HEX_FILTERITEMS(items,name)  do{   \
    if( items ){    union filter_item  *pitem  = (items);       \
        while( pitem->val ){                \
            printf("\t" name ":%x\n",pitem->val);   pitem ++;   \
        }        }  }while(0)

const char *filtermode2str(int mode){
    switch(mode){
        case FILTER_MODE_DENY_OR:       return "DENY_OR";
        case FILTER_MODE_DENY_AND:      return "DENY_AND";
        case FILTER_MODE_ALLOW_OR:      return "ALLOW_OR";
        case FILTER_MODE_ALLOW_AND:     return "ALLOW_AND";
        default:                        return "UNKNOWN";
    }
}


static inline int comp_mac(const union filter_item  *pitem,const void *value)
{
    return memcmp(pitem->mac,(const unsigned char *)value,6) ? -1:0;
}

static inline int comp_uint(const union filter_item  *pitem,const void *value)
{
    return pitem->val == *(const uint32_t *)value ? 0:-1;
}
/** 
 * @brief 
 * 
 * @param pitem 
 * @param value 
 * @param int(*comp 
 * @param pitem 
 * @param value 
 * @param  
 * 
 * @return 0:   找到匹配项
 *          -1: 没找到匹配项
 */
static inline int find_match_item(
        const union filter_item  *pitem,
        const void *value,
        int (*comp)(const union filter_item  *pitem,const void *value)) 
{
    if( pitem ) {
        while( pitem->val ){
            if( !comp(pitem,value) )
                return 0;
            pitem ++;
        }
    }

    return -1;
}

static inline int is_filter(const struct filter_ctl *ctl,
        const void *srcval,const void *dstval,
        int (*comp)(const union filter_item  *pitem,const void *value))
{
    int src = find_match_item(ctl->excsrc,srcval,comp );
    int dst = find_match_item(ctl->excdst,dstval,comp );
    switch( ctl->mode ){
        case FILTER_MODE_ALLOW_OR:
            return (!src) || (!dst) ? 0:1;
        case FILTER_MODE_ALLOW_AND:
            return (!src) && (!dst) ? 0:1;
        case FILTER_MODE_DENY_OR:
            return (!src) || (!dst) ? 1:0;
        case FILTER_MODE_DENY_AND:
            return (!src) && (!dst) ? 1:0;
        default:
            return 0;
    }
}

static inline int is_filter_port(const struct filter_ctl *ctl,
        uint32_t sport,uint32_t dport,uint32_t mapport)
{
    if( sport < dport ){
        sport = mapport;
    }
    else{
        dport = mapport;
    }

    int src = find_match_item(ctl->excsrc,&sport,comp_uint );
    int dst = find_match_item(ctl->excsrc,&dport,comp_uint );
    switch( ctl->mode ){
        case FILTER_MODE_ALLOW_OR:
            return (!src) || (!dst) ? 0:1;
        case FILTER_MODE_ALLOW_AND:
            return (!src) && (!dst) ? 0:1;
        case FILTER_MODE_DENY_OR:
            return (!src) || (!dst) ? 1:0;
        case FILTER_MODE_DENY_AND:
            return (!src) && (!dst) ? 1:0;
        default:
            return 0;
    }
}








/*
 *  分析普通过滤语法
 */
struct NormalAnalyseCtl{
    int                     count;
    union filter_item       items[FILTER_MAX_ITEM];
};
#define COPY_TO_FILTER(filter,type,value)   do{ \
    if( value.count > 0 ){               \
        filter->type   = malloc(sizeof(filter->type[0])*(value.count+1));   \
        if( !filter->type ){    perror(" malloc");  return -1; }    \
        memcpy(filter->type,value.items,sizeof(filter->type[0])*(value.count)); \
        memset(&filter->type[value.count],0,sizeof(filter->type[0])); \
    }}while(0)
#define FREE_FILTER_ITEM(item)  do{                 \
    free((item)->excsrc); item->excsrc    = NULL;   \
    free((item)->excdst); item->excdst    = NULL;   \
    (item)->mode  = FILTER_MODE_DENY_OR;               \
}while(0)

static inline void set_filter_value(struct NormalAnalyseCtl *pctl,
        const char *val,
        int (*value_callback)(union filter_item *out,const char *val))
{
    if( pctl && pctl->count < FILTER_MAX_ITEM ) {
        if( !value_callback(
                    &pctl->items[pctl->count],
                    val ) ){
            pctl->count ++;
        }
    }
}

static int analyse_normal_filter(struct filter_ctl *pfilter,
        char* param,const char *keyword,
        int (*value_callback)(union filter_item *out,const char *val))
{
    char    *lasts      = NULL;
    char    *token      = strtok_r(param,",",&lasts);
    int     keywordlen  = strlen(keyword);

    struct NormalAnalyseCtl           allowsrc;
    struct NormalAnalyseCtl           denysrc;
    struct NormalAnalyseCtl           allowdst;
    struct NormalAnalyseCtl           denydst;
    int     filtermode  = -1;

    memset(&allowsrc,0,sizeof(allowsrc));
    memset(&denysrc,0,sizeof(denysrc));
    memset(&allowdst,0,sizeof(allowdst));
    memset(&denydst,0,sizeof(denydst));

    while( token ) {
        if( !strcmp(token,"DALL") ) {
            filtermode    = FILTER_MODE_ALLOW_OR;
        }
        else if( !strcmp(token,"ALL") ) {
            filtermode    = FILTER_MODE_DENY_OR;
        }
        else if( !strcmp(token,"DAND") ) {
            filtermode    = FILTER_MODE_DENY_AND;
        }
        else if( !strcmp(token,"AND") ) {
            filtermode    = FILTER_MODE_ALLOW_AND;
        }
        else{
            int issrc       = -1;
            if( (token[0] == 'S' || token[0] == 'D') ){
                issrc       = token[0] == 'S' ? 1:0;
                token       ++;
            }
            if( !memcmp(token,keyword,keywordlen) ){
                int forbit  = -1;
                switch( token[keywordlen] ){
                    case '!':   forbit  = 1;    break;
                    case '=':   forbit  = 0;    break;
                    default:                    break;
                }

                if( forbit != -1 ){
                    switch( issrc ){
                        case -1:
                        case 0:
                            set_filter_value(
                                    forbit ? &denydst : &allowdst,
                                    token + 1 + keywordlen ,value_callback);
                            if( !issrc )
                                break;
                        case 1:
                            set_filter_value(
                                    forbit ? &denysrc : &allowsrc,
                                    token + 1 + keywordlen ,value_callback);
                        default:
                            break;
                    }
                }
            }
        }

        token  = strtok_r(NULL,",",&lasts);
    }

    if( allowsrc.count == 0 && allowdst.count == 0 ){
        /*
         *  没有指定特别allow情况,认为是allow所有
         */
        if( filtermode != FILTER_MODE_DENY_AND )
            filtermode     = FILTER_MODE_DENY_OR;
    }
    else if( denysrc.count == 0 && denydst.count == 0 ){
        /*
         *  没有指定特别deny情况,认为是deny所有
         */
        if( filtermode != FILTER_MODE_ALLOW_AND )
            filtermode     = FILTER_MODE_ALLOW_OR;
    }

    if( filtermode == -1 ){
        filtermode     = FILTER_MODE_ALLOW_OR;
    }

    if( FILTER_MODE_IS_ALLOW(filtermode) ) {
        COPY_TO_FILTER(pfilter,excsrc,allowsrc);
        COPY_TO_FILTER(pfilter,excdst,allowdst);
    }
    else {
        COPY_TO_FILTER(pfilter,excsrc,denysrc);
        COPY_TO_FILTER(pfilter,excdst,denydst);
    }

    pfilter->mode = filtermode;
    return 0;
}

static int str2hex(char val)
{
    if (val >= '0' && val <= '9')
        return val - '0';
    else if (val >= 'A' && val <= 'F')
        return val - 'A'+10;
    else if (val >= 'a' && val <= 'f')
        return val - 'a'+10;
    else
        return 0;
}

static int analyse_mac_item(union filter_item *out,const char *val)
{
    if( strlen(val) != 17 )
        return -1;

    out->mac[0] = (str2hex(val[0])<<4 ) | str2hex(val[1]);
    out->mac[1] = (str2hex(val[3])<<4 ) | str2hex(val[4]);
    out->mac[2] = (str2hex(val[6])<<4 ) | str2hex(val[7]);
    out->mac[3] = (str2hex(val[9])<<4 ) | str2hex(val[10]);
    out->mac[4] = (str2hex(val[12])<<4 ) | str2hex(val[13]);
    out->mac[5] = (str2hex(val[15])<<4 ) | str2hex(val[16]);
    return 0;
}

static int analyse_ip_item(union filter_item *out,const char *val)
{
    return (out->val = htonl(inet_addr(val))) ? 0:-1;
}

static int analyse_port_item(union filter_item *out,const char *val)
{
    return (out->val = atoi(val)) ? 0 :-1;
}

static inline int filterctl_getuniq(const struct filter_ctl *pctl)
{
    if( !FILTER_MODE_IS_ALLOW(pctl->mode))
        return 0;

    if( pctl->excsrc 
            && ( pctl->excsrc[0].val == 0 
                || pctl->excsrc[1].val != 0) ){
        return 0;
    }

    if( pctl->excdst 
            && ( pctl->excdst[0].val == 0 
                || pctl->excdst[1].val != 0 ) ){
        return 0;
    }

    //  到这里,只允许源
    if( !pctl->excsrc )
        return pctl->excdst[0].val;

    if( !pctl->excdst )
        return pctl->excsrc[0].val;

    if( pctl->excdst[0].val == pctl->excsrc[0].val )
        return pctl->excsrc[0].val;

    return 0;
}

/*
 *  语法分析,
 *  语法形式
 *      名称{条件=[!]值,DALL}
 */




#if 0
/*
 *      分析mac过滤语法
 */
struct MacAnalyseCtl{
    int                     count;
    struct mac_filter_item  items[FILTER_MAX_ITEM];
};


static int analyse_eth_filter(struct mac_filter *mac_filter,char* param)
{
    char    *lasts;
    char    *token  = strtok_r(param,",",&lasts);

    MacAnalyseCtl           allowsrc;
    MacAnalyseCtl           denysrc;
    MacAnalyseCtl           allowdst;
    MacAnalyseCtl           denydst;
    int                     denyall     = 0;

    memset(&allowsrc,0,sizeof(allowsrc));
    memset(&denysrc,0,sizeof(denysrc));
    memset(&allowdst,0,sizeof(allowdst));
    memset(&denydst,0,sizeof(denydst));

    while( token ) {
        struct MacAnalyseCtl    *pctl   = NULL;
        int     issrc   = -1;

        if( !memcmp(token,"SMAC",4) ) {
            issrc       = 1;
            pctl        = allow ? allowsrc : denysrc;
        }
        else if( !memcmp(token,"DMAC",4) ) {
            issrc       = 0;
            pctl        = allow ? allowdst : denydst;
        }
        else if( !strcmp(token,"DALL") ) {
            denayall    = 1;
            issrc       = 2;
        }

        if( issrc == 0 || issrc ==1 ){
            switch( token[4] ) {
                case '!':   pctl    = issrc ? denysrc: denydst; break;
                case '=':   pctl    = issrc ? allowsrc: allowsrc; break;
                default:    break;
            }
        }

        if( pctl && pctl->count < FILTER_MAX_ITEM ) {
            unsigned char   *mac    = pctl->items[pctl->count].mac;
            if( 6 == sscanf(token+5,"%X:%X:%X:%X:%X:%X",
                        pctl->mac[0],pctl->mac[1],pctl->mac[2],
                        pctl->mac[3],pctl->mac[4],pctl->mac[5]) ){
                pctl->count ++;
            }
        }

        token  = strtok_r(NULL,",",&lasts);
    }

    if( denyall ) {
        COPY_TO_FILTER(mac_filter,excsrc,allowsrc);
        COPY_TO_FILTER(mac_filter,excdst,allowdst);
    }
    else {
        COPY_TO_FILTER(mac_filter,excsrc,denysrc);
        COPY_TO_FILTER(mac_filter,excdst,denydst);
    }
    mac_filter->denyall = denyall;
    return 0;
}

filter->protoallow
#endif


/*
 *      time range filter
 */
struct SFilterCtl_time{
    uint32_t                startsec;
    uint32_t                endsec;
};
static struct SFilterCtl_time  sFilterTime;



static int gettimeval(char* str,char seperator,int min, int max)
{
    int         val;
    char*       pstart  = NULL;
    if( !str || !*str )
        return -2;

    pstart  = strrchr(str,seperator);
    if( pstart )
        *pstart  ++  = 0;
    else
        pstart  = str;

    val     = strtoul(pstart,NULL,0);
    return( val >= min && val <= max ) ? val : -1;
}

static uint32_t str2time(char* str,uint32_t defval)
{
    int         val     = 0;
    time_t      cursec  = time(NULL);
    struct  tm  curtime;
    localtime_r(&cursec,&curtime);

    if( str ){
        while( *str && isspace(*str)) str ++;
    }

    if( !str || !str[0] || !isdigit(str[0])){
        return defval;
    }

    int step    = 0;    /*  list:
1:  year
2:  mon
3:  day
4:  hour
5:  min
6:  sec
*/
    char    *pnext =str;
    do{
        int val = atoi(pnext);
        while( isdigit(pnext[0]))    pnext++;

        switch( pnext[0] ){
            case '/':
            if( val > 1900 )
                step    = 1;
            else
                step    = 2;
            break;

            case ' ':
            step        = 3;
            break;

            case ':':
            if( step == 4 )
                step    = 5;
            else
                step    = 4;
            break;

            default:
            if( step == 5 )
                step    = 6;
            else
                step    = 4;
            break;
        }

        switch( step ){
            case 1:
                if( val > 1900 )
                    curtime.tm_year = val - 1900;
                break;

            case 2:
                val --;
                if( val >= 0 << val <= 11 )
                    curtime.tm_mon = val - 1;
                break;

            case 3:
                if( val >= 1 && val <= 31 )
                    curtime.tm_mday = val;
                break;

            case 4:
                if( val >= 0 && val <= 23 )
                    curtime.tm_hour = val;
                break;

            case 5:
                if( val >= 0 && val <= 59 )
                    curtime.tm_min  = val;
                break;

            case 6:
                if( val >= 0 && val <= 60 )
                    curtime.tm_sec  = val;
                break;
            default:
                break;
        }

        if( pnext[0] )
            pnext   ++;
    }while(pnext[0]);

    return mktime(&curtime);
}


static int timefilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    char  cache[256];
    char* pend  = NULL;
    token   = token;

    if( param ){
        while( *param && isspace(*param)) param ++;
    }

    if( !param || !param[0] )
        return 0;

    if( param[0] == '+' ){
        sFilterTime.startsec    = time(NULL);
        sFilterTime.endsec      = sFilterTime.startsec + atoi(param+1);
        filter->status  = EOptModeLimit;
        return 0;
    }

    if( param[0] == '-' && !strchr(param,':')){
        sFilterTime.endsec      = time(NULL);
        sFilterTime.startsec    = sFilterTime.endsec - atoi(param+1);
        filter->status  = EOptModeLimit;
        return 0;
    }

    if( !isdigit(param[0]) ){
        return ERRCODE_SNIFF_PARAMERR;
    }

    strncpy(cache,param,sizeof(cache)-1);
    cache[sizeof(cache)-1]  = 0;

    pend    = strchr(cache,'-');
    if( pend ){
        *pend ++ = 0;
    }
    sFilterTime.startsec   = str2time(cache,1);
    sFilterTime.endsec     = str2time(pend,0xffffffff);
    filter->status  = EOptModeLimit;
    return 0;
}

static int timefilter_validate(struct FilterInfo *filter)
{
    if( filter->status != EOptModeDef ){
        time_t      startsec     = sFilterTime.startsec;
        struct  tm  starttime;
        time_t      endsec     = sFilterTime.endsec;
        struct  tm  endtime;
        localtime_r(&startsec,&starttime);
        localtime_r(&endsec,&endtime);

        PRN_MSG("Time Range: %d/%02d/%02d %02d:%02d:%02d - %d/%02d/%02d %02d:%02d:%02d\n",
                starttime.tm_year + 1900,starttime.tm_mon +1,starttime.tm_mday,
                starttime.tm_hour,starttime.tm_min,starttime.tm_sec,
                endtime.tm_year + 1900,endtime.tm_mon +1,endtime.tm_mday,
                endtime.tm_hour,endtime.tm_min,endtime.tm_sec
               );
        if( sFilterTime.startsec >=  sFilterTime.endsec ){
            PRN_MSG("time range error\n");
            return ERRCODE_SNIFF_PARAMERR;
        }
    }

    return 0;
}

static int timefilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe)
{
    if( ethframe->ts->tv_sec < sFilterTime.startsec )
        return ERRCODE_SNIFF_IGNORE;
    if( ethframe->ts->tv_sec <= sFilterTime.endsec )
        return 0;

    return ERRCODE_SNIFF_STOP;
}





/*
 *      protocol filter
 */
struct SFilterCtl_Protocol{
    enum EOptMode           dataok;
    enum EOptMode           vnc;
    int                     remote;
    char                    protodeny[ELastProto]; /* 充许的协议 */
};

static struct SFilterCtl_Protocol   sFilterProto = {EOptModeDef,EOptModeDef};



static int protofilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    unsigned char   allow[ELastProto];
    int             allowcount      = 0;
    unsigned char   deny[ELastProto];    
    int             denycount       = 0;

    int             denyall         = -1;    /*  默认拒绝所有  */


    char            cache[256]  = "";
    char            *lasts      = NULL;

    int             i;

    if( !token || !param || !*param )
        return ERRCODE_SNIFF_SUCCESS;

    if( !strcmp(token,FILTER_PROTOTOKEN_DATAOK) ){
        int val     = strtoul(optarg,0,0);
        if( val >= EOptModeDef && val <= EOptModeFull ){
            sFilterProto.dataok   = val;
            if( sFilterProto.dataok != EOptModeDef )
                filter->status  = EOptModeLimit;

            PRN_MSG("dataok: %d\n",val);
        }

        return ERRCODE_SNIFF_PARAMERR;
    }

    if( !strcmp(token,FILTER_PROTOTOKEN_VNCMODE) ){
        int val     = strtoul(optarg,0,0);
        if( val < EOptModeDef || val > EOptModeFull ){
            return ERRCODE_SNIFF_PARAMERR;
        }

        sFilterProto.vnc   = val;
        if( sFilterProto.vnc != EOptModeDef ){
            filter->status  = EOptModeLimit;
            if( sFilterProto.vnc == EOptModeFull ){
                memset(sFilterProto.protodeny,1,sizeof(sFilterProto.protodeny ));
                sFilterProto.protodeny[EIPProto]    = 0;
                sFilterProto.protodeny[ETCPProto]   = 0;
            }

            PRN_MSG("vnc: %d\n",val);
        }

        return 0;
    }    

    if( !strcmp(token,FILTER_PROTOTOKEN_REMOTE) ){
        sFilterProto.remote     = 1;
        if( sFilterProto.vnc != EOptModeDef ){
            filter->status  = EOptModeLimit;
        }
        return 0;
    }

    if( strcmp(token,filter->name) )
        return 0;

    memset(allow,0,sizeof(allow));
    memset(deny,0,sizeof(deny));

    /*  语法:
     *  TCP,UDP,ARP,RARP,DALL
     */
    for( i = 0; i < sizeof(cache)-1 && *param ; i ++ ) {
        while(isspace(*param) )   param++;
        if( *param )
            cache[i]    = toupper(*param++);
    }

    token   = strtok_r(cache,",",&lasts);
    while( token ) {
        unsigned char   *proto  = allow;
        int             *pcount = &allowcount;
        if( *token == '!' ) {
            proto   = deny ;
            pcount  = &denycount;
            token   ++;
        }

        (*pcount) ++;

        if( !strcmp("TCP",token) ) {
            if( proto  == allow )   proto[ETCPProto]    = 1;
        }
        else if( !strcmp("UDP",token) ) {
            if( proto  == allow )   proto[EUDPProto]    = 1;
        }
        else if( !strcmp("IGMP",token) ) {
            if( proto  == allow )   proto[EIGMPProto]   = 1;
        }
        else if( !strcmp("IP",token) ) {
            proto[EIPProto]     = 1;
        }
        else if( !strcmp("ARP",token) ) {
            proto[EARPProto]    = 1;
        }
        else if( !strcmp("RARP",token) ) {
            proto[ERARPProto]    = 1;
        }
        else if( !strcmp("DALL",token) ) {
            denyall    = 1;
        }
        else if( !strcmp("ALL",token) ) {
            denyall    = 0;
        }
        else{
            (*pcount) --;
        }


        token   = strtok_r(NULL,",",&lasts);
    }

    if( allowcount == 0 ){
        /*  如果没有指定充许通过的
            那将充许所有
            */
        denyall = 0;
    }
    else{
        if( denycount == 0 ){
            denyall = 1;
        }
    }

    if( denyall == -1 ){
        /*  
         *  如果指定了拒绝协议，也指定了充许协议
         *  并且没有指定DALL或是ALL，
         *  那默认为DALL
         */
        denyall = 1;
    }


    if( denyall ) {
        memset(sFilterProto.protodeny,1,sizeof(sFilterProto.protodeny ));
        if(  allow[EIPProto] || allow[ETCPProto] ||allow[EUDPProto] ||allow[EIGMPProto] )
            sFilterProto.protodeny[EIPProto]    = 0;
        if( allow[ETCPProto] )      sFilterProto.protodeny[ETCPProto]   = 0;
        if( allow[EUDPProto] )      sFilterProto.protodeny[EUDPProto]   = 0;
        if( allow[EIGMPProto] )     sFilterProto.protodeny[EIGMPProto]  = 0;

        if( allow[EARPProto] )      sFilterProto.protodeny[EARPProto]   = 0;
        if( allow[ERARPProto] )     sFilterProto.protodeny[ERARPProto]  = 0;
        sFilterProto.protodeny[EOtherProto]     = 1;
    }
    else {
        memset(sFilterProto.protodeny,0,sizeof(sFilterProto.protodeny ));
        if( deny[EIPProto] )        sFilterProto.protodeny[EIPProto]    = 1;
        if( deny[EIPProto] || deny[ETCPProto] )       sFilterProto.protodeny[ETCPProto]   = 1;
        if( deny[EIPProto] || deny[EUDPProto] )       sFilterProto.protodeny[EUDPProto]   = 1;
        if( deny[EIPProto] || deny[EIGMPProto] )      sFilterProto.protodeny[EIGMPProto]  = 1;

        if( deny[EARPProto] )       sFilterProto.protodeny[EARPProto]   = 1;
        if( deny[ERARPProto] )      sFilterProto.protodeny[ERARPProto]  = 1;
        sFilterProto.protodeny[EOtherProto]     = 0;
    }

    struct FilterInfo* pipfilter = filter_get(EFilterItemIp);
    struct FilterInfo* ptcpfilter = filter_get(EFilterItemTcp);
    struct FilterInfo* pudpfilter = filter_get(EFilterItemUdp);
    if( sFilterProto.protodeny[EIPProto] == 1 ){
        pipfilter->status  = EOptModeFull;
        ptcpfilter->status = EOptModeFull;
        pudpfilter->status = EOptModeFull;
    }
    else{
        if( sFilterProto.protodeny[ETCPProto] == 1 )
            ptcpfilter->status = EOptModeFull;
        if( sFilterProto.protodeny[EUDPProto] == 1 )
            pudpfilter->status = EOptModeFull;
    }

    filter->status  = EOptModeLimit;
    return 0;
}

const char* dataok2str(enum EOptMode type)
{
    switch( type ){
        case EOptModeLimit:    return "Proto";
        case EOptModeFull:     return "Data";
        default:                        break;
    }

    return "";
}

const char* vnc2str(enum EOptMode type)
{
    switch( type ){
        case EOptModeLimit:    return "NoVNC";
        case EOptModeFull:     return "OnlyVNC";
        default:                        break;
    }

    return "";
}

static int protofilter_validate(struct FilterInfo *filter)
{
    int i   = 0;
    struct FilterInfo* pipfilter = filter_get(EFilterItemIp);
    struct FilterInfo* ptcpfilter = filter_get(EFilterItemTcp);
    struct FilterInfo* pudpfilter = filter_get(EFilterItemUdp);
    if( sFilterProto.vnc == EOptModeFull ){
        pudpfilter->status      = EOptModeFull;
        sFilterProto.protodeny[EIPProto]   = 0;
        sFilterProto.protodeny[ETCPProto]  = 0;
        sFilterProto.protodeny[EUDPProto]  = 1;
    }

    if( pipfilter->status  == EOptModeFull ){
        sFilterProto.protodeny[EIPProto]   = 1;
        sFilterProto.protodeny[ETCPProto]  = 1;
        sFilterProto.protodeny[EUDPProto]  = 1;
    }
    else{
        if( ptcpfilter->status == EOptModeFull )
            sFilterProto.protodeny[ETCPProto]  = 1;
        if( pudpfilter->status == EOptModeFull )
            sFilterProto.protodeny[EUDPProto]  = 1;
    }

    for( i = 0; i < ELastProto && sFilterProto.protodeny[i]; i ++ ) 
        ;

    if( i == ELastProto ){
        PRN_MSG("error: no proto allow,exit\n");
        return ERRCODE_SNIFF_PARAMERR;
    }


    printf("PROTOCOL: ALLOW  %s%s%s%s%s%s%s %s %s %s\n",
            sFilterProto.protodeny[EIPProto] == 0?"IP ":"",
            sFilterProto.protodeny[ETCPProto] == 0?"TCP ":"",
            sFilterProto.protodeny[EUDPProto] == 0?"UDP ":"",
            sFilterProto.protodeny[EARPProto] == 0?"ARP ":"",
            sFilterProto.protodeny[ERARPProto] == 0?"RARP ":"",
            sFilterProto.protodeny[EIGMPProto] == 0?"IGMP ":"",
            sFilterProto.protodeny[EOtherProto] == 0?"OTHER ":"",
            dataok2str(sFilterProto.dataok),
            vnc2str(sFilterProto.vnc),
            sFilterProto.remote ? "Remote" : ""
          );

    return 0;
}

static int protofilter_getethframetype()
{
    if( sFilterProto.protodeny[EOtherProto] ==0 )
        return ETH_P_ALL;

    if( sFilterProto.protodeny[EIPProto] 
            + sFilterProto.protodeny[EARPProto] 
            + sFilterProto.protodeny[ERARPProto] < 2 )
    {
        return ETH_P_ALL;
    }

    if( sFilterProto.protodeny[EIPProto] ==0 )
        return ETH_P_IP;
    if( sFilterProto.protodeny[EARPProto] == 0)
        return ETH_P_ARP;
    if( sFilterProto.protodeny[ERARPProto] == 0)
        return ETH_P_RARP;

    return ETH_P_ALL;
}

static int protofilter_getbpfinfo(uint16_t *remote,uint16_t *ethframe,uint32_t *ipaddr,uint16_t *udpport,uint16_t *tcpport)
{
    *remote     = sFilterProto.remote;
    *ethframe   = ETH_P_ALL;
    *ipaddr     = 0;
    *udpport    = 0;
    *tcpport    = 0;

    if( (sFilterProto.protodeny[EOtherProto] == 0 ) )
        return 0;
    if( sFilterProto.protodeny[EIPProto] + sFilterProto.protodeny[EARPProto] + sFilterProto.protodeny[ERARPProto] < 2 )
        return 0;

    if( sFilterProto.protodeny[EARPProto]  == 0 ){
        *ethframe   = ETH_P_ARP;
        return 0;
    }

    if( sFilterProto.protodeny[ERARPProto]  == 0 ){
        *ethframe   = ETH_P_RARP;
        return 0;
    }

    uint32_t val    = ipfilter_getuniq();
    if( val != 0 )
        *ipaddr     = val;

    if( sFilterProto.protodeny[EIGMPProto] + sFilterProto.protodeny[ETCPProto] + sFilterProto.protodeny[EUDPProto] < 2 ){
        *ethframe   = ETH_P_IP;
        return 0;
    }

    if( sFilterProto.protodeny[EIGMPProto]  == 0 )
        return 0;


    if( sFilterProto.protodeny[ETCPProto] == 0){
        if( sFilterProto.remote == 0 ){
            val     = tcpfilter_getuniq();
            if( val != 0 )
                *tcpport = val;
        }
        return ETCPProto;
    }

    if( sFilterProto.protodeny[EUDPProto] == 0){
        val         = udpfilter_getuniq();
        if( val != 0 )
            *udpport = val;
        return EUDPProto;
    }

    return 0;
}

static int protofilter_isallowproto(enum EProtoNum proto)
{
    return proto < ELastProto && sFilterProto.protodeny[proto] == 0 ? 1 : 0;
}
static int protofilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe)
{
    int     ret = 0;
    switch( ethframe->ethproto ){
        case ETH_P_IP:
            if( sFilterProto.protodeny[EIPProto] != 0 || !ethframe->hip ){
                ret = ERRCODE_SNIFF_IGNORE;
            }
            break;


        case ETH_P_ARP:
            ret = sFilterProto.protodeny[EARPProto] != 0 ? ERRCODE_SNIFF_IGNORE: 0;
            break;

        case ETH_P_RARP: 
            ret = sFilterProto.protodeny[ERARPProto] != 0 ? ERRCODE_SNIFF_IGNORE: 0;
            break;

        default:
            ret = sFilterProto.protodeny[EOtherProto] != 0 ? ERRCODE_SNIFF_IGNORE: 0;
            break;
    }

    if( ret != 0 ){
        DBG_ECHO("ignore disable eth 0x%04x pkg\n",ethframe->ethproto);
        return ret;
    }

    if( ethframe->ethproto != ETH_P_IP ){
        return 0;
    }
    switch( ethframe->hip->protocol ) {
        case IPPROTO_TCP:
            if( sFilterProto.protodeny[ETCPProto] != 0 )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        case IPPROTO_UDP:
            if( sFilterProto.protodeny[EUDPProto] != 0 )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        case IPPROTO_IGMP:
            if( sFilterProto.protodeny[EIGMPProto] != 0 )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        default:
            break;
    }
    if( ret != 0 ){
        DBG_ECHO("ignore disable ip prot 0x%04x pkg\n",ethframe->hip->protocol);
        return ret;
    }

    if( !sFilterProto.remote && (ethframe->hip->protocol == IPPROTO_TCP) ){
        if( ethframe->mapport == 22 || ethframe->mapport == 23 )
            return ERRCODE_SNIFF_IGNORE;
    }

    int isvnc   = (ethframe->hip->protocol == IPPROTO_TCP) && (CFG_IS_VNCPORT(ethframe->mapport));
    switch( sFilterProto.vnc ){
        case EOptModeLimit:
            if( isvnc )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        case EOptModeFull:
            if( !isvnc )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        default:
            break;
    }
    if( ret != 0 ){
        DBG_ECHO("ignore port %d pkg by vnc rule %d/%d\n",ethframe->mapport,sFilterProto.vnc,isvnc);
        return ret;
    }
    switch( sFilterProto.dataok ){
        case EOptModeLimit:
            if( ethframe->datalen > 0 )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        case EOptModeFull:
            if( ethframe->datalen == 0 )
                ret = ERRCODE_SNIFF_IGNORE;
            break;

        default:
            break;
    }
    if( ret != 0 ){
        DBG_ECHO("ignore datasz %d pkg by data rule %d\n",ethframe->datalen,sFilterProto.dataok);
        return ret;
    }
    return 0;
}


static void filterctl_release(struct FilterInfo *filter,struct filter_ctl *ctl)
{
    if( filter ) {
        FREE_FILTER_ITEM(ctl);
        filter->status  = EOptModeDef;
    }
}

/*
 *
 */
struct SFilterCtl_Mac {
    enum EOptMode           bcastok;
    struct filter_ctl       mac;
};

static struct SFilterCtl_Mac    sFilterMac  = {EOptModeDef};
/*
 *  token:  FILTER_MACTOKEN_BCASTOK         bcast mac
 */
static int macfilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    if( !token || !param )
        return ERRCODE_SNIFF_PARAMERR;

    while( isspace(*param) ) param ++;
    if( !*param )
        return 0;

    if( !strcmp(FILTER_MACTOKEN_BCASTOK,token) ){
        int val     = strtoul(param,0,0);
        if( val >= EOptModeDef && val <= EOptModeFull ){
            sFilterMac.bcastok  = val;
            if( sFilterMac.bcastok != EOptModeDef )
                filter->status  = EOptModeLimit;
            return 0;
        }

        return ERRCODE_SNIFF_PARAMERR;
    }

    if( !strcmp(filter->name,token) ){
        char *cache = strdup(param);
        int ret = analyse_normal_filter(&sFilterMac.mac,cache,"MAC",analyse_mac_item);
        free(cache);

        if( ret == 0 )
            filter->status    = EOptModeLimit;
        return ret;
    }

    return 0;
}

static int macfilter_validate(struct FilterInfo *filter)
{
    if( !sFilterMac.mac.excsrc && !sFilterMac.mac.excdst ) {
        if( FILTER_MODE_IS_ALLOW(sFilterMac.mac.mode) ) {
            PRN_MSG("wrong mac filter syntax,skip\n");
            return ERRCODE_SNIFF_PARAMERR;
        }
    }

    PRN_MSG("MAC BCast Stat: %d FILTER: %s :\n",
            sFilterMac.bcastok,
            filtermode2str(sFilterMac.mac.mode));
    DUMP_MAC_FILTERITEMS(sFilterMac.mac.excsrc,"SRC MAC");
    DUMP_MAC_FILTERITEMS(sFilterMac.mac.excdst,"DST MAC");
    return 0;
}

static int macfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *pEthFrame)
{
    if( sFilterMac.bcastok != EOptModeDef ){
        int isbc        = (memcmp(pEthFrame->heth->h_dest,"\xff\xff\xff\xff\xff\xff",6) == 0 )
            || (memcmp(pEthFrame->heth->h_dest,"\x1\x0\x5e",3) == 0) ;
        if( (isbc && ( sFilterMac.bcastok == EOptModeLimit ))
                || ((!isbc) && ( sFilterMac.bcastok == EOptModeFull ) ) ){
            DBG_ECHO("ignore broadcast\n");
            return ERRCODE_SNIFF_IGNORE;
        }
    }

    if( sFilterMac.mac.excsrc || sFilterMac.mac.excdst ){
        if( is_filter(&sFilterMac.mac,pEthFrame->heth->h_source,pEthFrame->heth->h_dest,comp_mac) ){
            DBG_ECHO("ignore special mac\n");
            return ERRCODE_SNIFF_IGNORE;
        }
    }

    return 0;
}

static void macfilter_release(struct FilterInfo *filter)
{
    filterctl_release(filter,&sFilterMac.mac);
    sFilterMac.bcastok  = EOptModeDef;

    return ;
}



struct SFilterCtl_Map {
    int     vncportstart;
};
static struct SFilterCtl_Map    sFilterMap  = {CFG_DEF_VNCPORT_START};

static int mapfilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    if( token && !strcmp(token,FILTER_MAPTOKEN_VNCPORT) ){
        int val     = strtoul(param,0,0);
        if( val > 0 && val != CFG_DEF_VNCPORT_START){
            sFilterMap.vncportstart = val;
            filter->status  = EOptModeLimit;
        }
    }
    return 0;
}

static int mapfilter_validate(struct FilterInfo *filter)
{
    if( sFilterMap.vncportstart != 0)
    PRN_MSG("VNC PORT: %d-%d -> %d-%d\n",
            CFG_DEF_VNCPORT_START,CFG_DEF_VNCPORT_START+CFG_DEF_VNCPORT_NUM,
            sFilterMap.vncportstart,sFilterMap.vncportstart+CFG_DEF_VNCPORT_NUM);
    return 0;
}

static int mapfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *ethframe)
{
    return 0;
}

static uint16_t mapfilter_convport(uint16_t port)
{
    if( sFilterMap.vncportstart != 0 
            && port >= sFilterMap.vncportstart
            && port <= sFilterMap.vncportstart + CFG_DEF_VNCPORT_NUM
      ){
        return port + CFG_DEF_VNCPORT_START - sFilterMap.vncportstart;
    }

    return port;
}


struct SFilterCtl_IP {
    struct filter_ctl       ip;
};

static struct SFilterCtl_IP    sFilterIp;

static int ipfilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    if(filter->status == EOptModeFull )
        return 0;

    if( !token || !param )
        return ERRCODE_SNIFF_PARAMERR;

    while( isspace(*param) ) param ++;
    if( !*param )
        return 0;

    if( !strcmp(FILTER_IPTOKEN_ADDR,token) ){
        char *cache = strdup(param);
        int ret = analyse_normal_filter(&sFilterIp.ip,cache,"ADDR",analyse_ip_item);
        free(cache);

        if( ret == 0 )
            filter->status  = EOptModeLimit;
        return ret;
    }

    return 0;
}

static int ipfilter_validate(struct FilterInfo *filter)
{
    if( !sFilterIp.ip.excsrc && !sFilterIp.ip.excdst ) {
        if( FILTER_MODE_IS_ALLOW(sFilterIp.ip.mode) ) {
            PRN_MSG("wrong ip filter syntax,skip\n");
            return ERRCODE_SNIFF_PARAMERR;
        }
    }

    printf("IP FILTER: %s :\n",
            filtermode2str(sFilterIp.ip.mode));
    DUMP_IP_FILTERITEMS(sFilterIp.ip.excsrc,"SRC IP");
    DUMP_IP_FILTERITEMS(sFilterIp.ip.excdst,"DST IP");
    return 0;
}

static int ipfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *pEthFrame)
{
    if( is_filter(&sFilterIp.ip,&pEthFrame->saddr,&pEthFrame->daddr,comp_uint) ){
        DBG_ECHO("ignore by ip %x %x\n",pEthFrame->saddr,pEthFrame->daddr);
        return ERRCODE_SNIFF_IGNORE;
    }
    return 0;
}

static void ipfilter_release(struct FilterInfo *filter)
{
    filterctl_release(filter,&sFilterIp.ip);
}

static int ipfilter_getuniq()
{
    return filterctl_getuniq(&sFilterIp.ip);
}

struct SFilterCtl_Tcp {
    struct filter_ctl       port;
};

static struct SFilterCtl_Tcp    sFilterTcp;

static int portfilter_set( struct FilterInfo *filter,struct filter_ctl *info,const char* token,const char* param)
{
    if(filter->status == EOptModeFull )
        return 0;

    if( !token || !param )
        return ERRCODE_SNIFF_PARAMERR;

    while( isspace(*param) ) param ++;
    if( !*param )
        return 0;

    if( !strcmp(filter->name,token) ){
        char *cache = strdup(param);
        int ret = analyse_normal_filter(info,cache,"PORT",analyse_port_item);
        free(cache);

        if( ret == 0 )
            filter->status  = EOptModeLimit;
        return ret;
    }

    return 0;
}

static int portfilter_validate(const char* name,
        struct FilterInfo *filter,struct filter_ctl *info)
{
    if( !info->excsrc && !info->excdst ) {
        if( FILTER_MODE_IS_ALLOW(info->mode) ) {
            PRN_MSG("wrong %s filter syntax,skip\n",name);
            return ERRCODE_SNIFF_PARAMERR;
        }
    }

    PRN_MSG("%s FILTER: %s :\n",name,
            filtermode2str(info->mode));
    DUMP_INT_FILTERITEMS(info->excsrc,"SRC PORT");
    DUMP_INT_FILTERITEMS(info->excdst,"DST PORT");
    return 0;
}

static int tcpfilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    if(filter->status == EOptModeFull )
        return 0;

    return portfilter_set(filter,&sFilterTcp.port,token,param);
}

static int tcpfilter_validate(struct FilterInfo *filter)
{
    int ret = portfilter_validate(filter->name,filter,&sFilterTcp.port);

    return ret;
}

static int tcpfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *pEthFrame)
{
    if( is_filter_port(&sFilterTcp.port,pEthFrame->sport,pEthFrame->dport,pEthFrame->mapport) ){
        DBG_ECHO("ignore tcp port %d->%d \n",pEthFrame->sport,pEthFrame->dport);
        return ERRCODE_SNIFF_IGNORE;
    }
    return 0;
}
static void tcpfilter_release(struct FilterInfo *filter)
{
    filterctl_release(filter,&sFilterTcp.port);
}

static int tcpfilter_getuniq()
{
    return filterctl_getuniq(&sFilterTcp.port);
}

struct SFilterCtl_Udp {
    struct filter_ctl       port;
};

static struct SFilterCtl_Udp    sFilterUdp;

static int udpfilter_set(struct FilterInfo *filter,const char* token,const char* param)
{
    return portfilter_set(filter,&sFilterUdp.port,token,param);
}

static int udpfilter_validate(struct FilterInfo *filter)
{
    return portfilter_validate(filter->name,filter,&sFilterUdp.port);
}
static int udpfilter_check(struct FilterInfo *filter,const struct EthFrameInfo *pEthFrame)
{
    if( is_filter_port(&sFilterUdp.port,pEthFrame->sport,pEthFrame->dport,pEthFrame->mapport) ){
        DBG_ECHO("ignore udp port %d->%d \n",pEthFrame->sport,pEthFrame->dport);
        return ERRCODE_SNIFF_IGNORE;
    }
    return 0;
}
static void udpfilter_release(struct FilterInfo *filter)
{
    filterctl_release(filter,&sFilterUdp.port);
}

static int udpfilter_getuniq()
{
    return filterctl_getuniq(&sFilterUdp.port);
}










