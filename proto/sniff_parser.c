/*
 * =====================================================================================
 *
 *       Filename:  sniff_parser.c
 *
 *    Description:  处理器,使用链表方式,每个节点进行一个操作
 *
 * =====================================================================================
 */
#include <string.h>

#include "sniff_error.h"
#include "sniff.h"
#include "sniff_conf.h"
#include "sniff_parser.h"
#include "proto_pub.h"





struct SniffParseItem{

    SNIFFPARSER_PARSE_CALLBACK      parser;
    SNIFFPARSER_RELEASE_CALLBACK    release;

    void                            *param;
};

static int                      s_dwParserNum;
static struct SniffParseItem    s_tParsers[MAX_PARSER_NUM];


static int  s_ucShowmode        = SNIFF_SHOWMODE_MATCH;
static char s_strMatchMode[SNIFF_MATCH_MAX];



int SnifParser_Init(const struct SniffConf *ptConf)
{
    int ret = 0;
    if( ptConf->strCapFileWr[0] ){
        ret = PCapOutput_Init(ptConf->strCapFileWr);
        if( ret != 0 ){
            PRN_MSG("create output filter %s fail,ret:%d\n",ptConf->strCapFileWr,ret);
        }
    }

    s_ucShowmode    = ptConf->ucShowmode;
    strncpy(s_strMatchMode,ptConf->strMatch,sizeof(s_strMatchMode)-1);

    if( ret == 0 
            && ptConf->ucShowmode != SNIFF_SHOWMODE_SILENT ){
        ret = ShowTime_Init(ptConf);
        if( ret != 0 ){
            PRN_MSG("create tcp filter fail,ret:%d\n",ret);
        }
    }

    if( ret == 0 
            && ptConf->ucShowmode != SNIFF_SHOWMODE_SILENT ){
        ret = TcpIpParser_Init(ptConf);
        if( ret != 0 ){
            PRN_MSG("create tcp filter fail,ret:%d\n",ret);
        }
    }

    return  ret;
}


int SnifParser_Exec(struct EthFrameInfo         *pEthFrame)
{
    int i   =0;
    struct SniffParseItem   *ptItem = s_tParsers;

    for( ; i < s_dwParserNum ; i ++,ptItem++ ) {
        if( ptItem->parser ) {
            ptItem->parser(ptItem->param,pEthFrame);
        }
    }
            

    return 0;
}


void SnifParser_ResetShow()
{
    INIT_SHOWBUF();
}

void SnifParser_Show()
{
    DUMP_SHOWBUF();
}

int SniffParser_Register(SNIFFPARSER_RELEASE_CALLBACK release,SNIFFPARSER_PARSE_CALLBACK parser, void *param)
{
    if( !parser )
        return ERRCODE_SNIFF_PARAMERR;

    if( s_dwParserNum >= MAX_PARSER_NUM - 1 )
        return ERRCODE_SNIFF_FULL;

    s_tParsers[s_dwParserNum].parser    = parser;
    s_tParsers[s_dwParserNum].release   = release;
    s_tParsers[s_dwParserNum].param     = param;
    s_dwParserNum   ++;

    return 0;
}

int SniffParser_Release()
{
    int i   = 0;
    for( ; i < s_dwParserNum ; i ++ ){
        if( s_tParsers[i].release ){
            s_tParsers[i].release(s_tParsers[i].param);
            s_tParsers[i].release   = NULL;
            s_tParsers[i].parser    = NULL;
        }
    }

    s_dwParserNum   = 0;

    return 0;
}

