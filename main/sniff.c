
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "sniff_error.h"
#include "sniff_conf.h"
#include "sniff.h"
#include "sniff_parser.h"


static struct SniffDevCtl  s_tDevCtl;

static struct option sniff_options[] = {
    //  name        has arg[0 no 1 must 2 opt]  returnval  returncode
    //  输入/输出控制
    {"i",            1, 0, SNIFF_OPCODE_DEVNAME},
    {"r",            1, 0, SNIFF_OPCODE_RDCAPFILE},
    {"w",            1, 0, SNIFF_OPCODE_WRCAPFILE},

    {"p",            0, 0, SNIFF_OPCODE_PROMISC},

    {"f",            1, 0, SNIFF_OPCODE_MMAP_QLEN},
    {"c",            1, 0, SNIFF_OPCODE_CAPNUM},

    //  协议过滤机制
    {"P",            1, 0, SNIFF_OPCODE_PROTO},
    {"F",            1, 0, SNIFF_OPCODE_FILTER},
    {"remote",       0, 0, SNIFF_OPCODE_REMOTE},
    {"bcast",        1, 0, SNIFF_OPCODE_BCAST},
    {"data",         1, 0, SNIFF_OPCODE_DATA},
    {"tcpdata",      0, 0, SNIFF_OPCODE_TCPDATA},
    {"rmxdata",      0, 0, SNIFF_OPCODE_RMXDATA},
    {"vnc",          1, 0, SNIFF_OPCODE_VNCOK},
    {"vncstart",     1, 0, SNIFF_OPCODE_VNCPORT},

    //  显示控制
    {"alias",        1, 0, SNIFF_OPCODE_ALIAS},
    {"m",            1, 0, SNIFF_OPCODE_SHOWMATCH},
    {"M",            1, 0, SNIFF_OPCODE_SHOWNOMATCH},
    {"x",            0, 0, SNIFF_OPCODE_HEX},
    {"X",            0, 0, SNIFF_OPCODE_HEXALL},
    {"ttttt",        0, 0, SNIFF_OPCODE_RELATIMESTAMP},
    {"s",            0, 0, SNIFF_OPCODE_SILENT},
    {"eth",          0, 0, SNIFF_OPCODE_DECETH},

    {NULL,           0, 0,  0},
};


static void help(const char *appname)
{
    //  输入控制
    printf("%s : capture netcard's traffic and decode it, options include:\n",appname);
    printf("\tauth: mushuanli@163.com/lizlok@gmail.com\n");
    printf("\t-i     - ethname to sniff\n"
            "\t-r     - read sniff data from file\n"
            "\t-f     - set mmap buf frame count to fnum(def:200),0: disable mmap mode\n"
            "\t-p     - use promisc mode(default off)\n"
            "\t-c     - capture package count(default(0) not limit)\n");


    //  过滤功能
    printf("\n\t-P     - which protocol(default all) will be sniff?\n"
            "           protocol include: ARP,RARP,TCP,UDP,IGMP,DALL\n"
            "\t-F     - specialfy sniff filters(default allow all)\n"
            "\t         Filter syntax example:\n"
            "\t         ETH{SMAC=ff:fa:fb:fc:fd:fe,DMAC!ff:fa:fb:fc:fd:fe,DALL}\n"
            "\t         IP{SADDR=10.10.10.10,DADDR!10.20.30.40,DAND}\n"
            "\t         TCP{SPORT!80,DPORT=30,ALL}\n"
            "\t         UDP{SPORT!80,DPORT=30,AND}\n"
            "\t         TIME{[xxxx/xx/xx ]xx:xx:xx-[xxxx/xx/xx ]xx:xx:xx}\n"
            "\t         MAP{from[-to]:dstport}\n"
            "\t         'TCP{PORT=80,PORT=110}UDP{PORT=53}'\n"
            "\t         DALL allow only match (one condition) item\n"
            "\t         DAND deny match all condition item \n"
            "\t         ALL  only deny match (one condition) item\n"
            "\t         AND  only deny match (all condition) item\n"
            "\t-bcast - =[0|1|2] 0: capture all, 1: only capture unicast, 2: only capture bcast\n"
            "\t-data  - =[0|1|2] 0: capture all, 1: only capture proto,   1: only capture data\n"
            "\t-tcpdata  - only decode tcp data, don't decode tcp head\n"
            "\t-rmxdata  - only decode rmx data(unknow packet will dump hex), don't decode tcp head(tcpdata option) and ping/pong\n"
            "\t-vnc      - support all VNC port? (0: capture all, 1: skip all vnc, 2: only capture vnc) \n"
            "\t-vncstart=x - VNC port start from x\n"
            "\t-remote - capture remote control package(ignore TCP port 22/23)\n"
            "special keyword: DALL - deny all except spedial, ! - except, = - allow\n"
            "NOTE: the filter param should use '' to quote,else it won't correct send\n");

    //  显示控制
    printf("\n\t-m     - only show match record\n"
            "\t-M     - filter match record(don't show)\n"
            "\t-alias - ='name1=1.2.3.4,name2=5.6.7.8',show IP as alias\n"
            "\t-x     - use hex to decode frame\n"
            "\t-X     - use hex to decode all frame\n"
            "\t-w     - write capture result to filename\n"
            "\t-s     - silient mode(don't decode package to screen)\n"
            "\t-ttttt - Print a delta (micro-second resolution) between current and first line on each dump line.\n"
            "\t-eth   - show ether head\n"
            );

    return ;
}

/*  处理抓包流程,num != -1 时只抓 num 个包  */
static int ParseArgs(struct SniffConf *ptConf,int argc, char ** argv)
{
    int ret = 0;
    int c;
    opterr  = 0;

    memset(ptConf,0,sizeof(*ptConf));

    ret    = SFilter_Init();
    if( ret != 0) {
        return ret;
    }

    ptConf->wMmapQLen      = DEFAULT_MMAP_QLEN;
    ptConf->wEthFrameType   = DEFAULT_ETH_FRAMETYPE;

    while ( ret == 0 && (c = getopt_long_only(argc, argv, "i:r:f:pc:P:F:m:M:w:s", sniff_options, NULL)) != -1 ) {  
        switch ( c ) {  
            case SNIFF_OPCODE_DEVNAME:
                strncpy(ptConf->strEthname,optarg,sizeof(ptConf->strEthname)-1);
                break;

            case SNIFF_OPCODE_RDCAPFILE:
                strncpy(ptConf->strCapFileRd,optarg,sizeof(ptConf->strCapFileRd)-1);
                break;

            case SNIFF_OPCODE_WRCAPFILE:
                strncpy(ptConf->strCapFileWr,optarg,sizeof(ptConf->strCapFileWr)-1);
                break;

            case SNIFF_OPCODE_PROMISC:
                ptConf->bPromisc    = TRUE;
                break;

            case SNIFF_OPCODE_MMAP_QLEN:
                ptConf->wMmapQLen  = strtoul(optarg,NULL,0);
                break;

            case SNIFF_OPCODE_CAPNUM:
                ptConf->dwCapNum   = strtoul(optarg,NULL,0);
                break;

            case SNIFF_OPCODE_SHOWMATCH:
                ptConf->ucShowmode = SNIFF_SHOWMODE_MATCH;
                memset(ptConf->strMatch,0,sizeof(ptConf->strMatch));
                strncpy(ptConf->strMatch,optarg,sizeof(ptConf->strMatch)-1);
                break;

            case SNIFF_OPCODE_SHOWNOMATCH:
                ptConf->ucShowmode = SNIFF_SHOWMODE_UNMATCH;
                memset(ptConf->strMatch,0,sizeof(ptConf->strMatch));
                strncpy(ptConf->strMatch,optarg,sizeof(ptConf->strMatch)-1);
                break;

            case SNIFF_OPCODE_ALIAS:
                memset(ptConf->strAlias,0,sizeof(ptConf->strAlias));
                strncpy(ptConf->strAlias,optarg,sizeof(ptConf->strAlias)-1);
                break;

            case SNIFF_OPCODE_RELATIMESTAMP:
                ptConf->ucRelateTimestamp   = 1;
                break;

            case SNIFF_OPCODE_HEX:
                ptConf->ucDecHex   = SNIFF_HEX_UNKNOWNPKG;
                break;

            case SNIFF_OPCODE_HEXALL:
                ptConf->ucDecHex   = SNIFF_HEX_ALLPKG;
                break;


            case SNIFF_OPCODE_SILENT:
                ptConf->ucShowmode = SNIFF_SHOWMODE_SILENT;
                break;

            case SNIFF_OPCODE_DECETH:
                ptConf->bDecEth    = TRUE;
                break;

            case SNIFF_OPCODE_VNCPORT:
            case SNIFF_OPCODE_VNCOK:
            case SNIFF_OPCODE_PROTO:
            case SNIFF_OPCODE_FILTER:
            case SNIFF_OPCODE_REMOTE:
            case SNIFF_OPCODE_BCAST:
            case SNIFF_OPCODE_DATA:
                ret = SFilter_Analyse(c,optarg);
                if( ret != 0 ){
                    PRN_MSG("parse arg %c %s fail:%d, unsupport\n",c,optarg,ret);
                }
                break;

            case SNIFF_OPCODE_RMXDATA:
            case SNIFF_OPCODE_TCPDATA:
                ptConf->bOnlyTcpData = 1;
                if( c == SNIFF_OPCODE_RMXDATA ){
                    ptConf->bRMXOnlyData = 1;
                    ptConf->ucDecHex   = SNIFF_HEX_UNKNOWNPKG;
                }
                break;

            default:
                ret = 1;
                help(argv[0]);
                break;
        }

    }


    if( ret != 0 ){
        goto end;
    }

    //  检查参数是否符合运行条件
    //  ##  检查输入参数
    if( !ptConf->strEthname[0] && !ptConf->strCapFileRd[0] ){
        PRN_MSG("no input device/file, please use -i [ethname] or -r capfilename to special program input, -h for help\n");
        ret = ERRCODE_SNIFF_PARAMERR;
        goto end;
    }
    if( ptConf->strEthname[0] && ptConf->strCapFileRd[0] ){
        PRN_MSG("duplicate input device/file, only can use -i [ethname] or -r capfilename to special one program input, -h for help\n");
        ret = ERRCODE_SNIFF_PARAMERR;
        goto end;
    }

    //  ##  检查输出参数
    if( ptConf->ucShowmode == SNIFF_SHOWMODE_SILENT ) {
        if( !ptConf->strCapFileWr[0] ){
            PRN_MSG("no output device/file, please use -w [capfilename] to output to file or don't use -s , -h for help\n");
            ret = ERRCODE_SNIFF_PARAMERR;
            goto end;
        }

        ptConf->bDecEth = FALSE;
    }

    //  ##  检查过滤参数
    ret = SFilter_Validate(&ptConf->wEthFrameType);
    if( ret != 0 ){
        PRN_MSG("no output device/file, please use -w [capfilename] to output to file or don't use -s , -h for help\n");
        ret = ERRCODE_SNIFF_PARAMERR;
        goto end;
    }

end:
    if( ret != 0 ) {
        SFilter_Release();
    }

    return ret;
}


static int RecvEthFrame(struct SniffDevCtl *ptDev)
{
    TcpipParser_ResetFrame(&ptDev->tEthFrame);

    int len = ptDev->readframe(ptDev);
    if( len <= 0 )
        return len;
    else if( len < ETH_HLEN )
        return ERRCODE_SNIFF_BADFRAME;

    ptDev->tEthFrame.framesize   = len;
    int ret = TcpipParser_SetFrame(&ptDev->tEthFrame);
	return ret == 0 ? len : ret;
}

static void ReleaseClean()
{
    SniffParser_Release();

    if( s_tDevCtl.release ){
        s_tDevCtl.release(&s_tDevCtl);
        s_tDevCtl.release = NULL;
    }

    SFilter_Release( );
}

void sig_handler( int sig)
{
    if(sig == SIGINT){
        ReleaseClean();
        exit(1);
    }
}


static int Init(struct SniffDevCtl *ptDev,const struct SniffConf *ptConf)
{
    int ret = 0;
    memset(ptDev,0,sizeof(*ptDev));


    //  打开输入设备
    if( ptConf->strEthname[0] ){
        ret = EthCapDev_Init(ptDev,ptConf->strEthname,
                ptConf->bPromisc,ptConf->wMmapQLen,
                ptConf->wEthFrameType);
    }
    else{
        ret = PCapDev_Init(ptDev,ptConf->strCapFileRd);
    }

    if( ret != 0 ){
        PRN_MSG("init input %s fail, ret:%d\n",ptConf->strEthname[0]? ptConf->strEthname : ptConf->strCapFileRd,ret);
        return ret;
    }

    //  注册输出设备
    ret = SnifParser_Init(ptConf);
    if( ret != 0 ){
        PRN_MSG("init parser fail, ret:%d\n",ret);
    }
    return ret;
}


static int Run(struct SniffDevCtl *ptDev,const struct SniffConf *ptConf)
{
    int         ret     = 0;
    int         recvcnt = 0;
    do{
        SnifParser_ResetShow();
        int len = RecvEthFrame(ptDev);
        if( len < 0 ){
            ret = len;
            PRN_MSG("recv frame fail, ret:%d\n",ret);
            break;
        }
        else if( len == 0 ){
            break;
        }

        ret =  SFilter_IsDeny(&ptDev->tEthFrame);
        if( 0 == ret ){
            recvcnt ++;
            SnifParser_Exec(&ptDev->tEthFrame);
        }
        else if( ret != ERRCODE_SNIFF_IGNORE ){
            break;
        }
            
        SnifParser_Show();

        if( ptDev->postread )
            ret = ptDev->postread(ptDev);

    }while( ret == 0 && (ptConf->dwCapNum == 0 || recvcnt != ptConf->dwCapNum) );

    PRN_MSG("recv %d package, stop for err:%d\n",recvcnt,ret);
    return ret;
}

int main(int argc, char **argv)
{
    struct SniffConf tConf;
    int ret;

    printf("\tdeveloper: mushuanli@163.com|lizlok@gmail.com %s pid:%d\n",argv[0],getpid());
    
    memset(&tConf,0,sizeof(tConf));

    ret = ParseArgs(&tConf,argc,argv);
    if( ret != 0 ){
        return 1;
    }

    //  注册进程清除操作
    atexit(ReleaseClean);
    signal(SIGINT, sig_handler);

    ret = Init(&s_tDevCtl,&tConf);
    if( ret != 0 ){
        return 1;
    }

    ret = Run(&s_tDevCtl,&tConf);
    return ret;
}

