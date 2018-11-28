#ifndef SNIFF_H_
#define SNIFF_H_

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

//  调试打印函数
#define PRN_MSG(fmt,arg...)     printf("%s:%d " fmt "\n",__func__,__LINE__,##arg)
#define DBG_ECHO(fmt,arg...)    //  PRN_MSG(fmt,##arg)



#define PER_PACKET_SIZE             (8192)  //  pcap 文件中每个包的最大大小
#define ETH_MTU_MAX                 (8192)  //  认为网卡合法的 MTU 大小,暂定为大于1540
#define DEFAULT_MMAP_QLEN           20000   //  默认的mmap队列长度
#define DEFAULT_ETH_FRAMETYPE       0xffff  //  默认以太网帧类型

#ifndef TRUE
#define TRUE                    1
#define FALSE                   0
#endif

#define UDP_IGNORE_LIST         {137, 138,0}
#define TCP_IGNORE_LIST         {137,138,139,3389,0}

   
enum EOptMode{
    EOptModeDef = 0,
    EOptModeLimit,
    EOptModeFull
};

/*  接收到的帧信息
 */
struct EthFrameInfo{
    struct timeval              *ts;        /*  帧接收时间                  */
    struct ethhdr*      heth;
    uint16_t            framesize;
    uint16_t            ethproto;

    struct iphdr*       hip;
    union {
        struct tcphdr   *htcp;
        struct udphdr   *hudp;
    };

    uint32_t            saddr;
    uint32_t            daddr;
    uint16_t            sport;
    uint16_t            dport;
    uint16_t            mapport;

    uint8_t             *data;
    size_t              datalen;
};




struct SniffDevCtl;
typedef int (*SNIFFDEV_READ_CALLBACK)(
            struct SniffDevCtl  *ptCtl);
typedef int (*SNIFFDEV_POSTREAD_CALLBACK)(
            struct SniffDevCtl  *ptCtl);
typedef int (*SNIFFDEV_RELEASE_CALLBACK)(
            struct SniffDevCtl  *ptCtl);

struct SniffDevCtl{
    struct SFilterCtl           *ptFilter;    /*  过滤器句柄                  */
    SNIFFDEV_READ_CALLBACK      readframe;  /*  读一个网卡帧                */
    SNIFFDEV_POSTREAD_CALLBACK  postread;   /*  用完后对网卡帧做其它操作    */
    SNIFFDEV_RELEASE_CALLBACK   release;    /*  释放                        */

    struct EthFrameInfo         tEthFrame;   /*  接收到的帧，readframe中赋值   */

    void                        *priv;      /*  回调函数使用的私有数据      */
};


int PCapDev_Init(struct SniffDevCtl *ptCtl,const char *capfilename);
int PCapOutput_Init(const char *outfilename);

int SFilter_Init(void);
void SFilter_Release();
int SFilter_Analyse(char opcode,const char *optarg);
int SFilter_Validate( unsigned short *pframetype);
int SFilter_setBPF(int sd,int frametype);
uint16_t SFilter_MapPort(uint16_t port);
int SFilter_GetBPFInfo(uint16_t *remote,uint16_t *ethframe,uint32_t *ipaddr,uint16_t *udpport,uint16_t *tcpport);

int SFilter_IsDeny(struct EthFrameInfo *ptEthFrame);

void TcpipParser_SetParam(char opcode,const char *optarg);
void TcpipParser_ResetFrame(struct EthFrameInfo *ptFrame);
int TcpipParser_SetFrame(struct EthFrameInfo *ptframe);

int EthCapDev_Init(struct SniffDevCtl *ptCtl,const char *devname,
        int promisc,int mmapqnum,
        unsigned short frametype);


#endif

