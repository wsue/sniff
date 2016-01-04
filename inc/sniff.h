#ifndef SNIFF_H_
#define SNIFF_H_

#include <stdio.h>
#include <stdint.h>
#include <sys/time.h>

//  调试打印函数
#define PRN_MSG(fmt,arg...)     printf("%s:%d " fmt "\n",__func__,__LINE__,##arg)
#define DBG_ECHO(fmt,arg...)    //  PRN_MSG(fmt,##arg)



#define PER_PACKET_SIZE             (2048)  //  pcap 文件中每个包的最大大小
#define ETH_MTU_MAX                 (1800)  //  认为网卡合法的 MTU 大小,暂定为大于1540
#define DEFAULT_MMAP_QLEN           200     //  默认的mmap队列长度
#define DEFAULT_ETH_FRAMETYPE       0xffff  //  默认以太网帧类型

#ifndef TRUE
#define TRUE                    1
#define FALSE                   0
#endif


/*  接收到的帧信息
 */
struct RcvFrameInfo{
    struct timeval              *ts;        /*  帧接收时间                  */
    char                        *buf;       /*  接收到的帧数据              */
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

    struct RcvFrameInfo         tRcvFrame;   /*  接收到的帧，readframe中赋值   */

    void                        *priv;      /*  回调函数使用的私有数据      */
};


int PCapDev_Init(struct SniffDevCtl *ptCtl,const char *capfilename);
int PCapOutput_Init(const char *outfilename);

struct SFilterCtl * SFilter_Init(void);
void SFilter_Release(struct SFilterCtl *filter);
int SFilter_Analyse(struct SFilterCtl *filter,char opcode,const char *optarg);
int SFilter_Validate(struct SFilterCtl *filter, unsigned short *pframetype);
int SFilter_setBPF(const struct SFilterCtl *filter,int sd,int frametype);
int SFilter_IsAllowTcpIp(const struct SFilterCtl *filter);

int SFilter_IsDeny(const struct SFilterCtl *filter,int vlanok,
        const unsigned char *data,int len);

#endif

