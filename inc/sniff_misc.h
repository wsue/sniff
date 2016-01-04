
#ifndef SNIFF_MISC_H_
#define SNIFF_MISC_H_


//  调试打印函数
#define PRN_MSG(fmt,arg...)     printf("%s:%d " fmt "\n",__func__,__LINE__,##arg)



#define PER_PACKET_SIZE             (2048)  //  pcap 文件中每个包的最大大小
#define ETH_MTU_MAX                 (1800)  //  认为网卡合法的 MTU 大小,暂定为大于1540

/*  pcap文件操作接口
 */
FILE* SniffPcap_Init(const char* fname,int isread);
void SniffPcap_Close(FILE *fp);
void SniffPcap_Write(FILE *fp,struct timeval *ts,const unsigned char* data,int len);
int SniffPcap_Read(FILE *fp,struct timeval *ts,unsigned char* data,int len);


/*
 *  过滤器模块操作接口
 */

struct SFilterCtl;

/*  返回过滤器支持的选项，最后一个选项的name = NULL
 *  过滤器使用的option.val 范围为从'A'-'Z'
 */
const struct option*    SFilter_GetOptions();
/*  显示选项对应的帮助
 */
const char*             SFilter_GetHelp();

/*  初始化过滤器信息    */
struct  SFilterCtl * SFilter_Init(void);
/*  释放过滤器信息      */
void    SFilter_Release(struct SFilterCtl *filter);

/*  分析一个过滤器语法  
 */
int     SFilter_Analyse(struct SFilterCtl *filter,char opcode,const char *optarg);
/*  生效过滤器语法, 在分析完所有语法后应该调用此函数来生效
 */
int     SFilter_Validate(struct SFilterCtl *filter, unsigned short *pframetype);
/*  判断报文是否允许通过    */
int     SFilter_IsDeny(struct SFilterCtl *filter,int vlanok,
        const unsigned char *data,int len);
/*  在socket上应用BPF过滤器，以实现内核过滤功能，提高性能   */
int SFilter_setBPF(struct SFilterCtl *filter,int sd,int frametype);





/*  接收到的帧信息
 */
struct RcvFrameInfo{
    struct timeval              *ts;        /*  帧接收时间                  */
    char                        *buf;       /*  接收到的帧数据              */
};

/*
 *  网卡收包处理回调
 *  可以挂多个处理函数
 *  但个个帧类型（除了0xffff和0）只能挂一个处理函数
 */

typedef void *PARSE_HANDLE;
typedef int (*SNIFF_INIT_CALLBACK)(PARSE_HANDLE *handle);
typedef int (*SNIFF_PARSE_CALLBACK)(
            const struct RcvFrameInfo *rcvinfo, /*  接收到的帧信息          */
            int                 framelen,       /*  帧长度                  */
            PARSE_HANDLE        handle);        /*  处理函数使用的私有句柄  */
typedef int (*SNIFF_RELEASE_CALLBACK)(PARSE_HANDLE *handle);

struct FrameParseItem{
    unsigned    short           frametype;  /*  帧类型,0表示是数组最后一项,
                                                0xffff表示对应所有帧
                                                其它表示对应特定帧类型
                                                */
    
    SNIFF_INIT_CALLBACK         init;       /*  此处理功能的初始化回调      */
    SNIFF_PARSE_CALLBACK        parse;      /*  对这个帧类型的处理回调      */
    SNIFF_RELEASE_CALLBACK      release;    /*  此处理功能的释放回调        */

    PARSE_HANDLE                priv;       /*  回调函数使用的私有数据区    */
};


struct SniffDevCtl;
typedef int (*SNIFFDEV_READ_CALLBACK)(
            struct SniffDevCtl  *ptCtl);
typedef int (*SNIFFDEV_POSTREAD_CALLBACK)(
            struct SniffDevCtl  *ptCtl);
typedef int (*SNIFFDEV_RELEASE_CALLBACK)(
            struct SniffDevCtl  *ptCtl);

struct SniffDevCtl{
    struct SFilterCtl           *filter;    /*  过滤器句柄                  */
    SNIFFDEV_READ_CALLBACK      readframe;  /*  读一个网卡帧                */
    SNIFFDEV_POSTREAD_CALLBACK  postread;   /*  用完后对网卡帧做其它操作    */
    SNIFFDEV_RELEASE_CALLBACK   release;    /*  释放                        */

    struct RcvFrameInfo         rcvframe;   /*  接收到的帧，readframe中赋值   */

    void                        *priv;      /*  回调函数使用的私有数据      */
};



/*  抓包初始化,
 *  如果初始化成功，那filter就归 handle 管理
 *  */
int EthCapDev_Init(struct SniffDevCtl *ptCtl,const char *devname,
        int promisc,int mmapqnum,
        unsigned short frametype,struct SFilterCtl *filter);
int PCapDev_Init(struct SniffDevCtl *ptCtl,const char *capfilename);




struct SniffConf{
    int promisc;            /*  是否使用混杂模式            */
    int mmap_qlen;          /*  mmap方式收包时mmap队列大小  */
    int vlanok;             /*  是否接收VLAN封装的报文      */
};


/*  处理抓包流程,num != -1 时只抓 num 个包  */
int Sniff_LoadConf(struct SniffConf *ptConf,int argc, char ** argv)
{
}

int Sniff_Init(struct SniffDevCtl *ptCtl,const char *devname,struct SFilterCtl *filter);
int Sniff_Run(struct SniffDevCtl *ptCtl,int num,struct FrameParseItem *ptItems);

#endif


