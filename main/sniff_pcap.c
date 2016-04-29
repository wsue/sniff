
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "sniff_error.h"
#include "sniff.h"

/*
 * Standard libpcap format.
 */
#define TCPDUMP_MAGIC		0xa1b2c3d4
#define PCAP_VERSION_MAJOR      2
#define PCAP_VERSION_MINOR      4
#define DLT_EN10MB	1	/* Ethernet (10Mb) */
#define LINKTYPE_ETHERNET	DLT_EN10MB	/* also for 100Mb and up */

struct pcap_file_header {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    uint32_t thiszone;	/* gmt to local correction */
    uint32_t sigfigs;	/* accuracy of timestamps */
    uint32_t snaplen;	/* max length saved portion of each pkt */
    uint32_t linktype;	/* data link type (LINKTYPE_*) */
};

struct timeval_sniff{
    uint32_t     sec;
    uint32_t     usec;
};
struct pcap_sf_pkthdr {
    struct timeval_sniff  ts;	        /* time stamp */
    uint32_t             caplen;	/* length of portion present */
    uint32_t             len;	/* length this packet (off wire) */
};

static FILE* SniffPcap_Open(const char* fname,int isread)
{
    FILE    *fp;
    struct pcap_file_header hdr;

    if( !fname || !*fname )
        return NULL;

    fp  = fopen(fname,isread ? "rb" :"wb");
    if( !fp ) {
        PRN_MSG("open file %s err :%d, stop \n",fname,errno);
        return NULL;
    }


    hdr.magic = TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;

    hdr.thiszone        = timezone;
    hdr.snaplen         = PER_PACKET_SIZE;
    hdr.sigfigs         = 0;
    hdr.linktype        = LINKTYPE_ETHERNET;

    if( !isread ){
        if (fwrite((char *)&hdr, sizeof(hdr), 1, fp) != 1){
            PRN_MSG("write file %s dump head err :%d, stop dump\n",fname,errno);
            fclose(fp);
            return NULL;
        }

        PRN_MSG("will dump result to  file %s \n",fname);
        return fp;
    }
    else{
        struct pcap_file_header hdr2;
        if( fread((char *)&hdr2, sizeof(hdr2), 1, fp) != 1 ){
            PRN_MSG("read dump head from file %s error\n",fname);
            fclose(fp);
            return NULL;
        }

        if( hdr2.magic != hdr.magic 
                || hdr2.version_major != hdr.version_major 
                || hdr2.version_minor != hdr.version_minor 
                || hdr2.linktype != hdr.linktype ){
            PRN_MSG("check dump head from file %s error\n",fname);
            fclose(fp);
            return NULL;
        }

        PRN_MSG("dump head: snaplen:%d linktyp:$d sigfigs:%d \n",
                hdr2.snaplen,hdr2.linktype,hdr2.sigfigs);
        return fp;
    }
}


static void SniffPcap_Write(FILE *fp,const struct timeval *ts,const unsigned char* data,int len)
{
    if( fp ) {
        struct pcap_sf_pkthdr sf_hdr;

        sf_hdr.ts.sec       = ts->tv_sec;
        sf_hdr.ts.usec      = ts->tv_usec;
        sf_hdr.caplen       = len;
        sf_hdr.len          = len;
        /* XXX we should check the return status */
        (void)fwrite(&sf_hdr, sizeof(sf_hdr), 1, fp);
        (void)fwrite(data, len, 1, fp);
    }
}

static int SniffPcap_Read(FILE *fp,struct timeval *ts,unsigned char* data,int len)
{
    if( fp ) {
        struct pcap_sf_pkthdr sf_hdr;
        int ret = fread(&sf_hdr, 1, sizeof(sf_hdr),  fp);
        if( ret != sizeof(sf_hdr) ){
            return ret == 0 ? 0:-1 ;
        }

        ts->tv_sec          = sf_hdr.ts.sec;
        ts->tv_usec         = sf_hdr.ts.usec;
        if( len >= sf_hdr.caplen ){
            len = sf_hdr.caplen;
            if( fread(data,1,len,fp) != len ){
                return -1;
            }
        }
        else{
            if( fread(data,1,len,fp) != len ){
                return -1;
            }
            fseek(fp,sf_hdr.caplen - len,SEEK_SET);
        }
        if( len > 0 )
            data[len]   = 0;
        return len;
    }

    return -1;
}

static void SniffPcap_Close(FILE *fp)
{
    if( fp ) {
        fflush(NULL);
        fclose(fp);
    }
}



struct PCapRcvCtl{
    FILE            *fp;
    char            buf[PER_PACKET_SIZE];
    struct  timeval ts;
};

static int PCapReadCallback(
            struct SniffDevCtl  *ptCtl)
{
    struct PCapRcvCtl   *ptCapCtl   = (struct PCapRcvCtl   *)ptCtl->priv;
    return SniffPcap_Read(ptCapCtl->fp,&ptCapCtl->ts,ptCapCtl->buf,sizeof(ptCapCtl->buf));
}

static int PCapRelease(struct SniffDevCtl  *ptCtl)
{
    if( ptCtl->priv )
    {
        struct PCapRcvCtl   *ptCapCtl   = (struct PCapRcvCtl   *)ptCtl->priv;

        SniffPcap_Close(ptCapCtl->fp);
        ptCtl->priv     = NULL;
    }
    return 0;
}

int PCapDev_Init(struct SniffDevCtl *ptCtl,const char *capfilename)
{
    FILE                *fp         = NULL;
    struct PCapRcvCtl   *ptCapCtl   = NULL;
    if( !ptCtl || !capfilename || !*capfilename )
        return ERRCODE_SNIFF_PARAMERR;

    memset(ptCtl,0,sizeof(*ptCtl));

    fp      = SniffPcap_Open(capfilename,1);
    if( !fp )
        return ERRCODE_SNIFF_OPENFILE;

    ptCapCtl            = (struct PCapRcvCtl *)malloc(sizeof(struct PCapRcvCtl));
    if( !ptCapCtl ){
        fclose(fp);
        return ERRCODE_SNIFF_NOMEM;
    }

    memset(ptCapCtl,0,sizeof(*ptCapCtl));
    ptCapCtl->fp        = fp;
    ptCtl->priv         = ptCapCtl;

    ptCtl->tRcvFrame.buf = ptCapCtl->buf;
    ptCtl->tRcvFrame.ts  = &ptCapCtl->ts;

    ptCtl->readframe    = PCapReadCallback;
    ptCtl->release      = PCapRelease;

    return 0;
}







int PCapOutput_Init(const char *outfilename)
{
    int ret         = 0;
    FILE *fp        = SniffPcap_Open(outfilename,0);
    if( !fp ) {
        return ERRCODE_SNIFF_OPENFILE;
    }

    ret             = SniffParser_Register(SniffPcap_Close,SniffPcap_Write,fp);
    if( ret != 0 ){
        SniffPcap_Close(fp);
    }

    return ret;
}
