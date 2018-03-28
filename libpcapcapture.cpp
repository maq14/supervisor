#include "libpcapcapture.h"

const int LibpcapCapture::MAXPACKETSIZE = 65536;
const int LibpcapCapture::RETINTERVAL = 300;

LibpcapCapture::LibpcapCapture()
{

}

LibpcapCapture::LibpcapCapture(char *dev) : Capture(dev)
{
    
}

int LibpcapCapture::init()
{
	char errbuf[PCAP_ERRBUF_SIZE];
    /* get net address and mask */
	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Can't get netmask for device %s\n", dev);
        net = 0;
        mask = 0;
        return -1;
    }
    /* open target device and prepare to listen */
    handle = pcap_open_live(dev, MAXPACKETSIZE, 1, RETINTERVAL, errbuf);
    if(handle == NULL)
    {
        printf("Couldn't open device %s: %s\n", dev, errbuf);
        return -1;
    }
    /* set rule for filter and install it */
    char filter_exp[15] = "tcp port 80";
    if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
        printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    if(pcap_setfilter(handle, &fp) == -1)
    {
        printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return -1;
    }
    return 0;
}

void LibpcapCapture::begin_dump(int interval, char *path, const char *mode)
{
    FILE *fp = fopen(path, mode);
    dumpfile = pcap_dump_fopen(handle, fp);
    time_t begintime;
    time(&begintime);
    while(true)
    {
        pcap_loop(handle, 10, save_packet, (u_char*)dumpfile);
        time_t nowtime;
        time(&nowtime);
        int diff = (int)difftime(nowtime, begintime);
        if(diff >= interval)
            break;
    }
    pcap_dump_close(dumpfile);
    pcap_breakloop(handle);
    return;
}

int LibpcapCapture::get_stat()
{
    return pcap_stats(handle, &this->ps);
}

int LibpcapCapture::get_num_recv()
{
    return (int)ps.ps_recv;
}

int LibpcapCapture::get_num_drop()
{
    return (int)ps.ps_drop;
}

int LibpcapCapture::get_num_ifdrop()
{
    return (int)ps.ps_ifdrop;
}

void LibpcapCapture::save_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
    pcap_dump((u_char*)args, pkthdr, packet);
}