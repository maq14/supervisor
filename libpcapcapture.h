#ifndef LIBPCAPCAPTURE_H
#define LIBPCAPCAPTURE_H
#include <pcap.h>
#include <time.h>
#include "capture.h"

class LibpcapCapture : public Capture
{
public:
	LibpcapCapture();
	LibpcapCapture(char *dev);
	int init();
	void begin_dump(int interval, char *path);
	int get_stat();
	int get_num_recv();
	int get_num_drop();
	int get_num_ifdrop();

	static void save_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);

	const static int MAXPACKETSIZE;
	const static int RETINTERVAL;
private:
	pcap_t *handle;
	pcap_dumper_t *dumpfile;
	struct bpf_program fp;
    bpf_u_int32 mask;
    bpf_u_int32 net;
    struct pcap_stat ps;
};
#endif