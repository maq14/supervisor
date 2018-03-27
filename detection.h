#ifndef DETECTION_H
#define DETECTION_H
#include "monitor.h"
#include "capture.h"
#include "libpcapcapture.h"
#include <pcap.h>
#include <vector>
#include <time.h>

#define MAXCPUUSAGE 0.6
#define MAXMEMUSAGE 0.6
#define MAXCONNNUM 5000
#define MAXNETSPEED 2.5

enum State 
{
    state0 = 0,
    state1 = 1
};

class Detection
{
public:
    Detection();
    Detection(char *dev, int interval, char *normalFileName, char *anomalousPath, char *tempFileName);
    int init();
    int merge(char *filename1, char *filename2, char *outputfilename);
    static void save_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
    void detect();
private:
    int open_and_save(char *inputfile, char *outputfile, const char *mode);
    double get_cpu_usage(vector<long long> v1, vector<long long> v2);
    double get_net_speed(long long bytes_num1, long long bytes_num2);
    bool anomalousOccur(double cpu_usage, double mem_usage, double net_speed, long long num_conn);

    char *dev;
    State st;
    int interval;
    char *normalFileName;
    char *anomalousPath;
    char *tempFileName;
    char *lastFileName;
    Capture *capture;
    Monitor *monitor;
    vector<long long> cpu_info;
    vector<long long> net_info;
    vector<long long> mem_info;
    long long conn_num;
};

#endif