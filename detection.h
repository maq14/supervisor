#ifndef DETECTION_H
#define DETECTION_H
#include "monitor.h"
#include "capture.h"
#include "libpcapcapture.h"
#include <pcap.h>
#include <vector>
#include <time.h>

#define MAX_CPU_USAGE 0.8
#define MAX_MEM_USAGE 0.8
#define MAX_CONN_NUM 1000
#define MAX_NET_SPEED 1.0

#define MAX_CPU_USAGE_VAR 0.36
#define MAX_MEM_USAGE_VAR 0.36
#define MAX_CONN_NUM_VAR 1000000
#define MAX_NET_SPEED_VAR 0.64

enum State 
{
    state0 = 0,
    state1 = 1
};

class Detection
{
public:
    Detection();
    Detection(char *dev, int interval, int sampling, char *normalFileName, char *anomalousPath, char *tempFileName);
    int init();
    void detect();
    static void save_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
private:
    int open_and_save(char *inputfile, char *outputfile, const char *mode);
    int merge(char *filename1, char *filename2, char *outputfilename);
    double get_cpu_usage(vector<long long> v1, vector<long long> v2);
    double get_net_speed(long long bytes_num1, long long bytes_num2);
    bool anomalousOccur();
    bool exceed_mean_thres(double cpu_usage, double mem_usage, double net_speed, long long num_conn);
    bool exceed_var_thres(double cpu_usage, double mem_usage, double net_speed, long long num_conn);
    double get_mean_mem_usage();
    long long get_mean_conn_num();
    double get_var_usage_cpu();
    double get_var_usage_mem();
    double get_var_NIC_speed();
    long long get_var_conn_num();

    char *dev;
    State st;
    int interval;
    int sampling;

    char *normalFileName;
    char *anomalousPath;
    char *tempFileName;
    char *lastFileName;

    Capture *capture;
    Monitor *monitor;

    vector<long long> cpu_info;
    vector<long long> net_info;
    vector<long long> mem_info;

    vector<long long> init_cpu_info;
    vector<long long> init_net_info;

    vector<double> usage_cpu;
    vector<double> usage_mem;
    vector<double> NIC_speed;
    vector<long long> conn_num;
};

#endif