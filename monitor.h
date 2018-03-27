#ifndef MONITOR_H
#define MONITOR_H
#include <stdio.h>
#include <vector>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

using namespace std;

class Monitor
{
public:
    Monitor();
    Monitor(char *dev);
    void get_cpu_info(vector<long long>& v);
    void get_net_info(vector<long long>& v);
    void get_mem_info(vector<long long>& v);
    long long get_conn_info();

    const static int INTERVAL;
    const static char CPUINFO[12];
    const static char NETINFO[15];
    const static char MEMINFO[14];
    const static char CONNINFO[14];
    const static char CONNSTATUS[12][4];
private:
    char *dev;
    void rstrip(char *s);
    vector<char*> split(char *s, const char *sp);
    bool isAlive(char *s);
};

#endif // MONITOR_H