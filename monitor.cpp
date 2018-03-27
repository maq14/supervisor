#include "monitor.h"

const int Monitor::INTERVAL = 5;
const char Monitor::CPUINFO[12] = "/proc/stat";
const char Monitor::NETINFO[15] = "/proc/net/dev";
const char Monitor::MEMINFO[14] = "/proc/meminfo";
const char Monitor::CONNINFO[14] = "/proc/net/tcp";
const char Monitor::CONNSTATUS[12][4] = {"00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0A", "0B"};

Monitor::Monitor()
{
    this->dev = new char[20];
    strcpy(dev, "eth0");
}

Monitor::Monitor(char *dev)
{
    this->dev = dev;
}

void Monitor::get_cpu_info(vector<long long> &v)
{
    FILE *fp = NULL;
    fp = fopen(CPUINFO, "r");
    char w[100];
    while(fscanf(fp, "%s", w) > 0)
    {
        if(strcmp(w, "cpu") == 0)
        {
            for(int i=0; i<7; i++)
            {
                fscanf(fp, "%s", w);
                v.push_back(atoll(w));
            }
            break;
        }
    }
    fclose(fp);
}

void Monitor::get_net_info(vector<long long>& v)
{
    FILE *fp = NULL;
    fp = fopen(NETINFO, "r");
    char w[100];
    while(fscanf(fp, "%s", w) > 0)
    {
        rstrip(w);
        if(strcmp(w, dev) == 0)
        {
            for(int i=0; i<2; i++)
            {
                fscanf(fp, "%s", w);
                v.push_back(atoll(w));//v[0] : bytes, v[1] : packets
            }
            break;
        }
    }
    fclose(fp);
}

void Monitor::get_mem_info(vector<long long>& v)
{
    FILE *fp = NULL;
    fp = fopen(MEMINFO, "r");
    char w[100];
    while(fscanf(fp, "%s", w) > 0)
    {
        rstrip(w);
        if(strcmp(w, "MemTotal") == 0)
        {
            fscanf(fp, "%s", w);
            v.push_back(atoll(w));
        }
        else if(strcmp(w, "MemFree") == 0)
        {
            fscanf(fp, "%s", w);
            v.push_back(atoll(w));
            break;
        }
    }
    fclose(fp);
}

long long Monitor::get_conn_info()
{
    FILE *fp = NULL;
    fp = fopen(CONNINFO, "r");
    char w[200];
    int state = 0;
    long long num = 0;
    while(true)
    {
        fgets(w, 200, fp);
        if(feof(fp))
            break;
        if(state == 0)
        {
            state ++;
            continue;
        }
        vector<char*> w_split = split(w, " ");
        char *conn_state = w_split[3];
        if(isAlive(conn_state))
            num ++;
    }
    fclose(fp);
    return num;
}

void Monitor::rstrip(char *s)
{
    int len = strlen(s);
    for(int i=len-1; i>=0; i--)
    {
        if(!isdigit(s[i]) && !isalpha(s[i]))
        {
            s[i] = '\0';
        }
        else
            break;
    }
}

vector<char*> Monitor::split(char *s, const char *sp)
{
    char *p;
    vector<char*> vec;
    p = strtok(s, sp);
    while(p)
    {
        vec.push_back(p);
        p = strtok(NULL, sp);
    }
    return vec;
}

bool Monitor::isAlive(char *s)
{
    for(int i=0; i<12;i++)
    {
        if(strcmp(s, CONNSTATUS[i]) == 0)
        {
            return true;
        }
    }
    return false;
}