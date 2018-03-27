#include "detection.h"

Detection::Detection()
{
	this->dev = new char[15];
	strcpy(this->dev, "eth0");
	this->st = state0;
	this->interval = 300;
	this->capture = new LibpcapCapture(this->dev);
	this->monitor = new Monitor(this->dev);
	this->normalFileName = new char[200];
	this->anomalousPath = new char[200];
	this->lastFileName = new char[200];
	this->tempFileName = new char[200];
}

Detection::Detection(char *dev, int interval, char *normalFileName, char *anomalousPath, char *tempFileName)
{
	this->dev = dev;
	this->st = state0;
	this->interval = interval;
	this->capture = new LibpcapCapture(this->dev);
	this->monitor = new Monitor(this->dev);
	this->normalFileName = normalFileName;
	this->anomalousPath = anomalousPath;
	this->tempFileName = tempFileName;
	this->lastFileName = new char[200];
}

int Detection::init()
{
	printf("detection init......\n");
	monitor->get_cpu_info(cpu_info);
	monitor->get_net_info(net_info);
	monitor->get_mem_info(mem_info);
	conn_num = monitor->get_conn_info();
	int res = capture->init();
	return res;
}

int Detection::merge(char *filename1, char *filename2, char *outputfilename)
{
	int res = -2;
	if(open_and_save(filename1, outputfilename, "a") == 0)
		res += 1;
	if(open_and_save(filename2, outputfilename, "a") == 0)
		res+= 1;
	return res;
}

void Detection::save_packet(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet)
{
	pcap_dump((u_char*)args, pkthdr, packet);
}

void Detection::detect()
{
	while(1)
	{
		capture->begin_dump(interval, tempFileName);
		vector<long long> cpu_info1, net_info1, mem_info1;
		cpu_info1.clear();net_info1.clear();mem_info1.clear();
		monitor->get_cpu_info(cpu_info1);
		monitor->get_mem_info(mem_info1);
		monitor->get_net_info(net_info1);
		conn_num = monitor->get_conn_info();
		double cpu_usage = get_cpu_usage(cpu_info1, cpu_info);
		double net_speed = get_net_speed(net_info1[0], net_info[0]);
		double mem_usage = double(mem_info1[0] - mem_info1[1]) / mem_info1[0];
		printf("cpu_usage: %f, net_speed: %f, mem_usage: %f, conn_num: %lld\n", 
			cpu_usage, net_speed, mem_usage, conn_num);
		if(capture->get_stat() != 0)
		{
			printf("capture get statistics error\n");
			break;
		}
		printf("packets received: %d\n", capture->get_num_recv());
		printf("packets dropped: %d\n", capture->get_num_drop());
		if(!anomalousOccur(cpu_usage, mem_usage, net_speed, conn_num))
		{
			if(st == state0)
			{
				if(open_and_save(tempFileName, normalFileName, "w") != 0)
				{
					printf("save normal file error\n");
					break;
				}
			}
			else
			{
				int rs1 = open_and_save(tempFileName, lastFileName, "a");
				int rs2 = open_and_save(tempFileName, normalFileName, "w");
				if(rs1!=0 || rs2!=0)
				{
					printf("cating pcap file error\n");
					break;
				}
				st = state0;
			}
		}
		else
		{
			if(st = state0)
			{
				time_t rawtime;
				time(&rawtime);
				struct tm *now_time;
				now_time = localtime(&rawtime);
				char filename[50];
				strftime(filename, 50, "%Y-%m-%d|%H-%M-%S.pcap", now_time);
				char fileNameAndPath[200];
				strcpy(fileNameAndPath, anomalousPath);
				strcat(fileNameAndPath, filename);
				strcpy(lastFileName, fileNameAndPath);
				if(merge(normalFileName, tempFileName, lastFileName) != 0)
				{
					printf("merging pcap file error\n");
					break;
				}
				st = state1;
			}
			else
			{
				if(open_and_save(tempFileName, lastFileName, "a") != 0)
				{
					printf("save anomalous pcap file error\n");
					break;
				}
			}
		}
		for(int i=0; i<7; i++)
			cpu_info[i] = cpu_info1[i];
		for(int i=0; i<2; i++)
		{
			net_info[i] = net_info1[i];
			mem_info[i] = mem_info1[i];
		}
	}
}

int Detection::open_and_save(char *inputfile, char *outputfile, const char *mode)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	handle = pcap_open_offline(inputfile, errbuf);
	if(handle == NULL)
	{
		printf("can't open file %s, error info: %s\n", inputfile, errbuf);
		return -1;
	}
	FILE *fp = NULL;
	fp = fopen(outputfile, mode); 
	pcap_dumper_t *dumpfile = pcap_dump_fopen(handle, fp);
	pcap_loop(handle, -1, save_packet, (u_char*)dumpfile);
	pcap_close(handle);
	pcap_dump_close(dumpfile);
	return 0;
}

double Detection::get_cpu_usage(vector<long long> v2, vector<long long> v1)
{
	long long all2 = 0;
	for(int i=0; i<7; i++)
		all2 += v2[i];
	long long idle2 = v2[3];
	long long all1 = 0;
	for(int i=0; i<7; i++)
		all1 += v1[i];
	long long idle1 = v1[3];
	double cpu_usage = double(all2 - all1 - (idle2 - idle1)) / (all2 - all1);
	return cpu_usage;
}

double Detection::get_net_speed(long long bytes_num1, long long bytes_num2)
{
	double speed = double(bytes_num1 - bytes_num2) / (1024 * 1024 * 1024);
	return speed;
}

bool Detection::anomalousOccur(double cpu_usage, double mem_usage, double net_speed, long long num_conn)
{
	if(cpu_usage>MAXCPUUSAGE && mem_usage>MAXMEMUSAGE && num_conn>MAXCONNNUM && net_speed>MAXNETSPEED)
		return true;
	return false;
}
