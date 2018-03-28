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
	this->sampling = 30;
}

Detection::Detection(char *dev, int interval, int sampling, char *normalFileName, char *anomalousPath, char *tempFileName)
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
	this->sampling = sampling;
}

int Detection::init()
{
	printf("detection init......\n");
	monitor->get_cpu_info(cpu_info);
	monitor->get_net_info(net_info);
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
	printf("detection begin...\n");
	unsigned int det_round = 0;
	while(true)
	{
		printf("-------- detection round %u --------\n", det_round);
		int round = interval / sampling;
		init_cpu_info.clear();init_net_info.clear();
		for(int i=0; i<7; i++)
			init_cpu_info.push_back(cpu_info[i]);
		for(int i=0; i<2; i++)
			init_net_info.push_back(net_info[i]);
		for(int i=0; i<round; i++)
		{
			if(i==0)
				capture->begin_dump(sampling, tempFileName, "w");
			else
				capture->begin_dump(sampling, tempFileName, "a");
			vector<long long> temp_cpu_info, temp_net_info;
			temp_cpu_info.clear();temp_net_info.clear();
			monitor->get_cpu_info(temp_cpu_info);
			monitor->get_mem_info(mem_info);
			monitor->get_net_info(temp_net_info);
			long long num_conn = monitor->get_conn_info();
			double cpu_usage = get_cpu_usage(temp_cpu_info, cpu_info);
			double net_speed = get_net_speed(temp_net_info[0], net_info[0]);
			double mem_usage = double(mem_info[0] - mem_info[1]) / mem_info[0];
			printf("samlpling round : %d, cpu_usage: %lf, net_speed: %lf, mem_usage: %lf, conn_num: %lld\n", 
				i, cpu_usage, net_speed, mem_usage, num_conn);
			usage_cpu.push_back(cpu_usage);
			usage_mem.push_back(mem_usage);
			NIC_speed.push_back(net_speed);
			conn_num.push_back(num_conn);
			for(int i=0; i<7; i++)
				cpu_info[i] = temp_cpu_info[i];
			for(int i=0; i<2; i++)
			{
				net_info[i] = temp_net_info[i];
			}
			mem_info.clear();
		}
		if(capture->get_stat() != 0)
		{
			printf("capture get statistics error\n");
			break;
		}
		printf("#### packets received: %d ####\n", capture->get_num_recv());
		printf("#### packets dropped: %d ####\n", capture->get_num_drop());
		if(!anomalousOccur())
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
			printf("normal condition, state : %d\n", state0);
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
			printf("anomalous condition, state : %d\n", state1);
		}
		usage_cpu.clear();
		usage_mem.clear();
		NIC_speed.clear();
		conn_num.clear();
		det_round ++;
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

double Detection::get_net_speed(long long bytes_num1, long long bytes_num2)
{
	double speed = double(bytes_num1 - bytes_num2) / (1024 * 1024 * 1024);
	return speed;
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

bool Detection::anomalousOccur()
{
	double usage_cpu_mean = get_cpu_usage(cpu_info, init_cpu_info);
	double usage_mem_mean = get_mean_mem_usage();
	long long conn_num_mean = get_mean_conn_num();
	double NIC_speed_mean = get_net_speed(net_info[0], init_net_info[0]);
	double usage_cpu_var = get_var_usage_cpu();
	double usage_mem_var = get_var_usage_mem();
	double NIC_speed_var = get_var_NIC_speed();
	long long conn_num_var = get_var_conn_num();

	if(st == state0)
	{
		if(exceed_var_thres(usage_mem_var, usage_mem_var, NIC_speed_var, conn_num_var))
			return true;
		else
		{
			if(exceed_mean_thres(usage_cpu_mean, usage_mem_mean, NIC_speed_mean, conn_num_mean))
				return true;
			else
				return false;
		}
	}
	else
	{
		if(exceed_var_thres(usage_mem_var, usage_mem_var, NIC_speed_var, conn_num_var))
		{
			if(exceed_mean_thres(usage_cpu_mean, usage_mem_mean, NIC_speed_mean, conn_num_mean))
				return true;
			else
				return false;
		}
		else
		{
			if(exceed_mean_thres(usage_cpu_mean, usage_mem_mean, NIC_speed_mean, conn_num_mean))
				return true;
			else
				return false;
		}
	}
}

bool Detection::exceed_mean_thres(double cpu_usage, double mem_usage, double net_speed, long long num_conn)
{
	if(cpu_usage>MAX_CPU_USAGE || mem_usage>MAX_MEM_USAGE || num_conn>MAX_CONN_NUM || net_speed>MAX_NET_SPEED)
		return true;
	return false;
}

bool Detection::exceed_var_thres(double cpu_usage, double mem_usage, double net_speed, long long num_conn)
{
	if(cpu_usage>MAX_CPU_USAGE_VAR || mem_usage>MAX_MEM_USAGE_VAR || num_conn>MAX_CONN_NUM_VAR || net_speed>MAX_NET_SPEED_VAR)
		return true;
	return false;
}

double Detection::get_mean_mem_usage()
{
	int size = usage_mem.size();
	double mean = 0.0;
	for(int i=0; i<size; i++)
		mean += usage_mem[i];
	mean /= size;
	return mean;
}

long long Detection::get_mean_conn_num()
{
	int size = conn_num.size();
	long long mean = 0;
	for(int i=0; i<size; i++)
		mean += conn_num[i];
	mean /= size;
	return mean;
}

double Detection::get_var_usage_cpu()
{
	int size = usage_cpu.size();
	double mean = 0.0, variance = 0.0;
	for(int i=0; i<size; i++)
		mean += usage_cpu[i];
	mean /= size;
	for(int i=0; i<size; i++)
		variance += (usage_cpu[i]-mean) * (usage_cpu[i]-mean);
	variance /= size;
	return variance;
}

double Detection::get_var_usage_mem()
{
	int size = usage_mem.size();
	double mean = 0.0, variance = 0.0;
	for(int i=0; i<size; i++)
		mean += usage_mem[i];
	mean /= size;
	for(int i=0; i<size; i++)
		variance += (usage_mem[i]-mean) * (usage_mem[i]-mean);
	variance /= size;
	return variance;
}

double Detection::get_var_NIC_speed()
{
	int size = NIC_speed.size();
	double mean = 0.0, variance = 0.0;
	for(int i=0; i<size; i++)
		mean += NIC_speed[i];
	mean /= size;
	for(int i=0; i<size; i++)
		variance += (NIC_speed[i]-mean) * (NIC_speed[i]-mean);
	variance /= size;
	return variance;
}

long long Detection::get_var_conn_num()
{
	int size = conn_num.size();
	double mean = 0.0, variance = 0.0;
	for(int i=0; i<size; i++)
		mean += conn_num[i];
	mean /= size;
	for(int i=0; i<size; i++)
		variance += (conn_num[i]-mean) * (conn_num[i]-mean);
	variance /= size;
	return variance;
}