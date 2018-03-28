#include <stdio.h>
#include "detection.h"

using namespace std;

#define TIMEINTERVAL 300

int main(int argc, char **argv)
{
	if(argc < 7)
	{
		printf("Usage : %s [dev] [interval] [sampling] [normal file name] [anomalous file path] [temp file name]\n", argv[0]);
		return 1;
	}
    Detection *d = new Detection(argv[1], atoi(argv[2]), atoi(argv[3]), argv[4], argv[5], argv[6]);
    if(d->init() != 0)
    {
    	printf("exit\n");
    	return 1;
    }
    d->detect();
    printf("-------- detection end --------\n");
    return 0;
}