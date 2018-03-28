#ifndef CAPTURE_H
#define CAPTURE_H
#include <string.h>

class Capture
{
public:
	Capture();
	Capture(char *dev);
	virtual int init() = 0;
	virtual void begin_dump(int interval, char *path, const char *mode) = 0;
	virtual int get_stat();
	virtual int get_num_recv();
	virtual int get_num_drop();
	virtual int get_num_ifdrop();
protected:
	char *dev;
};

#endif