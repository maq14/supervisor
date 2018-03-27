#include "capture.h"

Capture::Capture()
{
	this->dev = new char[20];
	strcpy(this->dev, "eth0");
}

Capture::Capture(char *dev)
{
	this->dev = dev;
}

int Capture::get_stat()
{
	return 0;
}

int Capture::get_num_recv()
{
	return 0;
}

int Capture::get_num_drop()
{
	return 0;
}

int Capture::get_num_ifdrop()
{
	return 0;
}
