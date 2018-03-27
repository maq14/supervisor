CC	= g++
LIBS	= -lpcap
TARGET 	= supervisor
OBJECTS	= main.o monitor.o capture.o libpcapcapture.o detection.o

$(TARGET): $(OBJECTS)
	$(CC) -o $(TARGET) $(OBJECTS) $(LIBS)

monitor.o: monitor.h monitor.cpp
	$(CC) -c -o monitor.o monitor.cpp

main.o: main.cpp monitor.h capture.h
	$(CC) -c -o main.o main.cpp

capture.o: capture.cpp capture.h
	$(CC) -c -o capture.o capture.cpp

libpcapcapture.o: libpcapcapture.h libpcapcapture.cpp capture.h
	$(CC) -c -o libpcapcapture.o libpcapcapture.cpp

detection.o: detection.cpp detection.h monitor.h capture.h libpcapcapture.h
	$(CC) -c -o detection.o detection.cpp

clean: 
	rm -f supervisor *.o
