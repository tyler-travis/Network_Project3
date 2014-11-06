CC = g++
CFLAGS = -Wall -c -std=c++11 -g
LDFLAGS = -lpthread
SOURCES = main.cpp frameio.cpp util.cpp IP.cpp arp_cache.cpp MAC.cpp chksum.cpp
OBJECTS = $(SOURCES:.cpp=.o)
EXECUTABLE = exec

all: $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm *.o exec
