
CPP=g++
OPTS=-O2 -ggdb
OBJS = 
CFLAGS= $(OPTS) #-Wall
CPPFLAGS=-std=gnu++0x $(CFLAGS)

all:	$(OBJS)
	$(CPP) $(CPPFLAGS) $(PG) -o crawler $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -lcares -lkyotocabinet
	$(CPP) $(CPPFLAGS) $(PG) -o lookup lookup.cc -I ext/ -lz 

%.o:	%.cc
	$(CPP) $(CPPFLAGS) -c $<

clean:
	rm -f $(OBJS) crawler lookup

