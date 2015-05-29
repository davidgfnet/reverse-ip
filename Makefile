
CPP=g++
OPTS=-O0 -ggdb
OBJS = 
CFLAGS= $(OPTS) #-Wall
CPPFLAGS=-std=gnu++0x $(CFLAGS)

all:	$(OBJS)
	$(CPP) $(CPPFLAGS) $(PG) -o crawler $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -lcares -lkyotocabinet

%.o:	%.cc
	$(CPP) $(CPPFLAGS) -c $<

clean:
	rm -f $(OBJS) crawler

