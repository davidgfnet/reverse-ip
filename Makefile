
CPP=g++
OPTS=-O2 -ggdb
OBJS = 
CFLAGS= $(OPTS) -Wall
CPPFLAGS=-std=gnu++0x $(CFLAGS)

all:	crawler lookup

crawler:	main.cc
	$(CPP) $(CPPFLAGS) $(PG) -o crawler $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -lcares -lcxxhttpserver -lpthread -lgnutls -lgcrypt

crawler_kc:	main.cc
	$(CPP) $(CPPFLAGS) $(PG) -o crawlerkc $(OBJS) main.cc ext/gzstream.cc  -I ext/ -lz -lcares -lkyotocabinet

lookup:	lookup.cc
	$(CPP) $(CPPFLAGS) $(PG) -o lookup lookup.cc -I ext/ -lz 

%.o:	%.cc
	$(CPP) $(CPPFLAGS) -c $<

clean:
	rm -f $(OBJS) crawler lookup

