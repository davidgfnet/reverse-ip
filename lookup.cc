
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <vector>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ares.h>

#define ALIGNB      8
#define ALIGNB_LOG2 3

int main(int argc, char ** argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s dbfile IP\n", argv[0]);
		exit(0);
	}

	std::string dbfile = std::string(argv[1]);
	std::string ip = std::string(argv[2]);
	unsigned int ipp[4];
	sscanf(ip.c_str(), "%d.%d.%d.%d", &ipp[0],&ipp[1],&ipp[2],&ipp[3]);

	FILE * fd = fopen(dbfile.c_str(),"rb");

	// Lookup table
	uint32_t * ttable = 0;
	unsigned int tsize = 256*256*256*sizeof(uint32_t);
	ttable = (uint32_t*)malloc(tsize);
	fread(ttable, 1, tsize, fd);

	// Read first 32 bit (compressed size)
	uint64_t entry = ttable[ipp[0]*256*256 + ipp[1]*256 + ipp[2]];
	entry = entry << ALIGNB_LOG2;
	fseeko(fd, entry, SEEK_SET);
	uint32_t csize, usize;
	fread(&csize, 1, 4, fd);
	fread(&usize, 1, 4, fd);
	
	// Read compressed chunk!
	Bytef * compressed = (Bytef*)malloc(csize);
	fread(compressed, 1, csize, fd);

	uLongf dlen = usize;
	Bytef * original = (Bytef*)malloc(dlen);
	int res = uncompress(original, &dlen, compressed, csize);
	free(compressed);

	fclose(fd);

	// Process list
	int p = 0; int ipm = 0;
	while (p < usize) {
		bool dump = (ipm == ipp[3]);
		if (original[p] == 0) {
			// End of this IP
			p++;
			ipm++;
		}
		else {
			int l = strlen((char*)&original[p]);
			if (dump)
				std::cout << std::string((char*)&original[p]) << std::endl;
			p += l+1;
		}
	}
}

