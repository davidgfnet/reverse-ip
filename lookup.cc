
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <gzbuffer.h>
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

bool endsWith(const std::string & s, const std::string & ext) {
	if (s.size() > ext.size())
		return strcmp(&s[s.size() - ext.size()], ext.c_str()) == 0 and s[s.size() - ext.size() - 1] == '.';
	else
		return false;
}

int main(int argc, char ** argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "  %s dbfile IP\n", argv[0]);
		fprintf(stderr, "  %s dbfile -s [filter]\n", argv[0]);
		exit(0);
	}

	std::string dbfile = std::string(argv[1]);
	std::string ip = std::string(argv[2]);
	std::string extf = std::string(argc >= 4 ? argv[3] : "");

	FILE * fd = fopen(dbfile.c_str(),"rb");
	if (!fd) {
		fprintf(stderr, "Could not open input file!");
		exit(1);
	}

	char head[4];
	fread(head, 1, 4, fd);
	if (memcmp(head, "R3RZ", 4) != 0) {
		fprintf(stderr, "File format mismatch! Wrong header magic");
		exit(1);
	}

	while (1) {
		uint32_t field, fptr;
		fread(&field, 1, 4, fd);
		fread(&fptr,  1, 4, fd);
		if (field == 0) {
			fprintf(stderr, "IP table not found in file index!");
			exit(1);
		}
		else if (field == 1) {
			// Seek to table
			fseeko(fd, ((off_t)fptr) * ALIGNB, SEEK_SET);
			break;
		}
	}

	// Lookup table
	uint32_t * ttable = 0;
	unsigned int tsize = 256*256*256*sizeof(uint32_t);
	ttable = (uint32_t*)malloc(tsize);
	fread(ttable, 1, tsize, fd);

	if (ip == "-s") {
		for (unsigned i = 0; i < 256*256*256; i++) {
			uint64_t entry = ttable[i];
			if (entry == 0) continue;
			entry = entry << ALIGNB_LOG2;

			fseeko(fd, entry, SEEK_SET);
			uint32_t csize, usize;
			fread(&csize, 1, 4, fd);
			fread(&usize, 1, 4, fd);

			mgzbuffer readbuf(fd, csize);

			std::string dom;
			int ipm = 0; int prev = 0;
			while (readbuf.getString(dom)) {
				if (dom.size() == 0) {
					if (prev != 0)
						std::cout << i/256/256 << "." << ((i/256)&255) << "." << (i&255) 
							<< "." << ipm << " " << prev << std::endl;
					prev = 0;
					ipm++;
				}
				else {
					if (!extf.size() or endsWith(dom, extf))
						prev++;
				}
			}
		}
	}else{
		unsigned int ipp[4];
		sscanf(ip.c_str(), "%d.%d.%d.%d", &ipp[0],&ipp[1],&ipp[2],&ipp[3]);

		// Read first 32 bit (compressed size)
		uint64_t entry = ttable[ipp[0]*256*256 + ipp[1]*256 + ipp[2]];
		if (entry == 0)
			return 0;

		entry = entry << ALIGNB_LOG2;
		fseeko(fd, entry, SEEK_SET);
		uint32_t csize, usize;
		fread(&csize, 1, 4, fd);
		fread(&usize, 1, 4, fd);

		mgzbuffer readbuf(fd, csize);

		int ipm = 0;
		std::string dom;
		while (readbuf.getString(dom)) {
			bool dump = (ipm == ipp[3]);
			if (dom.size() == 0) {
				// End of this IP
				ipm++;
			}
			else {
				if (dump)
					std::cout << dom << std::endl;
			}
		}
	}

	return 0;
}


