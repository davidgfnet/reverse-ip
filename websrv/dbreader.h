
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <gzbuffer.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <string.h>

#define ALIGNB      8
#define ALIGNB_LOG2 3

class DBReader {
public:
	DBReader(FILE * fd, uint32_t ip)
		: readbuf(NULL) {

		// Lookup table
		uint64_t offset = (ip>>8) << 2;
		fseeko(fd, offset, SEEK_SET);

		uint32_t fentry;
		fread(&fentry, 1, sizeof(fentry), fd);

		if (fentry != 0) {
			uint64_t entry = fentry;
			entry = entry << ALIGNB_LOG2;

			fseeko(fd, entry, SEEK_SET);
			uint32_t csize, usize;
			fread(&csize, 1, 4, fd);
			fread(&usize, 1, 4, fd);

			readbuf = new mgzbuffer(fd, csize);

			std::string dom = "dummy";
			int ipm = 0;
			do {
				if (dom.size() == 0)
					ipm++;
				if (ipm == (ip&255))
					break;
			} while (readbuf->getString(dom));
		}
	}
	~DBReader() {
		if (readbuf)
			delete readbuf;
	}

	bool nextDomain(std::string & domain) {
		if (!readbuf)
			return false;

		bool r = readbuf->getString(domain);
		if (!domain.size()) {
			delete readbuf;
			readbuf = NULL;
			return false;
		}
		return r;
	}
private:
	mgzbuffer * readbuf;
};


