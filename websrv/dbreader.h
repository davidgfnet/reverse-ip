
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <gzbuffer.h>
#include <stdlib.h>
#include <string>
#include <vector>
#include <map>
#include <string.h>

#define ALIGNB      8
#define ALIGNB_LOG2 3

typedef struct {
	uint32_t early_discarded;
	uint32_t domains_crawled;
	uint32_t domains_good;

	std::map <std::string, std::pair<uint32_t, uint32_t> > ext_dist;
	uint32_t length_histogram[65];
} dbfile_summary;

class DBReader {
public:
	static uint32_t getTablePtr(FILE * fd, unsigned ptr_type) {
		// Header check
		char head[4];
		fseeko(fd, 0, SEEK_SET);
		fread(head, 1, 4, fd);
		if (memcmp(head, "R3RZ", 4) != 0)
			return 0;

		// Look for the table offset
		while (1) {
			uint32_t tuple[2];
			if (fread(&tuple[0], 1, 8, fd) < 8)
				return 0;

			if (tuple[0] == 0)
				return 0;
			else if (tuple[0] == ptr_type)
				return tuple[1];
		}
	}

	DBReader(FILE * fd, uint32_t ip)
		: readbuf(NULL), ip(ip & ~0xff) {

		// Seek to table
		off_t foffset = getTablePtr(fd, 1);
		if (foffset == 0) return;

		fseeko(fd, foffset * ALIGNB, SEEK_SET);

		// Lookup table, seek from table begining
		uint64_t offset = (ip>>8) << 2;
		fseeko(fd, offset, SEEK_CUR);

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

	static bool getSummary(FILE * fd, dbfile_summary & ret) {
		// Just query for a summary		
		off_t foffset = getTablePtr(fd, 2);
		if (foffset == 0) return false;

		fseeko(fd, foffset * ALIGNB, SEEK_SET);

		fread(&ret.early_discarded, 1, 4, fd);
		fread(&ret.domains_crawled, 1, 4, fd);
		fread(&ret.domains_good,    1, 4, fd);

		uint32_t next;
		fread(&next, 1, 4, fd);
		while (next--) {
			char extn[65];
			uint32_t n1, n2;
			fread(&extn, 1, 64, fd);
			fread(&n1, 1, 4, fd);
			fread(&n2, 1, 4, fd);

			extn[64] = 0;
			ret.ext_dist[std::string(extn)] = std::make_pair(n1, n2);
		}

		fread(ret.length_histogram, 1, 65 * 4, fd);

		return true;
	}

	bool nextDomain(std::string & domain) {
		if (!readbuf)
			return false;

		bool r = readbuf->getString(domain);
		if (!r || !domain.size()) {
			delete readbuf;
			readbuf = NULL;
			return false;
		}
		return r;
	}

	bool nextDomainIP(std::string &domain, uint32_t &oip) {
		if (!readbuf)
			return false;

		bool r = readbuf->getString(domain);
		while (!domain.size() && r) {
			if ((ip & 0xff) == 0xff) {
				delete readbuf;
				readbuf = NULL;
				return false;
			}
			else
				ip++;

			r = readbuf->getString(domain);
		}
		oip = ip;
		return r;
	}
private:
	mgzbuffer * readbuf;
	uint32_t ip;
};


