
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <gzbuffer.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <set>
#include <vector>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ares.h>

#include "websrv/dbreader.h"

#define ALIGNB      8
#define ALIGNB_LOG2 3

int main(int argc, char ** argv) {
	if (argc < 3) {
		fprintf(stderr, "Usage:\n");
		fprintf(stderr, "  %s dbfile summary\n", argv[0]);
		fprintf(stderr, "  %s dbfile all\n", argv[0]);
		fprintf(stderr, "  %s dbfile table-dbg\n", argv[0]);
		fprintf(stderr, "  %s dbfile IP\n", argv[0]);
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

	if (ip == "summary") {
		dbfile_summary sum;
		bool res = DBReader::getSummary(fd, sum);

		if (!res) {
			fprintf(stderr, "Could not read domain summary table in database file!");
			exit(1);
		}

		std::string dist;
		for (auto kv: sum.ext_dist)
			dist += "  \"" + kv.first + "\": { \"crawled\": " +
			std::to_string(kv.second.first) + ", \"resolved\": " +
			std::to_string(kv.second.second) + "},\n";
		dist = dist.substr(0, dist.size() - 2) + "\n";

		std::string hist;
		for (unsigned i = 0; i < 65; i++)
			hist += "," + std::to_string(sum.length_histogram[i]);
		hist = hist.substr(1);

		std::string ret = "{\n"
			" \"early_discarded_domains\": " + std::to_string(sum.early_discarded) + ",\n"
			" \"total_domains_crawled\": " + std::to_string(sum.domains_crawled) + ",\n"
			" \"total_domains_resolved\": " + std::to_string(sum.domains_good) + ",\n"
			" \"domain_extension_distribution\": {\n" + dist + " },\n"
			" \"domain_length_histogram\": [" + hist + "]\n"
			"}\n";

		std::cout << ret << std::endl;
	} else if (ip == "table-dbg") {
		std::set< std::pair<uint32_t,uint32_t> > top100;
		uint32_t offset = DBReader::getTablePtr(fd, 1) * ALIGNB;
		uint32_t prev = 0, prevt = 0;
		fseeko(fd, offset, SEEK_SET);
		for (unsigned i = 0; i < 256*256*256; i++) {
			uint32_t ptr, offset = 0;
			fread(&ptr, 1, 4, fd);
			if (ptr != 0) {
				offset = ptr - prev;
				if (prevt != 0)
					top100.insert(std::make_pair(offset*ALIGNB, prevt));
				prev = ptr;
				prevt = i;
			}
			while (top100.size() > 100)
				top100.erase(*top100.begin());
		}
		for (auto elem: top100)
			std::cout << (elem.second/256/256) << "."
		              << ((elem.second/256)&255) << "."
			          << (elem.second&255) << " " << elem.first << std::endl;
	} else if (ip == "all" || ip == "allint") {
		bool printint = (ip == "allint");
		for (uint32_t ip = 0; ip < 256*256*256; ip++) {
			DBReader dbr(fd, ip << 8);
			std::string dom; uint32_t ipout;
			while (dbr.nextDomainIP(dom, ipout)) {
				std::cout << dom << " ";
				if (printint) {
					std::cout << ipout << std::endl;
				} else {
					std::cout << (ipout >> 24) << ".";
					std::cout << ((ipout >> 16) & 0xFF) << ".";
					std::cout << ((ipout >> 8) & 0xFF) << ".";
					std::cout << (ipout & 0xFF) << std::endl;
				}
			}
		}
	} else {
		unsigned int ipp[4];
		sscanf(ip.c_str(), "%d.%d.%d.%d", &ipp[0], &ipp[1], &ipp[2], &ipp[3]);

		uint32_t intip = (ipp[0]<<24) | (ipp[1]<<16) | (ipp[2]<<8) | ipp[3];
		DBReader dbr(fd, intip);

		std::string dom;
		while (dbr.nextDomain(dom))
			std::cout << dom << std::endl;
	}

	fclose(fd);

	return 0;
}


