
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <vector>
#include <unordered_map>
#include <string.h>
#include <assert.h>
#include <signal.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sstream>
#include <time.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ares.h>

#include "dns_servers.h"

#ifdef KC_SUPPORT
#include <kcpolydb.h>
kyotocabinet::PolyDB db;
#endif
std::string globaloutpath;
std::unordered_map < std::string, std::pair <uint32_t, uint32_t> > domain_ext;
uint32_t domain_len_dist[65] = {0};
uint32_t early_discarded = 0;

struct ares_addr_node dns_servers_list[sizeof(dns_servers)/sizeof(dns_servers[0])];

int inflight = 0;
int MAX_INFLIGHT = 2000;

enum SectionType { IP_Table = 1, Domain_Summary = 2, IP_Summary = 3 };

#define ALIGNB      8
#define ALIGNB_LOG2 3

#define MAX_FILE_MEM   (128*1024*1024)  // Can use up to 128MB in scratch memory to speed up DB generation

static void callback_kc(void *arg, int status, int timeouts, struct hostent *host);
static void callback_fs(void *arg, int status, int timeouts, struct hostent *host);
void dbgen_fs(std::string outpath, FILE * fd);
void dbgen_kc(FILE * fd);

std::string getext(const std::string dom) {
	auto p = dom.rfind('.');
	return dom.substr(p+1);
}

std::string getdname(const std::string dom) {
	auto p = dom.find('.');
	return dom.substr(0, p);
}

int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s command (args...)\n", argv[0]);
		fprintf(stderr, " Commands:\n");
		fprintf(stderr, "  * crawl-kc domains.gz tmpfile.kct max-inflight\n");
		fprintf(stderr, "  * crawl-fs domains.gz /tmpdir/ max-inflight\n");
		fprintf(stderr, "  * generatedb-kc tmpfile.kct out-file.db\n");
		fprintf(stderr, "  * generatedb-fs /tmppath/ out-file.db\n");
		exit(0);
	}

	std::string command = std::string(argv[1]);

	if (command == "crawl-kc" || command == "crawl-fs") {
		globaloutpath = std::string(argv[3]);
		MAX_INFLIGHT = std::stoi(argv[4]);
		std::string domfile = std::string(argv[2]);
		bool usekc = command == "crawl-kc";

		if (usekc) {
			#ifdef KC_SUPPORT
			if (!db.open(globaloutpath, kyotocabinet::PolyDB::OWRITER | kyotocabinet::PolyDB::OCREATE)) {
				std::cerr << "DB open error: " << db.error().name() << std::endl;
				exit(1);
			}
			#else
			std::cerr << "The crawler was not built with KC support!" << std::endl;
			exit(1);
			#endif
		}

		ares_channel channel;
		int status, addr_family = AF_INET;
		fd_set read_fds, write_fds;
		struct timeval *tvp, tv;

		status = ares_library_init(ARES_LIB_INIT_ALL);
		if (status != ARES_SUCCESS) {
			fprintf(stderr, "ares_library_init: %s\n", ares_strerror(status));
			return 1;
		}

		struct ares_options a_opt;
		memset(&a_opt,0,sizeof(a_opt));
		a_opt.tries = 1;
		a_opt.timeout = 10*1000;

		status = ares_init_options(&channel, &a_opt, ARES_OPT_TRIES | ARES_OPT_ROTATE | ARES_OPT_TIMEOUTMS);
		if (status != ARES_SUCCESS) {
			fprintf(stderr, "ares_init: %s\n", ares_strerror(status));
			return 1;
		}

		// Init servers (mix of IPv4 and IPv6, thus use ares_set_servers
		const unsigned num_servers = sizeof(dns_servers)/sizeof(dns_servers[0]);
		for (unsigned i = 0; i < num_servers; i++) {
			if (strchr(dns_servers[i], '.') == NULL) {
				dns_servers_list[i].family = AF_INET6;
				inet_pton(AF_INET6, dns_servers[i], &dns_servers_list[i].addr.addr6);
			} else {
				dns_servers_list[i].family = AF_INET;
				inet_pton(AF_INET, dns_servers[i], &dns_servers_list[i].addr.addr4);
			}
			dns_servers_list[i].next = &dns_servers_list[i+1];
		}
		dns_servers_list[num_servers-1].next = NULL;

		int ss_status = ares_set_servers(channel, dns_servers_list);
		if (ss_status != ARES_SUCCESS) {
			fprintf(stderr, "ares_set_servers: %s\n", ares_strerror(ss_status));
			return 1;
		}

		time_t prevt = time(0);
		unsigned readdom = 0;
		std::cout << "Reading domains and resolving IPs..." << std::endl;
		igzstream fin (domfile.c_str());
		while (1) {
			std::string domain;
			while (fin >> domain) {
				// Check for proper domains
				std::string domain_name = getdname(domain);

				if (domain.find('.') == std::string::npos ||
				    domain_name.size() > 64) {

					early_discarded++;

					continue; // Malformed domain name!
				}

				// Process input domains
				readdom++;
				std::string dext = getext(domain);
				if (domain_ext.find(dext) == domain_ext.end())
					domain_ext[dext] = std::make_pair(0,0);

				domain_ext[dext].first++;
				domain_len_dist[domain_name.size()]++;

				char * arg = (char*) malloc(domain.size()+1);
				memcpy(arg, domain.c_str(), domain.size()+1);
				ares_gethostbyname(channel, domain.c_str(), addr_family, usekc ? callback_kc : callback_fs, (void*)arg);
				inflight++;
				if (inflight >= MAX_INFLIGHT)
				    break;
			}
		
			/* Wait for queries to complete. */
			do {
				FD_ZERO(&read_fds);
				FD_ZERO(&write_fds);
				int nfds = ares_fds(channel, &read_fds, &write_fds);
				tvp = ares_timeout(channel, NULL, &tv);
				if (nfds > 0)
					select(nfds, &read_fds, &write_fds, NULL, tvp);
				ares_process(channel, &read_fds, &write_fds);
			} while(inflight >= MAX_INFLIGHT);

			// Exit if we are done
			if (inflight == 0 && fin.eof())
				break;

			// Update stdout
			if (time(0) != prevt) {
				std::cout << "Processed " << readdom << " domains so far ...\r" << std::flush;
				prevt = time(0);
			}
		}

		ares_destroy(channel);
		ares_library_cleanup();
		#ifdef KC_SUPPORT
		db.close();
		#endif

		// Generate the domain summary stats file
		std::map < std::string, std::pair <uint32_t, uint32_t> > dsum;
		uint32_t numdomscrawled = 0, numdomsgood = 0;
		for (auto kv : domain_ext) {
			dsum[kv.first] = kv.second;
			numdomscrawled += kv.second.first;
			numdomsgood += kv.second.second;
		}

		FILE * fd = fopen((globaloutpath + "/domainsummary.bin").c_str(), "wb");
		fwrite(&early_discarded, 1, 4, fd);

		fwrite(&numdomscrawled, 1, 4, fd);
		fwrite(&numdomsgood, 1, 4, fd);

		uint32_t numext = dsum.size();
		fwrite(&numext, 1, 4, fd);
		for (auto kv : dsum) {
			char ext[64] = {0};
			memcpy(ext, kv.first.c_str(), kv.first.size() >= 64 ? 64 : kv.first.size());
			fwrite(ext, 1, 64, fd);
			fwrite(&kv.second.first, 1, 4, fd);
			fwrite(&kv.second.second, 1, 4, fd);
		}

		fwrite(&domain_len_dist[0], 1, 4 * 65, fd);

		fclose(fd);
	}
	
	if (command == "generatedb-kc") {
		#ifdef KC_SUPPORT
		std::string outpath = std::string(argv[2]);
		std::string outdb = std::string(argv[3]);

		if (!db.open(outpath, kyotocabinet::PolyDB::OREADER)) {
			std::cerr << "DB open error: " << db.error().name() << std::endl;
			exit(1);
		}

		std::cout << "Done! Now building the database..." << std::endl;
		FILE * fd = fopen(outdb.c_str(),"wb");
		dbgen_kc(fd);
		fclose(fd);
		db.close();
		#else
		std::cerr << "The crawler was not built with KC support!" << std::endl;
		exit(1);
		#endif
	}
	if (command == "generatedb-fs") {
		std::string outpath = std::string(argv[2]);
		std::string outdb = std::string(argv[3]);

		std::cout << "Done! Now building the database..." << std::endl;
		FILE * fd = fopen(outdb.c_str(),"wb");
		dbgen_fs(outpath, fd);
		fclose(fd);
	}

}

static void rmkdir(const char *dir) {
    char tmp[256];
    char *p = NULL;
    size_t len;

    snprintf(tmp, sizeof(tmp),"%s",dir);
    len = strlen(tmp);
    if(tmp[len - 1] == '/')
            tmp[len - 1] = 0;
    for(p = tmp + 1; *p; p++)
            if(*p == '/') {
                    *p = 0;
                    mkdir(tmp, S_IRWXU);
                    *p = '/';
            }
    mkdir(tmp, S_IRWXU);
}

static void callback_kc(void *arg, int status, int timeouts, struct hostent *host) {
	#ifdef KC_SUPPORT
	inflight--;
	std::string domarg = std::string((char*)arg);
	free(arg);

	if (status == ARES_SUCCESS) {
		std::string domain = domarg;
		if (host->h_addr == 0) return;

		std::string dext = getext(domain);
		assert(domain_ext.find(dext) != domain_ext.end());
		domain_ext[dext].second++;

		struct in_addr **addr_list = (struct in_addr **) host->h_addr_list;
		for(int i = 0; addr_list[i] != NULL; i++) {
			uint32_t ip = (addr_list[i]->s_addr);  // ntohl

			std::string ipkey((char*)&ip, sizeof(uint32_t)), value;
			db.get(ipkey, &value);
			
			value += domain + " ";
			db.set(ipkey, value);
		}
	}
	#endif
}

static void callback_fs(void *arg, int status, int timeouts, struct hostent *host) {
	inflight--;
	std::string domarg = std::string((char*)arg);
	free(arg);

	if (status == ARES_SUCCESS) {
		std::string domain = domarg;
		if (host->h_addr == 0) return;

		std::string dext = getext(domain);
		assert(domain_ext.find(dext) != domain_ext.end());
		domain_ext[dext].second++;

		struct in_addr **addr_list = (struct in_addr **) host->h_addr_list;
		for(int i = 0; addr_list[i] != NULL; i++) {
			unsigned long ip = ntohl(addr_list[i]->s_addr);

			// Create dir structure, we limit the i-nodes to 1M aprox
			unsigned l0 = (ip >> 25) & 0x07F; //  7 bit
			unsigned l1 = (ip >> 19) & 0x03F; //  6 bit
			unsigned l2 = (ip >> 12) & 0x07F; //  7 bit
			unsigned l3 = (ip >>  0) & 0xFFF; // 12 bit

			std::string relpath = globaloutpath + "/" + std::to_string(l0) + "/" + std::to_string(l1);
			static unsigned long ctable[8192/sizeof(unsigned long)];
			if (!(ctable[(ip >> 22)&0x3FF] & (1<<((ip >> 19)&0x7))))
				rmkdir(relpath.c_str());
			ctable[(ip >> 22)&0x3FF] |= (1<<((ip >> 19)&0x7));

			std::string fn = relpath + "/" + std::to_string(l2);
			std::ofstream ofs(fn, std::ofstream::out | std::ofstream::app);

			if (domain.size() < 256) {
				unsigned char lb_hi = (l3 >> 8) & 0xFF;
				unsigned char lb_lo = l3 & 0xFF;
				unsigned char ds = domain.size();
				ofs << lb_lo << lb_hi << ds << domain;
			}
		}
	}
}

void write_header(FILE * fd) {
	// Header bytes: R3RZ
	fwrite("R3RZ", 1, 4, fd);
	
	// Write file index: for now we have table & domain summary
	unsigned indexs = 4 + (2+1)*8;                      // Size of header
	indexs = ((indexs + ALIGNB - 1) / ALIGNB) * ALIGNB; // Rounded to align size

	uint32_t ipt_offset  = indexs / ALIGNB;                            // Table after header
	uint32_t dsum_offset = ipt_offset + (1024*1024*16 * 4) / ALIGNB;   // Summary after table (2^24 32 bit entries)

	uint32_t ip_table[2]       = { IP_Table,       ipt_offset };
	uint32_t domain_summary[2] = { Domain_Summary, dsum_offset };

	fwrite(ip_table,       1, 8, fd);
	fwrite(domain_summary, 1, 8, fd);

	// Write empty section (all zeros) + padding
	for (unsigned i = 0; i < indexs - 4 - 8 - 8; i++)
		fputc(0, fd);
}

void write_sections(std::string outpath, FILE * fd) {
	FILE * f1 = fopen((outpath + "/domainsummary.bin").c_str(), "rb");
	fseek(f1, 0, SEEK_END);
	unsigned int fsize = ftello(f1);
	fseek(f1, 0, SEEK_SET);

	while (1) {
		char tmp[256*1024];
		int r = fread(tmp, 1, sizeof(tmp), f1);
		if (r <= 0)
			break;
		fwrite(tmp, 1, r, fd);
	}

	while (ftello(fd) % ALIGNB != 0)
		fseek(fd, 1, SEEK_CUR);

	fclose(f1);
}

uint32_t * ttable = 0;

void dbgen_kc(FILE * fd) {
	#ifdef KC_SUPPORT
	// Generate the database
	unsigned int tsize = 256*256*256*sizeof(uint32_t);
	ttable = (uint32_t*)malloc(tsize);
	memset(ttable, 0, tsize);

	write_header(fd);

	// Reserve the size for the index and we'll fill it as we go
	fwrite(ttable, 1, tsize, fd);

	// FIXME
	// write_sections(fd);

	// For each DB level:
	for (int l0 = 0; l0 < 256; l0++) {
	for (int l1 = 0; l1 < 256; l1++) {
	for (int l2 = 0; l2 < 256; l2++) {

		std::string buffer;

		for (int l3 = 0; l3 < 256; l3++) {
			uint32_t ip = htonl((l0 << 24) | (l1 << 16) | (l2 << 8) | l3);

			kyotocabinet::DB::Cursor* cursor = db.cursor();
			if (!cursor->jump((char*)&ip, sizeof(uint32_t))) {
				delete cursor;
				continue;
			}
			std::string key, value;
			cursor->get(&key, &value);
			delete cursor;

			std::istringstream iss(value);
			std::string domain;
			while (iss >> domain) {
				buffer += domain;
				buffer.push_back(0);
			}
			buffer.push_back(0);
		}

		// Compress
		uLongf outbufsize = buffer.size()*1.15f+1024*1024;
		Bytef * outputbuf = (Bytef*)malloc(outbufsize);
		int res = compress2(&outputbuf[8], &outbufsize, (Bytef*)buffer.c_str(), buffer.size(), 9);
		*((uint32_t*)outputbuf) = outbufsize;
		*(((uint32_t*)outputbuf)+1) = buffer.size();
		buffer = "";
		outbufsize += 8;

		while (outbufsize % ALIGNB != 0)
			outputbuf[outbufsize++] = 0;

		ttable[(l0<<16)|(l1<<8)|l2] = ftello(fd) >> ALIGNB_LOG2;
		fwrite(outputbuf, 1, outbufsize, fd);
		free(outputbuf);
	}
	}
	}

	// Update index
	fseeko(fd, 0, SEEK_SET);
	fwrite(ttable, 1, tsize, fd);

	free(ttable);
	#endif
}

void dbgen_fs(std::string outpath, FILE * fd) {
	// Generate the database
	unsigned int tsize = 256*256*256*sizeof(uint32_t);
	ttable = (uint32_t*)malloc(tsize);
	memset(ttable, 0, tsize);

	write_header(fd);

	off_t table_offset = ftello(fd);

	// Reserve the size for the index and we'll fill it as we go
	fwrite(ttable, 1, tsize, fd);

	write_sections(outpath, fd);

	uint32_t prevp = ftello(fd) >> ALIGNB_LOG2;

	std::string tmp_file = "/tmp/dbtmpfile.tmp" + std::to_string(getpid());

	// For each DB level:
	for (unsigned ol = 0; ol < 256*256*256; ol += 16) {

		unsigned l0 = (ol >> 17) & 0x7F;
		unsigned l1 = (ol >> 11) & 0x3F;
		unsigned l2 = (ol >>  4) & 0x7F;

		unsigned long fsize = 0;
		std::string fn = outpath + "/" + std::to_string(l0) + "/" + std::to_string(l1) + "/" + std::to_string(l2);
		{
			std::ifstream ifs(fn, std::ifstream::in);
			if (!ifs.good()) continue;
			fsize = ifs.tellg(); 
		}

		// Optimization: if the file is small, load it entirely into memory
		std::vector < std::string > domsrc(16*256);
		if (fsize <= MAX_FILE_MEM) {
			std::ifstream ifs(fn, std::ifstream::in);

			while (ifs) {
				// Rely on little endianess being used!
				unsigned short l3r; unsigned char ds;
				ifs.read((char*)&l3r, 2);
				ifs.read((char*)&ds, 1);

				std::string domain(ds, '\0');
				ifs.read(&domain[0], ds);

				domsrc[l3r] += domain;
				domsrc[l3r].push_back('\0');
			}
		}

		for (unsigned l3hi = 0; l3hi < 16; l3hi++) {
			ogzstream tmpfile(tmp_file.c_str());
			unsigned int uncsize = 0;

			for (unsigned l3 = 0; l3 < 256; l3++) {
				unsigned full_l3 = (l3hi << 8) | l3;

				if (fsize > MAX_FILE_MEM) {
					std::ifstream ifs(fn, std::ifstream::in);
					if (!ifs.good()) continue;

					while (ifs) {
						// Rely on little endianess being used!
						unsigned short l3r; unsigned char ds;
						ifs.read((char*)&l3r, 2);
						ifs.read((char*)&ds, 1);

						std::string domain(ds, '\0');
						ifs.read(&domain[0], ds);
						if (l3r != full_l3) continue;
						std::string buffer = domain;
						buffer.push_back(0);
						tmpfile << buffer;
						uncsize += buffer.size();
					}
					{
						std::string buffer;
						buffer.push_back(0);
						tmpfile << buffer;
						uncsize++;
					}
				}else{
					tmpfile << domsrc[full_l3];
					uncsize += domsrc[full_l3].size();
					tmpfile << '\0';
					uncsize += 1;
					domsrc[full_l3] = "";
				}
			}
			tmpfile.close();

			FILE * tmpf = fopen(tmp_file.c_str(), "rb");
			fseek(tmpf, 0, SEEK_END);
			unsigned int compressed_size = ftello(tmpf);
			fseek(tmpf, 0, SEEK_SET);

			fwrite((char*)&compressed_size, 1, 4, fd);
			fwrite((char*)&uncsize, 1, 4, fd);

			while (compressed_size > 0) {
				char tbuf[512*1024];
				unsigned int tocopy = compressed_size > sizeof(tbuf) ? sizeof(tbuf) : compressed_size;
				fread (tbuf, 1, tocopy, tmpf);
				fwrite(tbuf, 1, tocopy, fd);

				compressed_size -= tocopy;
			}
			fclose(tmpf);
			while (ftello(fd) % ALIGNB != 0)
				fseek(fd, 1, SEEK_CUR);

			ttable[ol | l3hi] = prevp;
			prevp = ftello(fd) >> ALIGNB_LOG2;
		}
	}

	// Update index
	fseeko(fd, table_offset, SEEK_SET);
	fwrite(ttable, 1, tsize, fd);

	free(ttable);

	// Cleanup!
	unlink(tmp_file.c_str());
}


