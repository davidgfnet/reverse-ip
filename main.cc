
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <gzstream.h>
#include <stdlib.h>
#include <string>
#include <map>
#include <vector>
#include <atomic>
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
#include <cxxhttpsrv/microrestd.h>

#include "dns_servers.h"

using namespace cxxhttpsrv;
class StatusService : public rest_service {
public:
	virtual bool handle(rest_request& req) override;
};

std::string globaloutpath;
std::unordered_map < std::string, std::pair <uint32_t, uint32_t> > domain_ext;
uint32_t domain_len_dist[65] = {0};
uint32_t early_discarded = 0;

struct ares_addr_node dns_servers_list[sizeof(dns_servers)/sizeof(dns_servers[0])];

enum WorkMode { mUnknown, mCrawling, mGeneratingDB };
const std::string WorkModeStr[] = {"Unknown", "DNS Crawling", "Generating DB"};
std::atomic<unsigned> inflight(0);
std::atomic<unsigned> domainstocrawl(0);
std::atomic<unsigned> readdom(0);
std::atomic<unsigned> resolveddom(0);
std::atomic<unsigned> resolvedipdom(0);
std::atomic<unsigned> MAX_INFLIGHT(2000);
std::atomic<unsigned> workingmode(mUnknown);
std::atomic<unsigned> approxprogress(0);

enum SectionType { IP_Table = 1, Domain_Summary = 2, IP_Summary = 3 };

#define ALIGNB      8
#define ALIGNB_LOG2 3

#define MAX_FILE_MEM   (256*1024*1024)  // Can use up to 128MB in scratch memory to speed up DB generation

static void callback_fs(void *arg, int status, int timeouts, struct hostent *host);
void dbgen_fs(std::string outpath, FILE * fd);

std::string getext(const std::string dom) {
	auto p = dom.rfind('.');
	return dom.substr(p+1);
}

std::string getdname(const std::string dom) {
	auto p = dom.find('.');
	return dom.substr(0, p);
}

off_t filesize(const char * fname) {
	off_t ret = 0;
	FILE * tmpf = fopen(fname, "rb");
	if (tmpf) {
		fseek(tmpf, 0, SEEK_END);
		ret = ftello(tmpf);
		fclose(tmpf);
	}
	return ret;
}

int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s command (args...)\n", argv[0]);
		fprintf(stderr, " Commands:\n");
		fprintf(stderr, "  * crawl-fs domains.gz /tmpdir/ max-inflight\n");
		fprintf(stderr, "  * generatedb-fs /tmppath/ out-file.db\n");
		exit(0);
	}

	// Start web iface
	rest_server server;
	server.set_log_file(stderr);
	server.set_max_connections(32);
	server.set_threads(2);

	StatusService service;
	if (!server.start(&service, 9006, false)) {
		fprintf(stderr, "Cannot start REST server!\n");
		return 1;
	}

	std::string command = std::string(argv[1]);
	workingmode = (command == "crawl-fs") ? mCrawling :
	              (command == "generatedb-fs") ? mGeneratingDB : mUnknown;

	if (workingmode == mCrawling) {
		globaloutpath = std::string(argv[3]);
		MAX_INFLIGHT = std::stoi(argv[4]);
		std::string domfile = std::string(argv[2]);

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

		{
			std::cout << "Reading input file..." << std::endl;
			igzstream fin (domfile.c_str());
			std::string domain;
			while (fin >> domain)
				domainstocrawl++;
		}

		time_t prevt = time(0);
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
				ares_gethostbyname(channel, domain.c_str(), addr_family, callback_fs, (void*)arg);
				inflight++;
				if (inflight >= MAX_INFLIGHT)
				    break;
			}
			approxprogress = readdom * 100 / domainstocrawl;
		
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
	else if (workingmode == mGeneratingDB) {
		std::string outpath = std::string(argv[2]);
		std::string outdb = std::string(argv[3]);

		std::cout << "Done! Now building the database..." << std::endl;
		FILE * fd = fopen(outdb.c_str(),"wb");
		dbgen_fs(outpath, fd);
		fclose(fd);
	}

	server.stop();
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

static void callback_fs(void *arg, int status, int timeouts, struct hostent *host) {
	inflight--;
	std::string domarg = std::string((char*)arg);
	free(arg);

	if (status == ARES_SUCCESS) {
		resolveddom++;
		std::string domain = domarg;
		if (host->h_addr == 0) return;

		std::string dext = getext(domain);
		assert(domain_ext.find(dext) != domain_ext.end());
		domain_ext[dext].second++;

		struct in_addr **addr_list = (struct in_addr **) host->h_addr_list;
		if (addr_list[0] != NULL)
			resolvedipdom++;

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
		approxprogress = (ol*100 / 256*256*256);

		unsigned l0 = (ol >> 17) & 0x7F;
		unsigned l1 = (ol >> 11) & 0x3F;
		unsigned l2 = (ol >>  4) & 0x7F;

		unsigned long fsize = 0;
		std::string fn = outpath + "/" + std::to_string(l0) + "/" + std::to_string(l1) + "/" + std::to_string(l2);
		fsize = filesize(fn.c_str());
		if (!fsize) continue;

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

			unsigned int compressed_size = filesize(tmp_file.c_str());
			FILE * tmpf = fopen(tmp_file.c_str(), "rb");

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

bool StatusService::handle(rest_request& req) {
	if (req.method != "GET") return req.respond_method_not_allowed("GET");

	std::string url = req.url;
	while (url.size() && url[0] == '/')
		url = url.substr(1);

	if (url == "") {
		std::string ret = "<html><body>\n"
			"<h1>ReverseIP Crawler Status Page</h1>\n"
			"Current status: " + WorkModeStr[workingmode] + "<br/>\n"
			"Approximate progress: " + std::to_string(approxprogress) + "%<br/><br/>\n";

		switch (workingmode) {
		case mCrawling:
			ret += "<table>"
			"<tr><td>inflight-requests</td><td>" + std::to_string(inflight) + "</td></tr>\n"
			"<tr><td>max-inflight-requests</td><td>" + std::to_string(MAX_INFLIGHT) + "</td></tr>\n"
			"<tr><td>domains-to-crawl</td><td>" + std::to_string(domainstocrawl) + "</td></tr>\n"
			"<tr><td>processed-domains</td><td>" + std::to_string(readdom) + "</td></tr>\n"
			"<tr><td>resolved-domains</td><td>" + std::to_string(resolveddom) + "</td></tr>\n"
			"<tr><td>resolved-domains-ip</td><td>" + std::to_string(resolvedipdom) + "</td></tr>\n"
			"</table>";
			break;
		};

		ret += "</body></html>";
		return req.respond("text/html", ret);
	}
	if (url == "stats") {
		std::string ret = "{\n"
			"  \"working-mode\": "          + std::to_string(workingmode) + ",\n"
			"  \"working-mode-str\": "      + WorkModeStr[workingmode] + ",\n"
			"  \"approximate-progress\": "  + std::to_string(approxprogress) + ",\n"

			"  \"inflight-requests\": "     + std::to_string(inflight) + ",\n"
			"  \"max-inflight-requests\": " + std::to_string(MAX_INFLIGHT) + ",\n"
			"  \"domains-to-crawl\": "      + std::to_string(domainstocrawl) + ",\n"
			"  \"processed-domains\": "     + std::to_string(readdom) + ",\n"
			"  \"resolved-domains\": "      + std::to_string(resolveddom) + ",\n"
			"  \"resolved-domains-ip\": "   + std::to_string(resolvedipdom) + "\n"
			"}\n";

		return req.respond("application/json", ret);
	}
	return req.respond_error("Endpoint not found!", 404);
}


