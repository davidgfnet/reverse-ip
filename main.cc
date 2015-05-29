
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

std::string outpath;

const char * dns_servers[4] = { "209.244.0.3", "209.244.0.4", "8.8.8.8", "8.8.4.4" };
struct in_addr dns_servers_addr[4];
int inflight = 0;
#define MAX_INFLIGHT 2000

#define ALIGNB      8
#define ALIGNB_LOG2 3

static void callback(void *arg, int status, int timeouts, struct hostent *host);
void dbgen(FILE * fd);

int main(int argc, char ** argv) {
	if (argc < 4) {
		fprintf(stderr, "Usage: %s command (args...)\n", argv[0]);
		fprintf(stderr, " Commands:\n");
		fprintf(stderr, "  * crawl domains.gz /tmppath/ out-file.db bw(kbps)\n");
		fprintf(stderr, "  * generatedb /tmppath/ out-file.db\n");
		exit(0);
	}

	std::string command = std::string(argv[1]);

	if (command == "crawl") {
		outpath = std::string(argv[3]);
		std::string outdb = std::string(argv[4]);
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

		addr_family = AF_INET;
		struct ares_options a_opt;
		memset(&a_opt,0,sizeof(a_opt));
		a_opt.tries = 1;
		a_opt.nservers = sizeof(dns_servers)/sizeof(dns_servers[0]);
		a_opt.servers = &dns_servers_addr[0];
		for (int i = 0; i < a_opt.nservers; i++)
			inet_aton(dns_servers[i], &dns_servers_addr[i]);

		status = ares_init_options(&channel, &a_opt, ARES_OPT_TRIES | ARES_OPT_SERVERS | ARES_OPT_ROTATE);
		if (status != ARES_SUCCESS) {
			fprintf(stderr, "ares_init: %s\n", ares_strerror(status));
			return 1;
		}

		std::cout << "Reading domains and resolving IPs..." << std::endl;
		igzstream fin (domfile.c_str());
		while (1) {
			std::string domain;
			while (fin >> domain) {
				char * arg = (char*) malloc(domain.size()+1);
				memcpy(arg, domain.c_str(), domain.size()+1);
				ares_gethostbyname(channel, domain.c_str(), addr_family, callback, (void*)arg);
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
		}

		ares_destroy(channel);
		ares_library_cleanup();
	}
	
	if (command == "generatedb") {
		outpath = std::string(argv[2]);
		std::string outdb = std::string(argv[3]);

		std::cout << "Done! Now building the database..." << std::endl;
		FILE * fd = fopen(outdb.c_str(),"wb");
		dbgen(fd);
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

static void callback(void *arg, int status, int timeouts, struct hostent *host) {
	inflight--;
	std::string domarg = std::string((char*)arg);
	free(arg);

	if (status == ARES_SUCCESS) {
		std::string domain = domarg;
		if (host->h_addr == 0) return;

		struct in_addr **addr_list = (struct in_addr **) host->h_addr_list;
		for(int i = 0; addr_list[i] != NULL; i++) {
			unsigned long ip = ntohl(addr_list[i]->s_addr);

			int l0 = (ip >> 24) & 0xFF;
			int l1 = (ip >> 16) & 0xFF;
			int l2 = (ip >>  8) & 0xFF;
			int l3 = (ip >>  0) & 0xFF;

			std::string relpath = outpath + "/" + std::to_string(l0) + "/" + std::to_string(l1);
			rmkdir(relpath.c_str());
			std::string fn = relpath + "/" + std::to_string(l2);
			std::ofstream ofs(fn, std::ofstream::out | std::ofstream::app);

			ofs << l3 << " " << domain << std::endl;
		}
	}
}

uint32_t * ttable = 0;

void dbgen(FILE * fd) {
	// Generate the database
	unsigned int tsize = 256*256*256*sizeof(uint32_t);
	ttable = (uint32_t*)malloc(tsize);
	memset(ttable, 0, tsize);

	// Reserve the size for the index and we'll fill it as we go
	fwrite(ttable, 1, tsize, fd);

	// For each DB level:
	for (int l0 = 0; l0 < 256; l0++) {
	for (int l1 = 0; l1 < 256; l1++) {
	for (int l2 = 0; l2 < 256; l2++) {

		std::string fn = outpath + "/" + std::to_string(l0) + "/" + std::to_string(l1) + "/" + std::to_string(l2);
		std::string buffer;

		std::ifstream ifs(fn, std::ifstream::in);
		if (!ifs.good()) continue;

		std::map <int, std::vector<std::string> > d;
		std::string domain; int l3;
		while (ifs >> l3 >> domain) {
			d[l3].push_back(domain);
		}

		for (int l3 = 0; l3 < 256; l3++) {
			const std::vector <std::string> & l = d[l3];
			for ( auto & s : l ) {
				buffer += s;
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
}

