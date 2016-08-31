
#include <string>
#include <cxxhttpsrv/microrestd.h>
#include "dbreader.h"

using namespace std;
using namespace cxxhttpsrv;

class ReverseIPService : public rest_service {
	class iprev_generator : public response_generator {
	public:
		iprev_generator(uint32_t ip, FILE* f) : f(f), dbreader(f, ip), state(0) {}
		~iprev_generator() { if (f) fclose(f); }

		virtual bool generate() override {
			switch(state) {
			case 0:
				data += "{\"domains\": [\n";
				state++;
				return true;
			case 1:
			case 2: {
				std::string nextdom;
				if (dbreader.nextDomain(nextdom)) {
					if (state == 1)
						state++;
					else
						data += ",";
					data += "\"" + nextdom + "\"\n";
					return true;
				}
				data += "]}\n";
				state = 3;
				} return true;
			default:
				return false;
			};
		}
		virtual string_piece current() const override {
			return string_piece(data.data(), data.size());
		}
		virtual void consume(size_t length) override {
			if (length >= data.size())
				data.clear();
			else if (length)
				data = data.substr(length);
		}

	private:
		FILE* f;
		std::string data;
		DBReader dbreader;
		int state;
	};

public:
	ReverseIPService(std::string fn) : filename(fn) { }
	virtual bool handle(rest_request& req) override {
		if (req.method != "GET") return req.respond_method_not_allowed("GET");

		std::string url = req.url;
		while (url.size() && url[0] == '/')
			url = url.substr(1);

		if (url == "summary") {
			FILE* fd = fopen(filename.c_str(), "rb");
			if (fd) {
				dbfile_summary sum;
				if (DBReader::getSummary(fd, sum)) {
					// Return a JSON encoded summary of the domains crawled!
					std::string dist;
					for (auto kv: sum.ext_dist)
						dist += "  \"" + kv.first + "\": { \"crawled\": " + std::to_string(kv.second.first) + 
							", \"resolved\": " + std::to_string(kv.second.second) + "},\n";
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
					return req.respond("application/json", ret);
				}
			}
			return req.respond_not_found();
		}
		else {
			unsigned int ipf[4];
			int m = sscanf(url.c_str(), "%3u.%3u.%3u.%3u", &ipf[0],&ipf[1],&ipf[2],&ipf[3]);

			if (m != 4 || ipf[0] > 255 || ipf[1] > 255 || ipf[2] > 255 || ipf[3] > 255)
				return req.respond_not_found();

			uint32_t ip = (ipf[0]<<24) | (ipf[1]<<16) | (ipf[2]<<8) | (ipf[3]);

			FILE* fd = fopen(filename.c_str(), "rb");
			if (fd)
				return req.respond("application/json", new iprev_generator(ip, fd));

			return req.respond_not_found();
		}
	}

private:
	std::string filename;
};

int main(int argc, char* argv[]) {
	if (argc < 3) {
		fprintf(stderr, "Usage: %s dbfile port [threads] [connection_limit]\n", argv[0]);
		return 1;
	}
	std::string dbfile(argv[1]);
	int port = stoi(argv[2]);
	int threads = argc >= 4 ? stoi(argv[3]) : 0;
	int connection_limit = argc >= 5 ? stoi(argv[4]) : 2;

	rest_server server;
	server.set_log_file(stderr);
	server.set_max_connections(connection_limit);
	server.set_threads(threads);

	ReverseIPService service(dbfile);
	if (!server.start(&service, port, false)) {
		fprintf(stderr, "Cannot start REST server!\n");
		return 1;
	}
	server.wait_until_signalled();
	server.stop();

	return 0;
}


