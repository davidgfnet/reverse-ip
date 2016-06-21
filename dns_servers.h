

// List of DNS servers (both IPv4 and IPv6) that don't hijack
// responses when a domain doesn't have any A records or it
// is unsafe (due to malware or phishing)
// Used this list: http://dns-bh.sagadc.org/20160511.txt

const char * dns_servers[] = {
	"8.8.8.8",              // Google 
	"8.8.4.4",
	"2001:4860:4860::8888", // Google IPv6
	"2001:4860:4860::8844",

	"64.6.64.6",            // Verisign
	"64.6.65.6",
	"2620:74:1b::1:1",      // Verisign IPv6
	"2620:74:1c::2:2",

	"84.200.69.80",               // DNS watch
	"84.200.70.40",
	"2001:1608:10:25::1c04:b12f", // DNS watch IPv6
	"2001:1608:10:25::9249:d69b",

	"74.82.42.42",          // Hurricane Electric
	"2001:470:20::2",

	"109.69.8.51",          // puntCAT
	"2a00:1508:0:4::9",

	"77.88.8.8",            // Yandex
	"77.88.8.1",
	"2a02:6b8::feed:0ff",
	"2a02:6b8:0:1::feed:0ff",

	"216.146.35.35",   // Dyn
	"216.146.36.36",

	"208.67.222.222",  // OpenDNS no-filter
	"208.67.220.220",
	"208.67.222.220",
	"208.67.220.222",

	"91.239.100.100",  // censurfridns.dk
	"89.233.43.71",
	"2001:67c:28a4::",
	"2002:d596:2a92:1:71:53::",

	"37.235.1.174",   // FreeDNS
	"37.235.1.177"
};

