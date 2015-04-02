// Syntax test for Tempesta Language.
//
// Built-in variables:
//	req		- current client HTTP request;
//	req.chunk	- current chunk of the HTTP request;
//	resp		- server response;
//	clinet		- the client descriptor;

//--------------------------------------------------------------------------
//	Generic test.
//--------------------------------------------------------------------------

// Silently drop all traffic at IP layer from a client for 10 seconds
// if their ever sent a request matching the condition.
if (((re(req.user_agent, "/firefox/i"))
     || !re(req.cookie, "/^our_tracking_cookie/"))
    && (req.x_forwarded_for != "1.1.1.1"
        || client.addr == 1.1.1.1))
	// Block the cloent at IP layer, so it will be filtered efficiently
	// w/o further HTTP processing.
	filter(client, DROP, 10000);


//--------------------------------------------------------------------------
//	Test for HTTP DoS protection.
//	DoS protection section must be the first to drop malicious traffic
//	early.
//--------------------------------------------------------------------------
if (req.method == HTTP_POST && length(req.body) > 4096)
	filter(req, HTTP_413); // drop the request and repy with 413

if (length(req.uri) > 256)
	filter(req, HTTP_414);

// Allow Cookie headers 8KB length at most,
// while length of other haders is limited by 512B.
// header() returns currently processing HTTP header.
if (header(req) == COOKIE) {
	if (length(header(req)) > 8192)
		filter(req, HTTP_431);
}
else if (length(header(req)) > 512)
	filter(req, HTTP_431);
}

if (!(req.method & (HTTP_GET | HTTP_POST)))
	filter(req, HTTP_403);
if (req.method == HTTP_POST && !req.content_type)
	filter(req, HTTP_415);

// re() can do multi-pattern search, return True if found.
if (!re(req.content_type, "/text\/plain/", "/text\/html/"))
	filter(req, HTTP_415);
if (!req.host)
	filter(req, HTTP_400);

// Host header must not be an IP address
if (!re(req.host, "/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/"))
	filter(req, HTTP_400);

// Create new per-request variable.
// Operator '$' creates a new member in predefined variable.
unsigned long $req.ts = req.chunk.ts;

if (req.chunk.ts > req.ts + 100) {
	// Reset the client TCP connection if delay between two HTTP request
	// chunks is more than 100ms.
	filter(client, TCP_RST);
} else {
	// Update the last request chunk timestamp.
	req.ts = req.chunk.ts;
}

// Limit number of established client connections by 10.
if (length(client.conn_list) > 10)
	filter(client, TCP_FIN); // close the connection politely

// Requests limiting (200RPS) with allowed bursts of 100 requests.
struct $client.history[8] {
	unsigned long	ts;
	unsigned int	req;
};
// Temporal variables.
unsigned long ts = req.ts;
unsigned int i = ts % 8;
if (client.history[i].ts != ts) {
	client.history[i].ts = ts;
	client.history[i].req = 0;
}
client.history[i].req++;
if (client.history[i].req > 100)
	filter(req, DROP);
// Collect current request sum.
for (rsum = 0, i = 0; i < 8; i++)
	if (client.history[i].ts + 8 >= ts)
		rsum += client.history[i].req;
if (rsum > 200)
	filter(req, DROP);


//--------------------------------------------------------------------------
//	Test for HTTP requests rewritting
//--------------------------------------------------------------------------
if (re(req.user_agent, "/explorer/i"))
	rewrite(req.uri, "/^(.*)$/", "/msie\/$1/");

rewrite(req.cookie, "/id=([^;]+)(?:;|$)/i", "/id=$1/");


//--------------------------------------------------------------------------
//	Test for HTTP Sticky cookies (issue #29 replacement).
//--------------------------------------------------------------------------

if (!re(req.cookie, "/tfw=([0-9a-fA-F]+)/")) {
	// Calculate cookie for the client.
	unsigned char $client.cookie[SHA1_DIGEST_SIZE];
	client.cookie = hmac(secret, req.ts, req.user_agent, client.addr);
	// Redirect with set cookie.
	Response resp302(req);
	resp302.add_hdr("Location", req.uri);
	resp302.add_hdr("Set-Cookie", "tfw=" + strhex(client.cookie));
	client.send(resp302);
} else {
	// Validate cookie.
	// We can use captured regex variable.
	if ($1 != strhex(client.cookie))
		filter(req, HTTP_403);
	// Pass the request otherwise.
}


//--------------------------------------------------------------------------
//	Test for load balancing.
//	Requests scheduling is placed after all sercurity checks.
//--------------------------------------------------------------------------

// Define server groups with backup servers.
ServerGroup sg_static = {
	server(10.0.1.1, 80),
	server(10.0.1.2, 80),
	server(10.0.1.3, 80, backup),
};
// Precompute server hashes.
for (srv: sg_static)
	unsigned long $srv.hash = hash(srv.addr);

ServerGroup sg_app = {
	server(10.0.1.1, 8080),
	server(10.0.1.2, 8080),
	server(10.0.1.3, 9080, backup),
};
unsigned char $sg_app.rr_ptr = 0;

// Dispatch request to server group.
if (re(req.uri, "/^\/static/")) {
	// Dispatch the request by rendezvous hashig.
	unsigned long h = hash(req.uri + req.host);
	int best_srv = 0;
	unsigned long best_w = h ^ sg_static[best_srv].hash;
	// length() for server group returns not more than
	// number of primary servers.
	for (int i = 1; i < length(sg_static); i++) {
		unsigned long curr_w = h ^ srv.hash;
		if (curr_w > best_w) {
			best_w = curr_w;
			best_srv = i;
		}
	}
	req.dispatch(sg_static[best_srv]);
} else {
	// Dispatch the request in round robin fashion.
	req.dispatch(sg_app[ag_app.rr_ptr++ % length(sg_app)]);
}

