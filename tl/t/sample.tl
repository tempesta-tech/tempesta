# Syntax test for Tempesta Language.
#
# Built-in variables:
#	pkt		- IPv4 or IPv6 packet;
#	req		- current client HTTP request;
#	client		- the client descriptor;
#	tdb		- global TempestaDB handler;

# One-shot function to be called at ingress IPv4 packet
if (tdb.select("ip_filter", pkt.src))
	filter(pkt, DROP);

# Sample senseless multi-layer rule
if ((req.user_agent =~ /firefox/i && client.addr == 1.1.1.1)
    || length(req.uri) > 256)
	# Block the client at IP layer, so it will be filtered
	# efficiently w/o further HTTP processing.
	tdb.insert("ip_filter", client.addr);
