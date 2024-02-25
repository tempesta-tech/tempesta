![Tempesta FW](https://raw.githubusercontent.com/wiki/tempesta-tech/tempesta/tempesta_technologies_logo_small.png)

# Tempesta FW

## What it is?

**Tempesta FW** is an all-in-one open-source solution for high performance web
content delivery and advanced protection against DDoS and web attacks. This is a
drop-in-replacement for the whole web server frontend infrastructure: an HTTPS
load balancer, a web accelerator, a DDoS mitigation system, and a web application
firewall (WAF).

**Tempesta FW** is the first and only hybrid of a Web accelerator and a multi-layer
firewall. This unique architecture provides
[seamless integration](https://tempesta-tech.com/knowledge-base/HTTP-tables/)
with the Linux iptables or nftables.

**Tempesta FW** services up to 1.8M HTTP requests per second on the cheapest hardware,
which is x3 faster than Nginx or HAProxy. **Tempesta TLS** is about 
[40-80% faster than Nginx/OpenSSL and provides up to x4 lower latency](https://netdevconf.info/0x14/session.html?talk-performance-study-of-kernel-TLS-handshakes).


## Demo

Watch the Tempesta FW **demo** in the Security Weekly show -
**[Fast And Secure Web](https://securityweekly.com/shows/fast-and-secure-web-alexander-krizhanovsky-psw-669/)**.


## How it works?

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API or even DPDK or other kernel bypass technology.

We do our best to keep the kernel modifications as small as possible. Current
[patch](https://github.com/tempesta-tech/tempesta/blob/master/linux-5.10.35.patch)
is just about 3,100 lines.


## Current state

We're in [alpha](https://en.wikipedia.org/wiki/Software_release_life_cycle#Alpha)
state for now. The alpha is available by:

* [source code](https://tempesta-tech.com/knowledge-base/Install-from-Sources/)
* [installation script](https://tempesta-tech.com/knowledge-base/Install-from-packages/) (binary packages)

The **master** branch is a development (and unstable) branch for contributers and
early testers only.
Use [release-0.7](https://github.com/tempesta-tech/tempesta/tree/release-0.7) branch
for a stable version.


## Installation and Configuration

Please see our **[Wiki](https://tempesta-tech.com/knowledge-base/home/)** for
following topics:

* [Quick start](https://tempesta-tech.com/knowledge-base/Configuration/#quick-start)
* [Design description](https://tempesta-tech.com/knowledge-base/Home/#design-considerations)
* [System requirements](https://tempesta-tech.com/knowledge-base/Requirements/)
* [Installation procedures](https://tempesta-tech.com/knowledge-base/Installation/)
* [Configuration guide](https://tempesta-tech.com/knowledge-base/Configuration/)
* [Use cases](https://tempesta-tech.com/knowledge-base/Use-cases/)
* [Performance tips & benchmarks](https://tempesta-tech.com/knowledge-base/Performance/)


## We appreciate support of our technical partner

 <a href="https://netactuate.com/"><img src="https://user-images.githubusercontent.com/884694/163684435-f4c9a95f-ab2c-4f3c-8734-81c173677e01.svg" width="300"/></a>
