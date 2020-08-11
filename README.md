![Tempesta FW](https://raw.githubusercontent.com/wiki/tempesta-tech/tempesta/tempesta_technologies_logo_small.png)

# Tempesta FW

## What it is?

**Tempesta FW** is an all-in-one open-source solution for high performance web
content delivery and advanced protection against DDoS and web attacks. This is a
drop-in-replacement for the whole web server frontend infrastructure: an HTTPS
load balancer, a web accelerator, a DDoS mitigation system, and a web application
firewall (WAF).

**Tempesta FW** is the first and only hybrid of a Web accelerator and a multi-layer
firewall. This unique architecture provides efficient blocking of any malicious traffic
and outstanding performance of web applications in normal operation. The architecture is
the result of collecting and application of
[state-of-the-art research and cutting edge technologies](http://tempesta-tech.com/company#research).

**Tempesta FW** services up to 1.8M HTTP requests per second on the cheapest hardware.
The benchmark results are open and can be easily proven. Our performance results are
beyond the reach of other modern web accelerators.


## How it works?

**Tempesta FW** is built into Linux TCP/IP stack for better and more stable
performance characteristics in comparison with TCP servers on top of common
Socket API or even DPDK or other kernel bypass technology.

We do our best to keep the kernel modifications as small as possible. Current
[patch](https://github.com/tempesta-tech/tempesta/blob/master/linux-4.14.32.patch)
is just about 2,700 lines.


## Current state

We're in [alpha](https://en.wikipedia.org/wiki/Software_release_life_cycle#Alpha)
state for now. The alpha is available by:

* [source code](https://github.com/tempesta-tech/tempesta/wiki/Install-from-Sources)
* [binary packages](https://github.com/tempesta-tech/tempesta/releases)
* [installation script](https://github.com/tempesta-tech/tempesta/wiki/Install-from-packages#using-installer-script)

The **master** branch is unstable and contains code for upcoming beta.


## Installation and Configuration

Please see our **[Wiki](https://github.com/tempesta-tech/tempesta/wiki)** for
following topics:

* [Design description](https://github.com/tempesta-tech/tempesta/wiki)
* [System requirements](https://github.com/tempesta-tech/tempesta/wiki/Requirements)
* [Installation procedures](https://github.com/tempesta-tech/tempesta/wiki/Installation)
* [Configuration guide](https://github.com/tempesta-tech/tempesta/wiki/Configuration)
* [Use cases](https://github.com/tempesta-tech/tempesta/wiki/Use-cases)
* [Performance benchmarks](https://github.com/tempesta-tech/tempesta/wiki/Benchmarks)
