# Tempesta TLS

This is Linux kernel fork from the
[mbed TLS 2.8.0](https://tls.mbed.org/download/start/mbedtls-2.8.0-gpl.tgz)
distributed under GPLv2.

TLS handshakes are susceptible to
[DDoS attacks](https://vincent.bernat.im/en/blog/2011-ssl-dos-mitigation) which
are very effective at depleting resources. Meantime, modern TLS libraries don't
address handshakes performance at all implementing handshakes code in
inefficient way. Tempesta TLS ephasizes TLS handshakes performance to mitigate
DDoS attacks.

The library was significantly reduced in size and is one of the smallest (yet featureful)
TLS implementations. The small size of the cryptography library helps it to be easily
auditable for security vulnerabilities.


# Resources

* [Kernel TLS handshakes for HTTPS DDoS mitigation](https://www.netdevconf.org/0x12/session.html?kernel-tls-handshakes-for-https-ddos-mitigation)
