# Tempesta TLS

Originally **Tempesta TLS** was forked from GPLv2 version of
[mbed TLS 2.8.0](https://tls.mbed.org/download/start/mbedtls-2.8.0-gpl.tgz).
However, it was significantly reworked to make the code fast, so at the moment
only interface code PKI is left from the original mbed TLS code.
The main changes are:
* Zero-copy I/O;
* Awareness about current TCP congestion and receive windows;
* Completely removed memory allocations and MPI overheads in the hot paths;
* Using Linux native crypto API with optimized algorithm implementations.

**Tempesta TLS** implements fast TLS handshakes and uses the native Linux
crypto API for the symmetric cryptography algorithms. TLS handshakes are
susceptible to
[DDoS attacks](https://vincent.bernat.im/en/blog/2011-ssl-dos-mitigation) which
are very effective at depleting resources. Meantime, modern TLS libraries don't
address handshakes performance at all implementing handshakes code in
inefficient way. **Tempesta TLS** emphasizes TLS handshakes performance to
mitigate DDoS attacks.

The library was significantly reduced in size and is one of the smallest (yet
featureful) TLS implementations. The small size of the cryptography library
helps it to be easily auditable for security vulnerabilities.

Theoretically, the kernel implementation provides more security (see
[Applied Cryptography](https://www.schneier.com/books/applied_cryptography/) by
Bruce Schneier, chapter 8.5) in comparison with traditional user space
applications because all the secrets are kept in the kernel memory and are not
swappable. The kernel address space keeps all the security sensitive data, such
as private and session keys. An application logic runs in a separate address
space, the user space, and is likely to be vulnerable due frequent code updates.
If an attacker breaks the user space application logic, they still can't get access
to the security sensitive data.

# Resources

* [Kernel TLS handshakes for HTTPS DDoS mitigation](https://www.netdevconf.org/0x12/session.html?kernel-tls-handshakes-for-https-ddos-mitigation)
* [Performance study of kernel TLS handshakes](https://netdevconf.info/0x14/session.html?talk-performance-study-of-kernel-TLS-handshakes)
