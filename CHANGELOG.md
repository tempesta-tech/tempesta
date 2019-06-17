0.6.4 (2019-06-18)

  * Fix TCP sequence numbering when working with fast same-host backends.
  * Handle enormous ciphersuite lists in ClientHello messages.
  * Fix crashes on server-client ciphersuite mismatch.


0.6.3 (2019-05-17)

  * Fix crashes on TLS handshakes utilizing SHA384.
  * Fix crashes on heavily fragmented TLS handshakes.
  * Fix crashes on premature handshake termination from a client.
  * Decrease TLS handshake context a bit.


0.6.2 (2019-03-30)

  * Fix TLS FSM jumps on exiting out of FSM.
  * Fix TLS handshake length calculation.
  * Always use the fastest cryptographic hash hunctions among available on current CPU.


0.6.1 (2019-03-21)

  * Free memory allocated during handshake.
  * fix encoding to chunked: chunk size is hex digit, not decimal.
  * Fix requests and handshakes processing if they are split into multiple skbs.


0.6.0 (2019-02-28)

Enhancements:

  * Make frang directives location-specific.
  * Replace custom skb lists with standard kernel skb lists.
  * Custom characters set for URI and HTTP headers.
  * Fast (AVX) versions of memcpy(), memset(), and memcmp().
  * Update to mbedTLS 2.8.0.
  * Replace HTTP scheduler with more powerful HTTP tables.
  * Block clients which ignore session cookies.
  * Reduce count of IPI during work_queue processing.
  * Add support MSI/MSI-X interrupts during NIC queues configuration.
  * Do not cache if request header contains "Pragma: no-cache"
  * Unload Tempesta modules is start was failed.
  * Fast in-place TLS implementation.
  * If an error happen during request processing, serve all the previous requests before closing the connection.
  * Check sticky cookie before passing request to cache.
  * Store client accounting data in TDB, keep accounting data between client reconnects.

Fixes:

  * Switch 'started' flag to false after start on reload operation had failed.
  * Multiple fixes of reference counting of connection structures.
  * Fix obs-text fields matching.
  * Fix skb leakage on HTTP request processing errors.
  * Fix use-after-free errors due to too early request structure destructions.
  * Keep original port and protocol when send cookie redirect.
  * Restore current fsm state after calling registered hooks.
  * More predictable JS challenge code.
  * Minor fixed in Sticky cookie processing.
  * Prevent possible integer overflows.
  * Copy network headers when single skb contains more than one HTTP message.
  * Prevent gluing of two HTTP messages if first advertised close of the connection.
  * Fix TCP socket write memory accounting
  * Fix skb fragments extending.
  * Don't drop requests if the server connection unexpectedly closed.


0.5.0 (2018-03-21)

  * Add HTTP health monitoring
  * Performance optiomistation and fixes for the On-the-fly reconfiguration
  * Add Referer header support to HTTP match rules
  * Add JavaScript challenge to Sticky Cookie module
  * Add user defined headers to forwarded messages
  * Whitelist requests from web search engines
  * Protect from manual unloading under load
  * Fix of response-request pairing for pipelined messages
  * Many other minor fixes. See git log for more information.


0.5.0-pre8 (2018-01-23)

  * Update supported Linux kernel to 4.9.35
  * Fix memory leaks under high load
  * Add predictive and dynamic ratio scheduler
  * On-the-fly reconfiguration
  * A lot of other bug fixes and improvements


0.5.0-pre7 (2017-03-26)

  * First release
