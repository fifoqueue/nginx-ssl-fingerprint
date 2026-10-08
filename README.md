# nginx-ssl-fingerprint

A high performance nginx module for JA3, JA4, JA4H, JA4X, JA4T, JA4L, HTTP/2, QUIC, and HTTP/3 fingerprinting of clients.

## Patches
 - [nginx - save TLS/HTTP2/QUIC/HTTP3 fingerprint state](patches)
 - [openssl - preserve the complete ClientHello extension order](patches)

### Support Matrix

Requires nginx 1.30.0 or newer. Versions below 1.30 are not supported.
CI builds and tests the following releases against each listed OpenSSL version:

|              | openssl-3.5.6 | openssl-3.5.9 | openssl-4.0.3 |
| ------------ | ------------- | ------------- | ------------- |
| nginx-1.30.5 |      ✅       |      ✅       |      ✅       |
| nginx-1.31.4 |      ✅       |      ✅       |      ✅       |
| nginx-1.31.6 |      ✅       |      ✅       |      ✅       |

Use the patch matching your release in `patches/`.
Patches for 1.30.0 and 1.31.3 remain available but are outside the CI matrix.
GitHub `master` (development/nightly) has a separate [best-effort patch](patches/master.patch),
based on nginx commit `2b5c2b605b5df669da5dec6749dcc76c07d1315d`.
It is not tested by CI and may need rebasing as upstream changes.
New releases are not automatically supported until their patch and tests have been checked.

## Configuration

### HTTP module variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| http_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| http_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| http_ssl_ja4_r    | NULL          | The raw ja4 fingerprint. |
| http_ssl_ja4h     | NULL          | HTTP request JA4H; also available on plain HTTP. |
| http_ssl_ja4h_r   | NULL          | Raw JA4H, including cookie names and values. |
| http_ssl_client_ja4x | NULL       | JA4X of the peer's leaf certificate, when supplied. |
| http_ssl_client_ja4x_r | NULL     | Raw peer leaf certificate OID sequences. |
| http_ssl_ja4t     | NULL          | Client TCP SYN JA4T; requires `tcp_save_syn on`. |
| http_ssl_ja4l     | NULL          | Packet-observed client JA4L; requires `ja4l_capture`. |
| http_ssl_ja4l_delta | NULL        | Client application/TCP latency ratio, rounded to one decimal. |
| http_ssl_alpn     | NULL          | Client-offered ALPN list.|
| http2_fingerprint | NULL          | The http2 fingerprint.   |
| quic_version      | NULL          | QUIC version as 8 hex digits. |
| quic_initial_packet_size | NULL   | Accepted Initial UDP datagram size. |
| quic_dcid_length  | NULL          | Initial DCID length.      |
| quic_scid_length  | NULL          | Initial SCID length.      |
| quic_transport_parameters | NULL  | Ordered, canonical client transport parameters. |
| quic_transport_parameters_normalized | NULL | Canonical parameters sorted by numeric ID; GREASE last. |
| quic_transport_parameters_raw | NULL | Exact transport-parameter bytes as hex. |
| quic_retry        | NULL          | `1` after a validated Retry, otherwise `0`. |
| quic_version_negotiation | NULL   | `original>negotiated`, or `0`. |
| http3_settings    | NULL          | Ordered HTTP/3 SETTINGS.  |
| http3_qpack       | NULL          | `max_table_capacity:blocked_streams`. |
| http3_fingerprint | NULL          | Perk-style HTTP/3 fingerprint. |
| http3_fingerprint_hash | NULL     | MD5 of `http3_fingerprint`. |
| http3_perk | NULL                 | Alias of `http3_fingerprint`. |
| http3_perk_hash | NULL            | Alias of `http3_fingerprint_hash`. |
| http3_perk_normalized | NULL      | Perk normalized transport-parameter variant. |
| http3_perk_hash_normalized | NULL | MD5 of `http3_perk_normalized`. |

JA4 follows the [FoxIO JA4 specification][ja4], including the `q` transport prefix for QUIC.
`http_ssl_alpn` contains every protocol offered by the client; unsafe bytes are percent-encoded.

### JA4+ scope and semantics

The module implements the JA4+ methods that describe the client, measured from nginx's HTTP/TLS state, Linux's saved incoming SYN, and optional Linux packet capture.
The existing nginx version patches include the required capture hooks; rebuild nginx with the updated patch.

| Methods | Support |
| --- | --- |
| JA4, JA4H | TLS ClientHello and HTTP requests, including HTTP/2 and HTTP/3. |
| JA4X | Client leaf certificate, when one is presented. |
| JA4T | Incoming TCP SYN on Linux; IPv4 and IPv6. |
| JA4L and Delta | Linux packet capture for TCP/TLS and QUIC v1, with IPv4 and IPv6. |

JA4H excludes Cookie, Referer, pseudo-headers, and nginx's synthesized HTTP/2 Host header from the header hash.
Actual header names retain case and order.
Cookie pairs are sorted by name, preserving order for duplicate names; values are split at the first `=`.
Empty cookie segments are ignored.
Method codes, language encoding, and empty hashes follow FoxIO's Wireshark implementation.
HTTP/3 uses the same rules with version `30`.
JA4H is cached per main request; internal subrequests share the incoming request's fingerprint.
`http_ssl_ja4h_r` contains cookie values: use it only for controlled diagnostics, not ordinary access logs.

JA4X hashes the client leaf certificate's issuer, subject, and extension OID sequences in certificate order.
`http_ssl_client_ja4x` is empty unless nginx requests a client certificate (`ssl_verify_client`) and the client presents one.

Enable JA4T explicitly in `http`, `server`, or `stream` scope:

```nginx
tcp_save_syn on;
```

SYN capture defaults to off.
It applies to the listening socket, including all virtual servers sharing that socket.
It costs kernel memory until accept and connection-pool memory afterward.
Large saved headers are allocated using the size returned by the kernel.
The SYN is consumed once at accept, and JA4T is computed lazily and cached on the real TCP connection, including for HTTP/2.
JA4T is available for captured IPv4/IPv6 TCP SYNs on Linux.
Connections without a saved SYN return an empty value.
Behind a TCP proxy, JA4T describes the proxy-to-nginx connection.
The existing `nginx.conf` enables capture and exposes all new variables for local testing, including plain HTTP on port 4435.

### JA4L packet capture

JA4L uses Linux `AF_PACKET` capture and kernel `SO_TIMESTAMPNS` timestamps.
Capture is disabled by default.
The nginx master needs `CAP_NET_RAW` when opening the capture sockets.

```nginx
# Main context: select the interface carrying the client traffic.
ja4l_capture eth0;
ja4l_max_flows 16384;  # per worker, default
ja4l_timeout 30s;      # retention of observations no connection claimed, default

http {
    tcp_save_syn on;  # associate TCP observations with accepted connections
    # ...
}
```

Packet selection and rendering follow the pinned FoxIO Wireshark reference in [NOTICE](NOTICE).
TCP measurements use SYN, SYN-ACK, ACK, and the first client/server/client payload packets.
TLS results contain `TCP_one_way_us_TTL_application_one_way_us`; HTTP/1 without TLS uses `TCP_one_way_us_TTL_tcp`.
QUIC Initial and Handshake packets, including coalesced packets, produce `one_way_us_TTL_quic`.
The delta variable reports the client's TLS application/TCP latency ratio rounded to one decimal.
All one-way durations are computed from full nanosecond differences divided by 2000.

IPv4 and IPv6 observations are associated with the actual socket endpoints.
TCP also matches the saved SYN sequence number; QUIC matches the client's connection ID.
Completed observations remain available for the connection, including subsequent HTTP/2 streams and HTTP/3 requests.
TLS stream connections expose the same measurements through `stream_ssl_ja4l*`.

The master creates one filtered packet socket per worker.
Filters select eligible nginx listener ports on the configured interface and are locked before workers inherit the sockets.
Loopback uses the transmit tap once per packet, where the kernel supplies a shared timestamp before delivering socket copies.
Other interfaces capture both received and transmitted packets.
The filter passes TCP truncated to its headers and only QUIC long-header datagrams, and drops IPv4 fragments, so payload is never copied to user space; flow records retain only connection metadata and times.
Malformed packets and fragments are ignored and cannot invalidate other observations.

Capture work scales with worker count.
Each socket gets a 2 MiB receive buffer (`SO_RCVBUFFORCE` when the master has `CAP_NET_ADMIN`, otherwise capped by `rmem_max`); the BPF filter supports up to 1017 distinct listener ports.
Every worker observes every connection but claims only its own, so when the per-worker flow limit is reached the oldest unclaimed record is evicted.
Incomplete, expired, unmatched, or invalid observations return an empty variable.
Detected packet loss discards pending observations and drains the affected queue before recording fresh handshakes.
TCP measurement requires a saved SYN and the complete three-way handshake.
The delta variable is empty for the `tcp` and `quic` formats.

The Python tests compare TCP and QUIC values exactly with timestamps from an independent packet socket.
Run them with a test server using `ja4l_capture lo;`, packet-capture privileges for the test process, and `JA4L_TEST=1`.
The existing `NGINX_HOST` and port environment variables select IPv4 or IPv6 test listeners.

JA4+ portions are covered by [FoxIO License 1.1](LICENSE-JA4PLUS), separately from this repository's original [BSD license](LICENSE).
FoxIO's [licensing FAQ](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) distinguishes internal use from monetization, which requires an OEM license.
Attribution and pinned reference revisions are recorded in [NOTICE](NOTICE).

### QUIC and HTTP/3 formats

`quic_transport_parameters` preserves wire order.
Standard integer values are rendered in decimal, opaque values in lowercase hex, QUIC GREASE parameters as `GREASE`, and the random `initial_source_connection_id` value as `AUTO`.
`quic_transport_parameters_normalized` sorts numeric IDs and places GREASE last, matching the normalized Perk form.
Use `quic_transport_parameters_raw` when the exact RFC 9000 wire bytes are needed.
Known integer decoding follows the current [IANA QUIC registry][iana-quic]; unrecognized values remain lossless lowercase hex.

`http3_fingerprint` and `http3_perk` use the currently deployed [Perk-style layout][perk]: `SETTINGS|pseudo-header-order|transport-parameters|DCID-length,SCID-length`.
The normalized aliases use the same SETTINGS, pseudo-header order, and CID lengths with sorted transport parameters.
The raw variables preserve the individual captured fields.
SETTINGS order and values are preserved without a fixed entry cutoff.

Retry detection is exact after nginx validates the returned token.
In a Retry flow, `quic_initial_packet_size` describes the accepted post-Retry Initial while `quic_dcid_length` is restored from the original client Initial.
Version Negotiation spans two QUIC connections, so it is correlated heuristically by listener and client UDP endpoint for five seconds using a dynamically growing per-worker hash table.

The listed nginx releases accept QUIC v1.
Version Negotiation records the attempted version.

### Compatibility and public lookup

| Output | Compatibility target | Public lookup |
| ------ | -------------------- | ------------- |
| `http_ssl_ja4` on QUIC | FoxIO JA4 (`q` transport prefix) | Queryable as a JA4 key in [JA4DB] and [Foil]; attribution requires a corpus match. |
| `http2_fingerprint` | Akamai HTTP/2 layout: `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-order` | Format-compatible, but not a JA4 key. |
| `http3_perk*` | Current impersonate.pro Perk raw and normalized layouts | Comparable with the [Perk diagnostic API][perk]; it is not a global attribution database. |
| QUIC scalar/raw variables | RFC 9000/9001 wire values and server-observed Retry/VN state | Evidence fields, not standardized database keys. |

HTTP/2 SETTINGS and pseudo-header order retain wire order without a fixed entry cutoff.

The test suite decrypts FoxIO's official QUIC fixture and asserts its published JA4 exactly.
Scheduled CI also searches a known Chromium QUIC JA4 on Foil and compares live HTTP/2 and aioquic requests with impersonate.pro's Akamai and Perk outputs.
It watches IANA's permanent QUIC transport-parameter and HTTP SETTINGS registries for drift.
Network diagnostics are allowed to skip when the public service or UDP egress is unavailable; all offline format fixtures remain mandatory.

Representative formats:

```text
http_ssl_ja4=q13d0312h3_55b375c5d22e_06cda9e17597
quic_version=00000001
quic_initial_packet_size=1200
quic_dcid_length=8
quic_scid_length=8
quic_transport_parameters=15:AUTO;1:30000
quic_transport_parameters_normalized=1:30000;15:AUTO
quic_transport_parameters_raw=0f00010480007530
quic_retry=1
quic_version_negotiation=1a2a3a4a>00000001
http3_settings=1:65536;6:262144;7:100;51:1;GREASE
http3_qpack=65536:100
http3_perk=1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|15:AUTO;1:30000|8,8
http3_perk_hash=3bfe1d06b25e25d77abb81225ba226cc
http3_perk_normalized=1:65536;6:262144;7:100;51:1;GREASE|m,a,s,p|1:30000;15:AUTO|8,8
http3_perk_hash_normalized=27b75a2b74b1b708fa9897ec38668823
```

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl;
        listen                 127.0.0.1:4434 quic reuseport;
        http2                  on;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja4: $http_ssl_ja4\nquic: $quic_version\ntp: $quic_transport_parameters\nh3fp: $http3_fingerprint\nh2fp: $http2_fingerprint";
    }
}
```

[ja4]: https://github.com/FoxIO-LLC/ja4
[JA4DB]: https://ja4db.com/
[Foil]: https://usefoil.com/ja4/q13d0312h3_55b375c5d22e_06cda9e17597
[perk]: https://impersonate.pro/docs/api
[iana-quic]: https://www.iana.org/assignments/quic/

### Stream module variables

| Name                | Default Value | Comments                 |
| ------------------- | ------------- | ------------------------ |
| stream_ssl_greased  | 0             | TLS greased flag.        |
| stream_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| stream_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| stream_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| stream_ssl_ja4_r    | NULL          | The raw ja4 fingerprint. |
| stream_ssl_client_ja4x | NULL       | Peer leaf certificate JA4X, when supplied. |
| stream_ssl_client_ja4x_r | NULL     | Raw peer leaf certificate OIDs. |
| stream_ssl_ja4t     | NULL          | TCP SYN JA4T; requires `tcp_save_syn on`. |
| stream_ssl_ja4l     | NULL          | Client JA4L for TLS stream connections. |
| stream_ssl_ja4l_delta | NULL        | Client application/TCP latency ratio. |
| stream_ssl_alpn     | NULL          | Client-offered ALPN list.|

#### Example

```nginx
stream {
    server {
        listen                 127.0.0.1:4443 ssl;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 "ja4: $stream_ssl_ja4\nja4_r: $stream_ssl_ja4_r\n";
    }
}
```


## Quick Start

```bash

# Clone

$ git clone -b openssl-4.0.3 --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.30.5 --depth=1 https://github.com/nginx/nginx
$ git clone -b master https://github.com/fifoqueue/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl-4.0.3.patch
$ patch --batch --fuzz=0 -p1 -d nginx < nginx-ssl-fingerprint/patches/release-1.30.5.patch

# Build

$ cd nginx
$ ASAN_OPTIONS=symbolize=1 ./auto/configure --with-openssl=$(pwd)/../openssl --with-openssl-opt=no-tests --add-module=$(pwd)/../nginx-ssl-fingerprint --with-http_ssl_module --with-stream_ssl_module --with-debug --with-stream --with-http_v2_module --with-http_v3_module --with-cc-opt="-fsanitize=address -O -fno-omit-frame-pointer -DNGX_DEBUG_PALLOC=1" --with-ld-opt="-L/usr/local/lib -Wl,-E -lasan"
$ make

# Test

$ objs/nginx -p . -c $(pwd)/../nginx-ssl-fingerprint/nginx.conf
$ curl -k https://127.0.0.1:4433
$ python3 -m pip install aioquic 'httpx[http2]' h2
$ python3 ../nginx-ssl-fingerprint/tests/test_fingerprint.py
$ python3 ../nginx-ssl-fingerprint/tests/test_quic_fingerprint.py

# Fuzzing

$ git clone https://github.com/tlsfuzzer/tlsfuzzer
$ cd tlsfuzzer
$ python3 -m venv venv
$ venv/bin/pip install --pre tlslite-ng
$ PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

```

## Performance

QUIC transport parameters are copied from nginx's existing peer-parameter callback, so the TCP/TLS path performs no QUIC extension lookup.
ALPN/QUIC and JA4+ state share the connection sidecar, allocated when a sidecar field is first needed.
JA4X is computed on first variable access.
Canonical transport parameters, HTTP/3 SETTINGS/QPACK, and fingerprints are generated lazily and cached at connection or request scope.
The first eight HTTP/2 and HTTP/3 SETTINGS stay in an allocation-free inline fast path; only unusual overflow is grown from the connection pool.
No captured SETTINGS entry is discarded for performance.

See the repeated, CPU-pinned keepalive, full-handshake, HTTP/2, and HTTP/3 [benchmark workflow][actions].

[actions]: https://github.com/fifoqueue/nginx-ssl-fingerprint/actions/workflows/performance.yml
