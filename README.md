# nginx-ssl-fingerprint

A high performance nginx module for JA3, JA4, HTTP/2, QUIC, and HTTP/3 fingerprinting.

## Patches
 - [nginx - save TLS/HTTP2/QUIC/HTTP3 fingerprint state](patches)
 - [openssl - preserve the complete ClientHello extension order](patches)

### Support Matrix

|              | openssl-3.5.6 | openssl-3.6.2 | openssl-4.0.1 |
| ------------ | ------------- | ------------- | ------------- |
| nginx-1.29.8 |      ✅       |      ✅       |      ✅       |
| nginx-1.30.0 |      ✅       |      ✅       |      ✅       |
| nginx-1.31.3 |      ✅       |      ✅       |      ✅       |
| nginx-1.31.4 |      ✅       |      ✅       |      ✅       |

## Configuration

### HTTP module variables

| Name              | Default Value | Comments                 |
| ----------------- | ------------- | ------------------------ |
| http_ssl_greased  | 0             | TLS greased flag.        |
| http_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| http_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| http_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| http_ssl_ja4_r    | NULL          | The raw ja4 fingerprint. |
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

JA4 follows the [FoxIO JA4 specification][ja4], including the `q` transport prefix for QUIC. `http_ssl_alpn` contains every protocol offered by the client; unsafe bytes are percent-encoded.

`quic_transport_parameters` preserves wire order. Standard integer values are rendered in decimal, opaque values in lowercase hex, QUIC GREASE parameters as `GREASE`, and the random `initial_source_connection_id` value as `AUTO`. `quic_transport_parameters_normalized` sorts numeric IDs and places GREASE last, matching the normalized Perk form. Use `quic_transport_parameters_raw` when the exact RFC 9000 wire bytes are needed. Known integer decoding follows the current [IANA QUIC registry][iana-quic]; unrecognized values remain lossless lowercase hex.

`http3_fingerprint` and `http3_perk` use the currently deployed [Perk-style layout][perk]: `SETTINGS|pseudo-header-order|transport-parameters|DCID-length,SCID-length`. The normalized aliases use the same SETTINGS, pseudo-header order, and CID lengths with sorted transport parameters. HTTP/3 and QUIC do not yet have a single JA4-equivalent standard covering all these fields, so the raw variables remain the stable interface. SETTINGS order and values are preserved without a fixed entry cutoff.

Retry detection is exact after nginx validates the returned token. In a Retry flow, `quic_initial_packet_size` describes the accepted post-Retry Initial while `quic_dcid_length` is restored from the original client Initial. Version Negotiation spans two QUIC connections, so it is correlated heuristically by listener and client UDP endpoint for five seconds using a dynamically growing per-worker hash table.

The listed nginx releases currently accept QUIC v1. The variable encoding is version-agnostic and Version Negotiation records the attempted version, but this module does not add QUIC v2 protocol support to nginx itself.

### Compatibility and public lookup

| Output | Compatibility target | Public lookup |
| ------ | -------------------- | ------------- |
| `http_ssl_ja4` on QUIC | FoxIO JA4 (`q` transport prefix) | Queryable as a JA4 key in [JA4DB] and [Foil]; attribution requires a corpus match. |
| `http2_fingerprint` | Akamai HTTP/2 layout: `SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo-order` | Format-compatible, but not a JA4 key. |
| `http3_perk*` | Current impersonate.pro Perk raw and normalized layouts | Comparable with the [Perk diagnostic API][perk]; it is not a global attribution database. |
| QUIC scalar/raw variables | RFC 9000/9001 wire values and server-observed Retry/VN state | Evidence fields, not standardized database keys. |

HTTP/2 SETTINGS and pseudo-header order retain wire order without a fixed entry cutoff.

The test suite decrypts FoxIO's official QUIC fixture and asserts its published JA4 exactly. Scheduled CI also searches a known Chromium QUIC JA4 on Foil and compares live HTTP/2 and aioquic requests with impersonate.pro's Akamai and Perk outputs. It watches IANA's permanent QUIC transport-parameter and HTTP SETTINGS registries for drift. Network diagnostics are allowed to skip when the public service or UDP egress is unavailable; all offline format fixtures remain mandatory.

Cisco Mercury's QUIC NPF is a separate fingerprint grammar and is not emitted under these variable names. Treating JA4, Perk, and NPF as interchangeable would produce keys that no database can reliably match.

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

$ git clone -b openssl-4.0.1 --depth=1 https://github.com/openssl/openssl
$ git clone -b release-1.31.4 --depth=1 https://github.com/nginx/nginx
$ git clone -b master https://github.com/fifoqueue/nginx-ssl-fingerprint

# Patch

$ patch -p1 -d openssl < nginx-ssl-fingerprint/patches/openssl-4.0.1.patch
$ patch -p1 -d nginx < nginx-ssl-fingerprint/patches/release-1.31.4.patch

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

QUIC transport parameters are copied from nginx's existing peer-parameter callback, so the TCP/TLS path performs no QUIC extension lookup. New ALPN/QUIC state lives in a lazily allocated sidecar; ordinary TLS connections retain only its pointer and an ALPN offset. Canonical transport parameters, HTTP/3 SETTINGS/QPACK, and fingerprints are generated lazily and cached at connection or request scope. The first eight HTTP/2 and HTTP/3 SETTINGS stay in an allocation-free inline fast path; only unusual overflow is grown from the connection pool. No captured SETTINGS entry is discarded for performance.

See the repeated, CPU-pinned keepalive, full-handshake, HTTP/2, and HTTP/3 [benchmark workflow][actions].

[actions]: https://github.com/fifoqueue/nginx-ssl-fingerprint/actions/workflows/performance.yml
