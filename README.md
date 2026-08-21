# nginx-ssl-fingerprint

A high performance nginx module for ja3 ja4 and http2 fingerprint.

## Patches
 - [nginx - save ja3/ja4/http2 fingerprint](patches)
 - [openssl - preserve the complete ClientHello extension order](patches)

### Support Matrix

|              | openssl-3.5.6 | openssl-3.6.2 | openssl-4.0.1 |
| ------------ | ------------- | ------------- | ------------- |
| nginx-1.29.8 |      ✅       |      ✅       |      ✅       |
| nginx-1.30.0 |      ✅       |      ✅       |      ✅       |
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
| http2_fingerprint | NULL          | The http2 fingerprint.   |

#### Example

```nginx
http {
    server {
        listen                 127.0.0.1:4433 ssl;
        http2                  on;
        ssl_certificate        cert.pem;
        ssl_certificate_key    priv.key;
        error_log              /dev/stderr debug;
        return                 200 "ja3: $http_ssl_ja3\nja4: $http_ssl_ja4\nja4_r: $http_ssl_ja4_r\nh2fp: $http2_fingerprint";
    }
}
```

### Stream module variables

| Name                | Default Value | Comments                 |
| ------------------- | ------------- | ------------------------ |
| stream_ssl_greased  | 0             | TLS greased flag.        |
| stream_ssl_ja3      | NULL          | The ja3 fingerprint.     |
| stream_ssl_ja3_hash | NULL          | The ja3 fingerprint hash.|
| stream_ssl_ja4      | NULL          | The ja4 fingerprint.     |
| stream_ssl_ja4_r    | NULL          | The raw ja4 fingerprint. |

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

# Fuzzing

$ git clone https://github.com/tlsfuzzer/tlsfuzzer
$ cd tlsfuzzer
$ python3 -m venv venv
$ venv/bin/pip install --pre tlslite-ng
$ PYTHONPATH=. venv/bin/python scripts/test-client-hello-max-size.py

```

## Performance

See the repeated, CPU-pinned keepalive, full-handshake, and HTTP/2 [benchmark workflow][actions].

[actions]: https://github.com/fifoqueue/nginx-ssl-fingerprint/actions/workflows/performance.yml
