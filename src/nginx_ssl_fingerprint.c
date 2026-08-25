#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_log.h>
#include <ngx_http_v2.h>
#if (NGX_HTTP_V3)
#include <ngx_http_v3.h>
#endif
#include <ngx_md5.h>
#include <openssl/sha.h>

#include <nginx_ssl_fingerprint.h>

#define IS_GREASE_CODE(code) (((code)&0x0f0f) == 0x0a0a && ((code)&0xff) == ((code)>>8))
#define IS_ASCII_ALNUM(ch)                                                   \
    (((ch) >= '0' && (ch) <= '9') || ((ch) >= 'A' && (ch) <= 'Z')          \
     || ((ch) >= 'a' && (ch) <= 'z'))

static inline uint16_t
read_uint16(const u_char *src)
{
    uint16_t  n;

    ngx_memcpy(&n, src, sizeof(n));
    return n;
}

static inline u_char *
write_uint16(u_char *dst, uint16_t n)
{
    ngx_memcpy(dst, &n, sizeof(n));
    return dst + sizeof(n);
}

static ngx_int_t
add_size(size_t *total, size_t n)
{
    if (n > NGX_MAX_SIZE_T_VALUE - *total) {
        return NGX_ERROR;
    }

    *total += n;
    return NGX_OK;
}

static int
compare_uint16(const void *one, const void *two)
{
    uint16_t  first, second;

    first = *(const uint16_t *) one;
    second = *(const uint16_t *) two;

    return (first > second) - (first < second);
}

ngx_int_t
ngx_ssl_client_hello_get_ja_data(ngx_ssl_conn_t *ssl, ngx_pool_t *pool,
    ngx_str_t *out, uint32_t *alpn_offset)
{
    const u_char  *ciphers, *groups, *formats, *sigalgs, *supvers, *alpn;
    u_char        *data, *ptr;
    size_t         ciphers_len, groups_len, formats_len, sigalgs_len,
                   supvers_len, alpn_len, num_exts, n, required;
    uint16_t       value;
    ngx_flag_t     have_groups, have_formats, have_sigalgs, have_supvers,
                   have_alpn;

    *alpn_offset = 0;

    ciphers_len = SSL_client_hello_get0_ciphers(ssl, &ciphers);
    if (ciphers_len > 65535 || (ciphers_len & 1) != 0) {
        return NGX_ERROR;
    }

    num_exts = 0;
    if (SSL_client_hello_get_extension_order(ssl, NULL, &num_exts) != 1
        || num_exts > 65535 / sizeof(uint16_t))
    {
        return NGX_ERROR;
    }

    have_groups = SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_groups,
                                             &groups, &groups_len) == 1;
    have_formats = SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ec_point_formats,
                                             &formats, &formats_len) == 1;
    have_sigalgs = SSL_client_hello_get0_ext(ssl,
                                             TLSEXT_TYPE_signature_algorithms,
                                             &sigalgs, &sigalgs_len) == 1;
    have_supvers = SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_supported_versions,
                                             &supvers, &supvers_len) == 1;
    have_alpn = SSL_client_hello_get0_ext(ssl,
        TLSEXT_TYPE_application_layer_protocol_negotiation,
        &alpn, &alpn_len) == 1;

    if ((have_groups && (groups_len < sizeof(uint16_t) || groups_len > 65535))
        || (have_formats && (formats_len < sizeof(uint8_t)
                             || formats_len > 65535))
        || (have_sigalgs && (sigalgs_len < sizeof(uint16_t)
                             || sigalgs_len > 65535))
        || (have_alpn && (alpn_len < sizeof(uint16_t) || alpn_len > 65535)))
    {
        return NGX_ERROR;
    }

    required = sizeof(uint16_t) * 3;
    if (add_size(&required, ciphers_len) != NGX_OK
        || add_size(&required, num_exts * sizeof(uint16_t)) != NGX_OK
        || add_size(&required, have_groups ? groups_len : sizeof(uint16_t))
           != NGX_OK
        || add_size(&required, sizeof(uint16_t) + (have_formats ? formats_len : 0))
           != NGX_OK
        || add_size(&required, sizeof(uint16_t)) != NGX_OK
        || add_size(&required, have_sigalgs ? sigalgs_len : sizeof(uint16_t))
           != NGX_OK
        || add_size(&required, have_alpn ? alpn_len : sizeof(uint16_t))
           != NGX_OK)
    {
        return NGX_ERROR;
    }

    data = ngx_palloc(pool, required);
    if (data == NULL) {
        return NGX_ERROR;
    }

    ptr = data;
    ptr = write_uint16(ptr,
        (uint16_t) SSL_client_hello_get0_legacy_version(ssl));
    ptr = write_uint16(ptr, (uint16_t) ciphers_len);
    if (ciphers_len != 0) {
        ngx_memcpy(ptr, ciphers, ciphers_len);
        ptr += ciphers_len;
    }

    ptr = write_uint16(ptr, (uint16_t) (num_exts * sizeof(uint16_t)));
    n = num_exts;
    if (SSL_client_hello_get_extension_order(ssl, (uint16_t *) ptr, &n) != 1
        || n != num_exts)
    {
        return NGX_ERROR;
    }
    ptr += num_exts * sizeof(uint16_t);

    if (have_groups) {
        ngx_memcpy(ptr, groups, groups_len);
        write_uint16(ptr, (uint16_t) groups_len);
        ptr += groups_len;
    } else {
        ptr = write_uint16(ptr, 0);
    }

    ptr = write_uint16(ptr, (uint16_t) (have_formats ? formats_len : 0));
    if (have_formats) {
        ngx_memcpy(ptr, formats, formats_len);
        ptr += formats_len;
    }

    value = 0;
    if (have_supvers && supvers_len >= 3) {
        for (n = 1; n + 1 < supvers_len
                    && n < (size_t) supvers[0] + 1;
             n += 2)
        {
            uint16_t  candidate;

            candidate = ((uint16_t) supvers[n] << 8) | supvers[n + 1];
            if (!IS_GREASE_CODE(candidate) && candidate > value) {
                value = candidate;
            }
        }
    }
    ptr = write_uint16(ptr, value);

    if (have_sigalgs) {
        ngx_memcpy(ptr, sigalgs, sigalgs_len);
        write_uint16(ptr, (uint16_t) sigalgs_len);
        ptr += sigalgs_len;
    } else {
        ptr = write_uint16(ptr, 0);
    }

    if (have_alpn) {
        *alpn_offset = (uint32_t) (ptr - data);
        ngx_memcpy(ptr, alpn, alpn_len);
        write_uint16(ptr, (uint16_t) alpn_len);
        ptr += alpn_len;
    } else {
        ptr = write_uint16(ptr, 0);
    }

    out->data = data;
    out->len = ptr - data;

    return NGX_OK;
}

static inline
unsigned char *append_uint8(unsigned char* dst, uint8_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }

    return dst;
}

static inline
unsigned char *append_uint16(unsigned char* dst, uint16_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    }  else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    }

    return dst;
}

static inline
unsigned char *append_uint32(unsigned char* dst, uint32_t n)
{
    if (n < 10) {
        dst[0] = n + '0';
        dst++;
    } else if (n < 100) {
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 2;
    } else if (n < 1000) {
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 3;
    } else if (n < 10000) {
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 4;
    } else if (n < 100000) {
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 5;
    } else if (n < 1000000) {
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 6;
    } else if (n < 10000000) {
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 7;
    } else if (n < 100000000) {
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 8;
    } else if (n < 1000000000) {
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 9;
    } else {
        dst[9] = n % 10 + '0';
        n /= 10;
        dst[8] = n % 10 + '0';
        n /= 10;
        dst[7] = n % 10 + '0';
        n /= 10;
        dst[6] = n % 10 + '0';
        n /= 10;
        dst[5] = n % 10 + '0';
        n /= 10;
        dst[4] = n % 10 + '0';
        n /= 10;
        dst[3] = n % 10 + '0';
        n /= 10;
        dst[2] = n % 10 + '0';
        n /= 10;
        dst[1] = n % 10 + '0';
        dst[0] = n / 10 + '0';
        dst += 10;
    }

    return dst;
}

static inline u_char *
append_uint64(u_char *dst, uint64_t n)
{
    u_char  buf[20], *p;

    p = buf + sizeof(buf);
    do {
        *--p = (u_char) ('0' + n % 10);
        n /= 10;
    } while (n != 0);

    return ngx_cpymem(dst, p, (buf + sizeof(buf)) - p);
}

static ngx_int_t
parse_quic_varint(const u_char **pos, const u_char *end, uint64_t *value)
{
    const u_char  *p;
    size_t         i, len;
    uint64_t       n;

    p = *pos;
    if (p == end) {
        return NGX_ERROR;
    }

    len = (size_t) 1 << (*p >> 6);
    if ((size_t) (end - p) < len) {
        return NGX_ERROR;
    }

    n = *p++ & 0x3f;
    for (i = 1; i < len; i++) {
        n = (n << 8) | *p++;
    }

    *pos = p;
    *value = n;
    return NGX_OK;
}

typedef struct {
    uint64_t       id;
    const u_char  *data;
    size_t         len;
} ngx_ssl_quic_tp_t;

static ngx_int_t
next_quic_transport_param(const u_char **pos, const u_char *end,
    ngx_ssl_quic_tp_t *tp)
{
    const u_char  *p;
    uint64_t       len;

    p = *pos;
    if (p == end) {
        return NGX_DONE;
    }

    if (parse_quic_varint(&p, end, &tp->id) != NGX_OK
        || parse_quic_varint(&p, end, &len) != NGX_OK
        || len > (uint64_t) (end - p))
    {
        return NGX_ERROR;
    }

    tp->data = p;
    tp->len = (size_t) len;
    *pos = p + tp->len;
    return NGX_OK;
}

static ngx_flag_t
quic_transport_param_is_integer(uint64_t id)
{
    switch (id) {
    case 0x01: /* max_idle_timeout */
    case 0x03: /* max_udp_payload_size */
    case 0x04: /* initial_max_data */
    case 0x05: /* initial_max_stream_data_bidi_local */
    case 0x06: /* initial_max_stream_data_bidi_remote */
    case 0x07: /* initial_max_stream_data_uni */
    case 0x08: /* initial_max_streams_bidi */
    case 0x09: /* initial_max_streams_uni */
    case 0x0a: /* ack_delay_exponent */
    case 0x0b: /* max_ack_delay */
    case 0x0e: /* active_connection_id_limit */
    case 0x20: /* max_datagram_frame_size */
    case 0x3e: /* initial_max_path_id */
    case 0x3127: /* initial_rtt */
    case 0xff04de1b: /* min_ack_delay */
        return 1;
    default:
        return 0;
    }
}

static ngx_flag_t
quic_version_is_reserved(uint32_t version)
{
    return (version & 0x0f0f0f0f) == 0x0a0a0a0a;
}

static u_char *
append_quic_version(u_char *p, uint32_t version)
{
    static const u_char  hex[] = "0123456789abcdef";
    ngx_uint_t           i;

    if (version == 0x00000001) {
        *p++ = '1';
        return p;
    }

    if (version == 0x6b3343cf) {
        *p++ = '2';
        return p;
    }

    if (quic_version_is_reserved(version)) {
        return ngx_cpymem(p, "GREASE", sizeof("GREASE") - 1);
    }

    for (i = 0; i < 8; i++) {
        *p++ = hex[(version >> (28 - i * 4)) & 0x0f];
    }

    return p;
}

static u_char *
append_quic_transport_param_value(u_char *p, ngx_ssl_quic_tp_t *tp)
{
    const u_char  *data, *end;
    size_t         i;
    uint32_t       version;
    uint64_t       value;

    /* Perk redacts the random initial_source_connection_id. */
    if (tp->id == 0x0f) {
        return ngx_cpymem(p, "AUTO", sizeof("AUTO") - 1);
    }

    if ((tp->id == 0x11 || tp->id == 0xff73db)
        && tp->len >= 4 && (tp->len & 3) == 0)
    {
        for (i = 0; i < tp->len; i += 4) {
            if (i == 4) {
                *p++ = '@';
            } else if (i > 4) {
                *p++ = ',';
            }

            version = ((uint32_t) tp->data[i] << 24)
                      | ((uint32_t) tp->data[i + 1] << 16)
                      | ((uint32_t) tp->data[i + 2] << 8)
                      | tp->data[i + 3];
            p = append_quic_version(p, version);
        }
        return p;
    }

    /* Perk renders Google's client-chosen initial RTT as AUTO. */
    if (tp->id == 0x3127) {
        return ngx_cpymem(p, "AUTO", sizeof("AUTO") - 1);
    }

    if (quic_transport_param_is_integer(tp->id)) {
        data = tp->data;
        end = data + tp->len;
        if (parse_quic_varint(&data, end, &value) == NGX_OK && data == end) {
            return append_uint64(p, value);
        }
    }

    return ngx_hex_dump(p, (u_char *) tp->data, tp->len);
}

static ngx_ssl_fingerprint_extra_t *
ngx_ssl_fingerprint_extra(ngx_connection_t *c)
{
    if (c->ssl->fp_extra == NULL) {
        c->ssl->fp_extra = ngx_pcalloc(NGX_SSL_FP_POOL(c),
                                       sizeof(ngx_ssl_fingerprint_extra_t));
    }

    return c->ssl->fp_extra;
}

ngx_int_t
ngx_ssl_client_alpn(ngx_connection_t *c, ngx_str_t *out)
{
    static const u_char         hex[] = "0123456789abcdef";
    u_char                     *p;
    const u_char               *data, *end;
    size_t                      len, n, i;
    ngx_ssl_fingerprint_extra_t *fp;

    fp = ngx_ssl_fingerprint_extra(c);
    if (fp == NULL) {
        return NGX_ERROR;
    }

    if (fp->alpn_done) {
        if (fp->alpn_str.data == NULL) {
            return NGX_DECLINED;
        }
        *out = fp->alpn_str;
        return NGX_OK;
    }
    fp->alpn_done = 1;

    data = c->ssl->fp_ja_data.data;
    if (data == NULL || c->ssl->fp_alpn_offset == 0) {
        return NGX_DECLINED;
    }
    end = data + c->ssl->fp_ja_data.len;
    if ((size_t) (end - data) < sizeof(uint16_t)
        || c->ssl->fp_alpn_offset
           > (size_t) (end - data) - sizeof(uint16_t))
    {
        return NGX_ERROR;
    }
    data += c->ssl->fp_alpn_offset;
    len = read_uint16(data);
    if (len == 0) {
        return NGX_DECLINED;
    }
    if (len < sizeof(uint16_t) + 1 || len > (size_t) (end - data)
        || len - sizeof(uint16_t) > (NGX_MAX_SIZE_T_VALUE - 1) / 3)
    {
        return NGX_ERROR;
    }

    end = data + len;
    data += sizeof(uint16_t);
    fp->alpn_str.data = ngx_pnalloc(NGX_SSL_FP_POOL(c),
                                    (len - sizeof(uint16_t)) * 3 + 1);
    if (fp->alpn_str.data == NULL) {
        return NGX_ERROR;
    }

    p = fp->alpn_str.data;
    while (data < end) {
        n = *data++;
        if (n == 0 || n > (size_t) (end - data)) {
            fp->alpn_str.data = NULL;
            return NGX_ERROR;
        }

        if (p != fp->alpn_str.data) {
            *p++ = ',';
        }

        for (i = 0; i < n; i++) {
            if (data[i] >= 0x21 && data[i] <= 0x7e
                && data[i] != '%' && data[i] != ',')
            {
                *p++ = data[i];
            } else {
                *p++ = '%';
                *p++ = hex[data[i] >> 4];
                *p++ = hex[data[i] & 0x0f];
            }
        }
        data += n;
    }

    fp->alpn_str.len = p - fp->alpn_str.data;
    *out = fp->alpn_str;
    return NGX_OK;
}

static u_char *
append_quic_transport_param(u_char *p, ngx_ssl_quic_tp_t *tp,
    ngx_flag_t separator)
{
    if (separator) {
        *p++ = ';';
    }

    if (tp->id % 31 == 27) {
        return ngx_cpymem(p, "GREASE", sizeof("GREASE") - 1);
    }

    p = append_uint64(p, tp->id);
    *p++ = ':';
    return append_quic_transport_param_value(p, tp);
}

ngx_int_t
ngx_ssl_quic_transport_params(ngx_connection_t *c, ngx_str_t *out)
{
    u_char                      *p;
    const u_char                *data, *end;
    ngx_int_t                    rc;
    ngx_ssl_quic_tp_t            tp;
    size_t                       capacity;
    ngx_ssl_fingerprint_extra_t *fp;

    fp = c->ssl->fp_extra;
    if (fp == NULL) {
        return NGX_DECLINED;
    }

    if (fp->quic_transport_params_str.data != NULL) {
        *out = fp->quic_transport_params_str;
        return NGX_OK;
    }

    data = fp->quic_transport_params.data;
    if (data == NULL || fp->quic_transport_params.len == 0) {
        return NGX_DECLINED;
    }

    if (fp->quic_transport_params.len > (NGX_MAX_SIZE_T_VALUE - 1) / 4)
    {
        return NGX_ERROR;
    }

    /* Decimal IDs and GREASE expand a two-byte empty parameter at most 4x. */
    capacity = fp->quic_transport_params.len * 4 + 1;
    fp->quic_transport_params_str.data =
        ngx_pnalloc(NGX_SSL_FP_POOL(c), capacity);
    if (fp->quic_transport_params_str.data == NULL) {
        return NGX_ERROR;
    }

    p = fp->quic_transport_params_str.data;
    end = data + fp->quic_transport_params.len;
    while ((rc = next_quic_transport_param(&data, end, &tp)) == NGX_OK) {
        p = append_quic_transport_param(
            p, &tp, p != fp->quic_transport_params_str.data);
    }

    if (rc != NGX_DONE || p > fp->quic_transport_params_str.data + capacity)
    {
        fp->quic_transport_params_str.data = NULL;
        return NGX_ERROR;
    }

    fp->quic_transport_params_str.len = p - fp->quic_transport_params_str.data;
    *out = fp->quic_transport_params_str;
    return NGX_OK;
}

static int
compare_quic_transport_param(const void *one, const void *two)
{
    const ngx_ssl_quic_tp_t  *first, *second;
    ngx_flag_t                first_grease, second_grease;

    first = one;
    second = two;
    first_grease = first->id % 31 == 27;
    second_grease = second->id % 31 == 27;

    if (first_grease != second_grease) {
        return first_grease ? 1 : -1;
    }

    return (first->id > second->id) - (first->id < second->id);
}

ngx_int_t
ngx_ssl_quic_transport_params_normalized(ngx_connection_t *c, ngx_str_t *out)
{
    u_char                      *p;
    const u_char                *data, *end;
    ngx_int_t                    rc;
    ngx_ssl_quic_tp_t           *item, *items, tp;
    size_t                       capacity, count, i;
    ngx_ssl_fingerprint_extra_t *fp;

    fp = c->ssl->fp_extra;
    if (fp == NULL) {
        return NGX_DECLINED;
    }

    if (fp->quic_transport_params_normalized_str.data != NULL) {
        *out = fp->quic_transport_params_normalized_str;
        return NGX_OK;
    }

    data = fp->quic_transport_params.data;
    if (data == NULL || fp->quic_transport_params.len == 0) {
        return NGX_DECLINED;
    }
    end = data + fp->quic_transport_params.len;

    count = 0;
    while ((rc = next_quic_transport_param(&data, end, &tp)) == NGX_OK) {
        count++;
    }
    if (rc != NGX_DONE || count == 0
        || count > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_ssl_quic_tp_t))
    {
        return NGX_ERROR;
    }

    items = ngx_pnalloc(c->pool, count * sizeof(ngx_ssl_quic_tp_t));
    if (items == NULL) {
        return NGX_ERROR;
    }

    data = fp->quic_transport_params.data;
    for (item = items; item < items + count; item++) {
        if (next_quic_transport_param(&data, end, item) != NGX_OK) {
            return NGX_ERROR;
        }
    }
    qsort(items, count, sizeof(ngx_ssl_quic_tp_t),
          compare_quic_transport_param);

    if (fp->quic_transport_params.len > (NGX_MAX_SIZE_T_VALUE - 1) / 4) {
        return NGX_ERROR;
    }
    capacity = fp->quic_transport_params.len * 4 + 1;
    fp->quic_transport_params_normalized_str.data =
        ngx_pnalloc(NGX_SSL_FP_POOL(c), capacity);
    if (fp->quic_transport_params_normalized_str.data == NULL) {
        return NGX_ERROR;
    }

    p = fp->quic_transport_params_normalized_str.data;
    for (i = 0; i < count; i++) {
        p = append_quic_transport_param(p, &items[i], i != 0);
    }
    if (p > fp->quic_transport_params_normalized_str.data + capacity) {
        fp->quic_transport_params_normalized_str.data = NULL;
        return NGX_ERROR;
    }

    fp->quic_transport_params_normalized_str.len =
        p - fp->quic_transport_params_normalized_str.data;
    *out = fp->quic_transport_params_normalized_str;
    return NGX_OK;
}

ngx_int_t
ngx_ssl_quic_transport_params_raw(ngx_connection_t *c, ngx_str_t *out)
{
    size_t                       len;
    ngx_ssl_fingerprint_extra_t *fp;

    fp = c->ssl->fp_extra;
    if (fp == NULL) {
        return NGX_DECLINED;
    }

    if (fp->quic_transport_params_raw_str.data != NULL) {
        *out = fp->quic_transport_params_raw_str;
        return NGX_OK;
    }

    if (fp->quic_transport_params.data == NULL) {
        return NGX_DECLINED;
    }

    len = fp->quic_transport_params.len;
    if (len > NGX_MAX_SIZE_T_VALUE / 2) {
        return NGX_ERROR;
    }

    fp->quic_transport_params_raw_str.len = len * 2;
    fp->quic_transport_params_raw_str.data =
        ngx_pnalloc(NGX_SSL_FP_POOL(c), len * 2);
    if (fp->quic_transport_params_raw_str.data == NULL) {
        return NGX_ERROR;
    }

    ngx_hex_dump(fp->quic_transport_params_raw_str.data,
                 fp->quic_transport_params.data, len);
    *out = fp->quic_transport_params_raw_str;
    return NGX_OK;
}

#define NGX_SSL_QUIC_VN_INITIAL_SIZE  256
#define NGX_SSL_QUIC_VN_TTL           5000

typedef struct {
    ngx_sockaddr_t           sockaddr;
    socklen_t                socklen;
    ngx_msec_t               expires;
    ngx_uint_t               hash;
    uint32_t                 version;
    ngx_listening_t         *listening;
    unsigned                 used:1;
    unsigned                 active:1;
} ngx_ssl_quic_vn_entry_t;

static ngx_ssl_quic_vn_entry_t  *ngx_ssl_quic_vn_cache;
static ngx_uint_t  ngx_ssl_quic_vn_cache_size;
static ngx_uint_t  ngx_ssl_quic_vn_used;
static ngx_uint_t  ngx_ssl_quic_vn_active;
static ngx_msec_t  ngx_ssl_quic_vn_until;

static ngx_inline ngx_uint_t
ngx_ssl_quic_vn_hash(ngx_connection_t *c)
{
    ngx_uint_t           hash;
    struct sockaddr_in  *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6 *sin6;
#endif

    switch (c->sockaddr->sa_family) {
    case AF_INET:
        sin = (struct sockaddr_in *) c->sockaddr;
        hash = ngx_crc32_short((u_char *) &sin->sin_addr,
                               sizeof(sin->sin_addr));
        hash ^= sin->sin_port;
        break;

#if (NGX_HAVE_INET6)
    case AF_INET6:
        sin6 = (struct sockaddr_in6 *) c->sockaddr;
        hash = ngx_crc32_short((u_char *) &sin6->sin6_addr,
                               sizeof(sin6->sin6_addr));
        hash ^= sin6->sin6_port ^ sin6->sin6_scope_id;
        break;
#endif

    default:
        hash = ngx_crc32_short((u_char *) c->sockaddr, c->socklen);
    }

    hash ^= (uintptr_t) c->listening >> 4;
    return hash;
}

static ngx_inline ngx_flag_t
ngx_ssl_quic_vn_equal(ngx_ssl_quic_vn_entry_t *entry, ngx_connection_t *c)
{
    return entry->listening == c->listening
           && entry->socklen == c->socklen
           && ngx_cmp_sockaddr((struct sockaddr *) &entry->sockaddr,
                               entry->socklen, c->sockaddr, c->socklen, 1)
              == NGX_OK;
}

static ngx_int_t
ngx_ssl_quic_vn_resize(ngx_uint_t size, ngx_msec_t now)
{
    ngx_uint_t                 i, index, nactive, old_size;
    ngx_msec_t                 until;
    ngx_ssl_quic_vn_entry_t   *entry, *new_cache, *old_cache;

    if (size < NGX_SSL_QUIC_VN_INITIAL_SIZE
        || (size & (size - 1)) != 0
        || size > NGX_MAX_SIZE_T_VALUE / sizeof(ngx_ssl_quic_vn_entry_t))
    {
        return NGX_ERROR;
    }

    new_cache = ngx_pcalloc(ngx_cycle->pool,
                            size * sizeof(ngx_ssl_quic_vn_entry_t));
    if (new_cache == NULL) {
        return NGX_ERROR;
    }

    old_cache = ngx_ssl_quic_vn_cache;
    old_size = ngx_ssl_quic_vn_cache_size;
    nactive = 0;
    until = 0;

    for (i = 0; i < old_size; i++) {
        entry = &old_cache[i];
        if (!entry->active
            || (ngx_msec_int_t) (entry->expires - now) <= 0)
        {
            continue;
        }

        if (nactive == size) {
            (void) ngx_pfree(ngx_cycle->pool, new_cache);
            return NGX_ERROR;
        }

        index = entry->hash & (size - 1);
        while (new_cache[index].used) {
            index = (index + 1) & (size - 1);
        }
        new_cache[index] = *entry;

        if (nactive == 0
            || (ngx_msec_int_t) (entry->expires - until) > 0)
        {
            until = entry->expires;
        }
        nactive++;
    }

    ngx_ssl_quic_vn_cache = new_cache;
    ngx_ssl_quic_vn_cache_size = size;
    ngx_ssl_quic_vn_used = nactive;
    ngx_ssl_quic_vn_active = nactive;
    ngx_ssl_quic_vn_until = until;

    if (old_cache != NULL) {
        (void) ngx_pfree(ngx_cycle->pool, old_cache);
    }

    return NGX_OK;
}

void
ngx_ssl_quic_vn_record(ngx_connection_t *c, uint32_t version)
{
    ngx_uint_t                hash, i, index, size;
    ngx_msec_t                now;
    ngx_ssl_quic_vn_entry_t  *entry, *slot;

    if (c->sockaddr == NULL
        || c->socklen > (socklen_t) sizeof(ngx_sockaddr_t))
    {
        return;
    }

    now = ngx_current_msec;
    if (ngx_ssl_quic_vn_cache == NULL) {
        if (ngx_ssl_quic_vn_resize(NGX_SSL_QUIC_VN_INITIAL_SIZE, now)
            != NGX_OK)
        {
            return;
        }

    } else if (ngx_ssl_quic_vn_active == 0
               || (ngx_msec_int_t) (ngx_ssl_quic_vn_until - now) <= 0)
    {
        ngx_memzero(ngx_ssl_quic_vn_cache,
                    ngx_ssl_quic_vn_cache_size
                    * sizeof(ngx_ssl_quic_vn_entry_t));
        ngx_ssl_quic_vn_used = 0;
        ngx_ssl_quic_vn_active = 0;
    }

    if (ngx_ssl_quic_vn_used
        >= ngx_ssl_quic_vn_cache_size - ngx_ssl_quic_vn_cache_size / 4)
    {
        size = ngx_ssl_quic_vn_cache_size;
        if (ngx_ssl_quic_vn_active >= size / 2) {
            if (size > NGX_MAX_SIZE_T_VALUE / 2) {
                return;
            }
            size *= 2;
        }
        (void) ngx_ssl_quic_vn_resize(size, now);
    }

    hash = ngx_ssl_quic_vn_hash(c);

retry:

    index = hash & (ngx_ssl_quic_vn_cache_size - 1);
    slot = NULL;

    for (i = 0; i < ngx_ssl_quic_vn_cache_size; i++) {
        entry = &ngx_ssl_quic_vn_cache[
            (index + i) & (ngx_ssl_quic_vn_cache_size - 1)];

        if (!entry->used) {
            if (slot == NULL) {
                slot = entry;
            }
            break;
        }

        if (!entry->active) {
            if (slot == NULL) {
                slot = entry;
            }
            continue;
        }

        if ((ngx_msec_int_t) (entry->expires - now) <= 0) {
            entry->active = 0;
            ngx_ssl_quic_vn_active--;
            if (slot == NULL) {
                slot = entry;
            }
            continue;
        }

        if (entry->hash == hash && ngx_ssl_quic_vn_equal(entry, c)) {
            entry->version = version;
            entry->expires = now + NGX_SSL_QUIC_VN_TTL;
            ngx_ssl_quic_vn_until = entry->expires;
            return;
        }
    }

    if (slot == NULL) {
        size = ngx_ssl_quic_vn_cache_size;
        if (size > NGX_MAX_SIZE_T_VALUE / 2
            || ngx_ssl_quic_vn_resize(size * 2, now) != NGX_OK)
        {
            return;
        }
        goto retry;
    }

    if (!slot->used) {
        ngx_ssl_quic_vn_used++;
    }
    ngx_memzero(slot, sizeof(*slot));
    ngx_memcpy(&slot->sockaddr, c->sockaddr, c->socklen);
    slot->socklen = c->socklen;
    slot->hash = hash;
    slot->version = version;
    slot->listening = c->listening;
    slot->expires = now + NGX_SSL_QUIC_VN_TTL;
    slot->used = 1;
    slot->active = 1;
    ngx_ssl_quic_vn_active++;
    ngx_ssl_quic_vn_until = slot->expires;
}

ngx_flag_t
ngx_ssl_quic_vn_match(ngx_connection_t *c, uint32_t *version)
{
    ngx_uint_t                hash, i, index;
    ngx_msec_t                now;
    ngx_ssl_quic_vn_entry_t  *entry;

    if (ngx_ssl_quic_vn_active == 0 || c->sockaddr == NULL
        || c->socklen > (socklen_t) sizeof(ngx_sockaddr_t))
    {
        return 0;
    }

    now = ngx_current_msec;
    if ((ngx_msec_int_t) (ngx_ssl_quic_vn_until - now) <= 0) {
        ngx_memzero(ngx_ssl_quic_vn_cache,
                    ngx_ssl_quic_vn_cache_size
                    * sizeof(ngx_ssl_quic_vn_entry_t));
        ngx_ssl_quic_vn_used = 0;
        ngx_ssl_quic_vn_active = 0;
        return 0;
    }

    hash = ngx_ssl_quic_vn_hash(c);
    index = hash & (ngx_ssl_quic_vn_cache_size - 1);
    for (i = 0; i < ngx_ssl_quic_vn_cache_size; i++) {
        entry = &ngx_ssl_quic_vn_cache[
            (index + i) & (ngx_ssl_quic_vn_cache_size - 1)];

        if (!entry->used) {
            return 0;
        }

        if (!entry->active) {
            continue;
        }

        if ((ngx_msec_int_t) (entry->expires - now) <= 0) {
            entry->active = 0;
            ngx_ssl_quic_vn_active--;
            continue;
        }

        if (entry->hash == hash && ngx_ssl_quic_vn_equal(entry, c)) {
            *version = entry->version;
            entry->active = 0;
            ngx_ssl_quic_vn_active--;
            return 1;
        }
    }

    return 0;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3(ngx_connection_t *c)
{
    u_char *ptr = NULL, *data = NULL, *end = NULL, *field;
    size_t num = 0, i;
    uint16_t n, greased = 0;

    if (c->ssl->fp_ja3_str.data != NULL) {
        return NGX_OK;
    }

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja3: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    end = data + c->ssl->fp_ja_data.len;
    if ((size_t) (end - data) < sizeof(uint16_t) * 2) {
        goto invalid;
    }

    if (c->ssl->fp_ja_data.len
        > (NGX_MAX_SIZE_T_VALUE - sizeof("65535,")) / 6)
    {
        goto invalid;
    }

    c->ssl->fp_ja3_str.len = c->ssl->fp_ja_data.len * 6 + sizeof("65535,");
    c->ssl->fp_ja3_str.data = ngx_pnalloc(NGX_SSL_FP_POOL(c),
                                          c->ssl->fp_ja3_str.len);
    if (c->ssl->fp_ja3_str.data == NULL) {
        /** Else we break a data stream */
        c->ssl->fp_ja3_str.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_ssl_ja3: alloc bytes: [%uz]",
                   c->ssl->fp_ja3_str.len);

    /* version */
    ptr = c->ssl->fp_ja3_str.data;
    ptr = append_uint16(ptr, read_uint16(data));
    *ptr++ = ',';
    data += sizeof(uint16_t);

    /* ciphers */
    num = read_uint16(data);
    if ((num & 1) != 0
        || num > (size_t) (end - data) - sizeof(uint16_t))
    {
        goto invalid;
    }
    data += sizeof(uint16_t);
    field = ptr;
    for (i = 0; i < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i + 1]);
        if (!IS_GREASE_CODE(n)) {
            /* if (data[i] == 0x13) {
                c->ssl->fp_ja3_str.data[2] = '2'; // fixup tls1.3 version
            } */
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    if (ptr == field) {
        *ptr++ = ',';
    } else {
        *(ptr - 1) = ',';
    }
    data += num;

    /* extensions */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        goto invalid;
    }
    num = read_uint16(data);
    if ((num & 1) != 0
        || num > (size_t) (end - data) - sizeof(uint16_t))
    {
        goto invalid;
    }
    data += sizeof(uint16_t);
    field = ptr;
    for (i = 0; i < num; i += 2) {
        n = read_uint16(data + i);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    if (ptr == field) {
        *ptr++ = ',';
    } else {
        *(ptr - 1) = ',';
    }
    data += num;


    /* groups */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        goto invalid;
    }
    num = read_uint16(data);
    if (num != 0
        && (num < sizeof(uint16_t) || (num & 1) != 0
            || num > (size_t) (end - data)))
    {
        goto invalid;
    }
    field = ptr;
    for (i = 2; i + 1 < num; i += 2) {
        n = ((uint16_t)data[i]) << 8 | ((uint16_t)data[i+1]);
        if (!IS_GREASE_CODE(n)) {
            ptr = append_uint16(ptr, n);
            *ptr++ = '-';
        } else if (greased == 0) {
            greased = n;
        }
    }
    if (ptr == field) {
        *ptr++ = ',';
    } else {
        *(ptr - 1) = ',';
    }
    data += num == 0 ? sizeof(uint16_t) : num;

    /* formats */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        goto invalid;
    }
    num = read_uint16(data);
    data += sizeof(uint16_t);
    if (num > (size_t) (end - data)
        || (num != 0 && (num < sizeof(uint8_t)
                         || (size_t) data[0] + 1 > num)))
    {
        goto invalid;
    }
    field = ptr;
    for (i = 1; i < num; i++) {
        ptr = append_uint16(ptr, (uint16_t)data[i]);
        *ptr++ = '-';
    }
    if (ptr != field) {
        ptr--;
    }
    data += num;

    /* end */
    c->ssl->fp_ja3_str.len = ptr - c->ssl->fp_ja3_str.data;

    /* greased */
    c->ssl->fp_tls_greased = greased;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_ssl_ja3: ja3 str=[%V], len=[%uz]",
                   &c->ssl->fp_ja3_str, c->ssl->fp_ja3_str.len);

    return NGX_OK;

invalid:

    ngx_log_error(NGX_LOG_WARN, c->log, 0,
            "ngx_ssl_ja3: invalid fp_ja_data");
    c->ssl->fp_ja3_str.data = NULL;
    c->ssl->fp_ja3_str.len = 0;

    return NGX_ERROR;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers and tested before.
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja3_hash is alread set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja3_hash(ngx_connection_t *c)
{
    ngx_md5_t ctx;
    u_char hash_buf[16];

    if (c->ssl->fp_ja3_hash.len > 0) {
        return NGX_OK;
    }

    if (ngx_ssl_ja3(c) != NGX_OK) {
        return NGX_ERROR;
    }

    c->ssl->fp_ja3_hash.len = 32;
    c->ssl->fp_ja3_hash.data = ngx_pnalloc(NGX_SSL_FP_POOL(c),
                                           c->ssl->fp_ja3_hash.len);
    if (c->ssl->fp_ja3_hash.data == NULL) {
        /** Else we can break a stream */
        c->ssl->fp_ja3_hash.len = 0;
        return NGX_ERROR;
    }

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_ssl_ja3_hash: alloc bytes: [%uz]",
                   c->ssl->fp_ja3_hash.len);

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, c->ssl->fp_ja3_str.data, c->ssl->fp_ja3_str.len);
    ngx_md5_final(hash_buf, &ctx);
    ngx_hex_dump(c->ssl->fp_ja3_hash.data, hash_buf, 16);

    return NGX_OK;
}

/**
 * Params:
 *      c and c->ssl should be valid pointers
 *
 * Returns:
 *      NGX_OK - c->ssl->fp_ja4_str is already set
 *      NGX_ERROR - something went wrong
 */
int ngx_ssl_ja4(ngx_connection_t *c)
{
    u_char        *ptr, *data, *end, *raw, *raw_ptr, *cipher_material,
                  *extension_material, *sigalgs_data;
    size_t         ciphers_len, exts_len, groups_len, formats_len,
                   sigalgs_len, alpn_len, raw_capacity;
    size_t         cipher_count, exts_count, exts_count_total, sigalg_count;
    size_t         i, j;
    uint16_t       n, version_code, *hash_buf, local_hash_buf[128];
    unsigned char  alpn[2] = { '0', '0' };
    unsigned char  cipher_hash[6] = { 0 }, exts_hash[6] = { 0 },
                   digest[SHA256_DIGEST_LENGTH];
    static const unsigned char  hex[] = "0123456789abcdef";
    ngx_flag_t    has_sni;
    enum {
        ngx_ssl_ja4_str_max_len = 36,
        ngx_ssl_ja4_hex_hash_len = 12
    };

    if (c->ssl->fp_ja4_str.data != NULL) {
        return NGX_OK;
    }

    data = c->ssl->fp_ja_data.data;
    if (data == NULL) {
        /**
         *  NOTE:
         *  If we can't set it in OpenSSL,
         *  then something defenetly something went wrong.
         *  Typical production configuration has log level set to error,
         *  this would help to debug this case, if it happened.
         */
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: fp_ja_data == NULL");
        return NGX_ERROR;
    }

    end = data + c->ssl->fp_ja_data.len;

    if ((size_t) (end - data) < sizeof(uint16_t) * 6 + sizeof(uint8_t) + 3) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: fp_ja_data too short");
        return NGX_ERROR;
    }

    if (c->ssl->fp_ja_data.len <= sizeof(local_hash_buf)) {
        hash_buf = local_hash_buf;
    } else {
        hash_buf = ngx_palloc(NGX_SSL_FP_POOL(c), c->ssl->fp_ja_data.len);
        if (hash_buf == NULL) {
            return NGX_ERROR;
        }
    }

    if (c->ssl->fp_ja_data.len / 2
        > (NGX_MAX_SIZE_T_VALUE - 13) / 5)
    {
        return NGX_ERROR;
    }

    raw_capacity = 13 + c->ssl->fp_ja_data.len / 2 * 5;
    if (raw_capacity > NGX_MAX_SIZE_T_VALUE - ngx_ssl_ja4_str_max_len) {
        return NGX_ERROR;
    }

    raw = ngx_pnalloc(NGX_SSL_FP_POOL(c),
                      raw_capacity + ngx_ssl_ja4_str_max_len);
    if (raw == NULL) {
        return NGX_ERROR;
    }

    raw_ptr = raw + 10;
    *raw_ptr++ = '_';
    cipher_material = raw_ptr;

    version_code = read_uint16(data);
    data += sizeof(uint16_t);

    /* ciphers */
    ciphers_len = read_uint16(data);
    data += sizeof(uint16_t);
    if (ciphers_len > (size_t) (end - data) || (ciphers_len & 1) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: invalid ciphers length");
        return NGX_ERROR;
    }

    cipher_count = 0;
    for (i = 0; i + 1 < ciphers_len; i += 2) {
        n = ((uint16_t) data[i] << 8) | (uint16_t) data[i + 1];
        if (!IS_GREASE_CODE(n)) {
            hash_buf[cipher_count++] = n;
        }
    }
    data += ciphers_len;

    if (cipher_count != 0) {
        qsort(hash_buf, cipher_count, sizeof(uint16_t), compare_uint16);

        for (i = 0; i < cipher_count; i++) {
            *raw_ptr++ = hex[(hash_buf[i] >> 12) & 0xf];
            *raw_ptr++ = hex[(hash_buf[i] >> 8) & 0xf];
            *raw_ptr++ = hex[(hash_buf[i] >> 4) & 0xf];
            *raw_ptr++ = hex[hash_buf[i] & 0xf];
            if (i + 1 != cipher_count) {
                *raw_ptr++ = ',';
            }
        }

        if (SHA256(cipher_material, raw_ptr - cipher_material, digest) == NULL) {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256 failed");
            return NGX_ERROR;
        }
        ngx_memcpy(cipher_hash, digest, sizeof(cipher_hash));
    }

    *raw_ptr++ = '_';
    extension_material = raw_ptr;

    /* extensions */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing extensions block");
        return NGX_ERROR;
    }

    exts_len = read_uint16(data);
    data += sizeof(uint16_t);
    if (exts_len > (size_t) (end - data) || (exts_len & 1) != 0) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: invalid extensions length");
        return NGX_ERROR;
    }

    exts_count = 0;
    exts_count_total = 0;
    has_sni = 0;
    for (i = 0; i + 1 < exts_len; i += 2) {
        n = read_uint16(data + i);

        if (IS_GREASE_CODE(n)) {
            continue;
        }

        exts_count_total++;

        if (n == 0x0000) {
            has_sni = 1;
            continue;
        }

        if (n == 0x0010) {
            continue;
        }

        hash_buf[exts_count++] = n;
    }
    data += exts_len;

    /* groups */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing groups block");
        return NGX_ERROR;
    }

    groups_len = read_uint16(data);
    if (groups_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (groups_len < sizeof(uint16_t)
            || groups_len > (size_t) (end - data))
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid groups length");
            return NGX_ERROR;
        }
        data += groups_len;
    }

    /* formats */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing formats block");
        return NGX_ERROR;
    }

    formats_len = read_uint16(data);
    data += sizeof(uint16_t);
    if (formats_len > (size_t) (end - data)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: invalid formats length");
        return NGX_ERROR;
    }
    data += formats_len;

    /* supported version */
    if ((size_t) (end - data) < sizeof(uint16_t) * 2) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing ja4 metadata block");
        return NGX_ERROR;
    }

    n = read_uint16(data);
    if (n != 0) {
        version_code = n;
    }
    data += sizeof(uint16_t);

    /* signature algorithms */
    sigalgs_data = data;
    sigalgs_len = read_uint16(data);
    if (sigalgs_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (sigalgs_len < sizeof(uint16_t)
            || sigalgs_len > (size_t) (end - data)
            || (sigalgs_len & 1) != 0)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid signature algorithms length");
            return NGX_ERROR;
        }

        data += sigalgs_len;
    }

    /* alpn 2 digits */
    if ((size_t) (end - data) < sizeof(uint16_t)) {
        ngx_log_error(NGX_LOG_WARN, c->log, 0,
                "ngx_ssl_ja4: missing alpn block");
        return NGX_ERROR;
    }

    alpn_len = read_uint16(data);
    if (alpn_len == 0) {
        data += sizeof(uint16_t);
    } else {
        if (alpn_len > (size_t) (end - data))
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: invalid alpn length");
            return NGX_ERROR;
        }

        /* JA4 specifies 00 when no non-empty ALPN identifier is present. */
        if (alpn_len <= sizeof(uint16_t) + 1 || data[2] == 0) {
            data += alpn_len;

        } else {
            n = data[2];
            if (n > alpn_len - 3) {
                ngx_log_error(NGX_LOG_WARN, c->log, 0,
                        "ngx_ssl_ja4: invalid alpn length");
                return NGX_ERROR;
            }
            alpn[0] = data[3];
            alpn[1] = data[n + 2];
            data += alpn_len;
        }
    }

    /* extensions and sigalgs digest */
    if (exts_count != 0) {
        qsort(hash_buf, exts_count, sizeof(uint16_t), compare_uint16);

        sigalg_count = 0;
        for (i = sizeof(uint16_t); i + 1 < sigalgs_len; i += 2) {
            n = ((uint16_t) sigalgs_data[i] << 8)
                | (uint16_t) sigalgs_data[i + 1];
            if (!IS_GREASE_CODE(n)) {
                sigalg_count++;
            }
        }

        for (i = 0; i < exts_count; i++) {
            *raw_ptr++ = hex[(hash_buf[i] >> 12) & 0xf];
            *raw_ptr++ = hex[(hash_buf[i] >> 8) & 0xf];
            *raw_ptr++ = hex[(hash_buf[i] >> 4) & 0xf];
            *raw_ptr++ = hex[hash_buf[i] & 0xf];
            if (i + 1 != exts_count) {
                *raw_ptr++ = ',';
            }
        }

        if (sigalg_count != 0) {
            *raw_ptr++ = '_';
            j = 0;
            for (i = sizeof(uint16_t); i + 1 < sigalgs_len; i += 2) {
                n = ((uint16_t) sigalgs_data[i] << 8)
                    | (uint16_t) sigalgs_data[i + 1];
                if (!IS_GREASE_CODE(n)) {
                    hash_buf[j++] = n;
                }
            }

            for (i = 0; i < sigalg_count; i++) {
                *raw_ptr++ = hex[(hash_buf[i] >> 12) & 0xf];
                *raw_ptr++ = hex[(hash_buf[i] >> 8) & 0xf];
                *raw_ptr++ = hex[(hash_buf[i] >> 4) & 0xf];
                *raw_ptr++ = hex[hash_buf[i] & 0xf];
                if (i + 1 != sigalg_count) {
                    *raw_ptr++ = ',';
                }
            }
        }

        if (SHA256(extension_material, raw_ptr - extension_material,
                   digest) == NULL)
        {
            ngx_log_error(NGX_LOG_WARN, c->log, 0,
                    "ngx_ssl_ja4: SHA256 failed");
            return NGX_ERROR;
        }
        ngx_memcpy(exts_hash, digest, sizeof(exts_hash));
    }

    /* ja4 str */
    c->ssl->fp_ja4_str.len = ngx_ssl_ja4_str_max_len;
    c->ssl->fp_ja4_str.data = raw + raw_capacity;

    ngx_log_debug1(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_ssl_ja4: alloc bytes: [%uz]",
                   raw_capacity + c->ssl->fp_ja4_str.len);

    ptr = c->ssl->fp_ja4_str.data;
#if (NGX_QUIC || NGX_COMPAT)
    *ptr++ = c->quic ? 'q' : 't';
#else
    *ptr++ = 't';
#endif
    switch (version_code) {
    case TLS1_3_VERSION:
        *ptr++ = '1';
        *ptr++ = '3';
        break;
    case TLS1_2_VERSION:
        *ptr++ = '1';
        *ptr++ = '2';
        break;
    case TLS1_1_VERSION:
        *ptr++ = '1';
        *ptr++ = '1';
        break;
    case TLS1_VERSION:
        *ptr++ = '1';
        *ptr++ = '0';
        break;
    case SSL3_VERSION:
        *ptr++ = 's';
        *ptr++ = '3';
        break;
    default:
        *ptr++ = '0';
        *ptr++ = '0';
        break;
    }
    *ptr++ = has_sni ? 'd' : 'i';
    n = (uint16_t) ngx_min(cipher_count, 99);
    if (n < 10) {
        *ptr++ = '0';
    }
    ptr = append_uint8(ptr, (uint8_t) n);
    n = (uint16_t) ngx_min(exts_count_total, 99);
    if (n < 10) {
        *ptr++ = '0';
    }
    ptr = append_uint8(ptr, (uint8_t) n);
    if (IS_ASCII_ALNUM(alpn[0]) && IS_ASCII_ALNUM(alpn[1])) {
        *ptr++ = alpn[0];
        *ptr++ = alpn[1];
    } else {
        *ptr++ = hex[alpn[0] >> 4];
        *ptr++ = hex[alpn[1] & 0xf];
    }
    *ptr++ = '_';
    ptr = ngx_hex_dump(ptr, cipher_hash, ngx_ssl_ja4_hex_hash_len / 2);

    *ptr++ = '_';
    ptr = ngx_hex_dump(ptr, exts_hash, ngx_ssl_ja4_hex_hash_len / 2);

    /* end */
    c->ssl->fp_ja4_str.len = ptr - c->ssl->fp_ja4_str.data;
    ngx_memcpy(raw, c->ssl->fp_ja4_str.data, 10);
    c->ssl->fp_ja4_r_str.data = raw;
    c->ssl->fp_ja4_r_str.len = raw_ptr - raw;

    ngx_log_debug2(NGX_LOG_DEBUG_EVENT, c->log, 0,
                   "ngx_ssl_ja4: ja4 str=[%V], len=[%uz]",
                   &c->ssl->fp_ja4_str, c->ssl->fp_ja4_str.len);

    return NGX_OK;
}

static ngx_inline ngx_http_v2_fp_setting_t *
http2_setting_at(ngx_http_v2_connection_t *h2c, size_t index)
{
    ngx_http_v2_fp_setting_t  *settings;

    if (index < NGX_FP_V2_SETTINGS_INLINE) {
        return &h2c->fp_settings.items[index];
    }

    settings = h2c->fp_settings.overflow->elts;
    return &settings[index - NGX_FP_V2_SETTINGS_INLINE];
}

/**
 * Params:
 *      r should be a valid h2 request
 *
 * Returns:
 *      NGX_OK -- *out is set
 *      NGX_ERROR -- something went wrong
 */
int ngx_http2_fingerprint(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_http_v2_stream_t      *stream = r->stream;
    ngx_http_v2_connection_t  *h2c = stream->connection;
    ngx_http_v2_fp_setting_t  *setting;
    unsigned char *pstr = NULL;
    size_t i, j, n;
    uint16_t id;

    if (h2c->fp_prefix.data == NULL) {
        if (h2c->fp_settings.len > (NGX_MAX_SIZE_T_VALUE - 12) / 17) {
            return NGX_ERROR;
        }
        n = 12 + h2c->fp_settings.len * 17;
        h2c->fp_prefix.data = ngx_pnalloc(h2c->connection->pool, n);
        if (h2c->fp_prefix.data == NULL) {
            return NGX_ERROR;
        }

        pstr = h2c->fp_prefix.data;

        for (i = 0, j = 0; i < h2c->fp_settings.len; i++) {
            setting = http2_setting_at(h2c, i);
            id = setting->id;
            if (IS_GREASE_CODE(id)) {
                continue;
            }
            if (j++ > 0) {
                *pstr++ = ';';
            }
            pstr = append_uint16(pstr, id);
            *pstr++ = ':';
            pstr = append_uint32(pstr, setting->value);
        }
        *pstr++ = '|';
        pstr = append_uint32(pstr, h2c->fp_windowupdate);
        *pstr++ = '|';

        h2c->fp_prefix.len = pstr - h2c->fp_prefix.data;
    }

    n = h2c->fp_prefix.len + 30 + stream->fp_pseudoheaders_len * 2;

    out->data = ngx_pnalloc(r->pool, n);
    if (out->data == NULL) {
        /** Else we break a stream */
        return NGX_ERROR;
    }
    pstr = ngx_cpymem(out->data, h2c->fp_prefix.data,
                      h2c->fp_prefix.len);

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                  "ngx_http2_fingerprint: alloc bytes: [%uz]\n", n);

    /* priorities */
    if (stream->fp_priority_set) {
        pstr = append_uint32(pstr, stream->fp_priority_sid);
        *pstr++ = ':';
        pstr = append_uint8(pstr, stream->fp_priority_excl);
        *pstr++ = ':';
        pstr = append_uint32(pstr, stream->fp_priority_dep);
        *pstr++ = ':';
        pstr = append_uint16(pstr, (uint16_t)stream->fp_priority_weight+1);
    } else {
        *pstr++ = '0';
    }
    *pstr++ = '|';

    /* fp_pseudoheaders */
    for (i = 0; i < stream->fp_pseudoheaders_len; i++) {
        *pstr++ = stream->fp_pseudoheaders[i];
        *pstr++ = ',';
    }

    /* null terminator */
    if (stream->fp_pseudoheaders_len != 0) {
        pstr--;
    }
    *pstr = 0;

    out->len = pstr - out->data;

    ngx_log_debug(NGX_LOG_DEBUG_EVENT, r->connection->log, 0,
                  "ngx_http2_fingerprint: http2 fingerprint: [%V], len=[%uz]\n",
                  out, out->len);

    return NGX_OK;
}

#if (NGX_HTTP_V3)

static ngx_flag_t
http3_setting_is_grease(uint64_t id)
{
    return id >= 0x21 && (id - 0x21) % 0x1f == 0;
}

static ngx_inline ngx_http_v3_fp_setting_t *
http3_setting_at(ngx_http_v3_session_t *h3c, size_t index)
{
    ngx_http_v3_fp_setting_t  *settings;

    if (index < NGX_HTTP_V3_FP_SETTINGS_INLINE) {
        return &h3c->fp_settings.items[index];
    }

    settings = h3c->fp_settings.overflow->elts;
    return &settings[index - NGX_HTTP_V3_FP_SETTINGS_INLINE];
}

int
ngx_http3_settings(ngx_http_request_t *r, ngx_str_t *out)
{
    u_char                    *p;
    size_t                     i, n;
    ngx_http_v3_fp_setting_t  *setting;
    ngx_http_v3_session_t     *h3c;

    if (r->connection->quic == NULL || r->v3_parse == NULL) {
        return NGX_DECLINED;
    }

    h3c = ngx_http_v3_get_session(r->connection);
    if (!h3c->fp_settings_done) {
        return NGX_AGAIN;
    }

    if (h3c->fp_settings_str.data != NULL) {
        *out = h3c->fp_settings_str;
        return NGX_OK;
    }

    if (h3c->fp_settings.len > (NGX_MAX_SIZE_T_VALUE - 1) / 42) {
        return NGX_ERROR;
    }
    n = h3c->fp_settings.len * 42 + 1;
    h3c->fp_settings_str.data = ngx_pnalloc(r->connection->quic->parent->pool,
                                            n);
    if (h3c->fp_settings_str.data == NULL) {
        return NGX_ERROR;
    }

    p = h3c->fp_settings_str.data;
    for (i = 0; i < h3c->fp_settings.len; i++) {
        setting = http3_setting_at(h3c, i);

        if (i != 0) {
            *p++ = ';';
        }

        if (http3_setting_is_grease(setting->id)) {
            p = ngx_cpymem(p, "GREASE", sizeof("GREASE") - 1);
            continue;
        }

        p = append_uint64(p, setting->id);
        *p++ = ':';
        p = append_uint64(p, setting->value);
    }

    h3c->fp_settings_str.len = p - h3c->fp_settings_str.data;
    *out = h3c->fp_settings_str;
    return NGX_OK;
}

int
ngx_http3_qpack(ngx_http_request_t *r, ngx_str_t *out)
{
    u_char                 *p;
    ngx_http_v3_session_t  *h3c;

    if (r->connection->quic == NULL || r->v3_parse == NULL) {
        return NGX_DECLINED;
    }

    h3c = ngx_http_v3_get_session(r->connection);
    if (!h3c->fp_settings_done) {
        return NGX_AGAIN;
    }

    if (h3c->fp_qpack_str.data != NULL) {
        *out = h3c->fp_qpack_str;
        return NGX_OK;
    }

    h3c->fp_qpack_str.data = ngx_pnalloc(r->connection->quic->parent->pool, 42);
    if (h3c->fp_qpack_str.data == NULL) {
        return NGX_ERROR;
    }

    p = append_uint64(h3c->fp_qpack_str.data, h3c->fp_qpack_capacity);
    *p++ = ':';
    p = append_uint64(p, h3c->fp_qpack_blocked);
    h3c->fp_qpack_str.len = p - h3c->fp_qpack_str.data;
    *out = h3c->fp_qpack_str;
    return NGX_OK;
}

static int
ngx_http3_fingerprint_create(ngx_http_request_t *r, ngx_str_t *out,
    ngx_flag_t normalized)
{
    u_char                       *p;
    size_t                        i, n;
    ngx_str_t                     settings, transport_params, *cached;
    ngx_http_v3_parse_headers_t  *headers;
    ngx_ssl_fingerprint_extra_t  *fp;

    if (r->connection->quic == NULL || r->v3_parse == NULL) {
        return NGX_DECLINED;
    }

    fp = r->connection->ssl->fp_extra;
    if (fp == NULL) {
        return NGX_DECLINED;
    }

    headers = &r->v3_parse->headers;
    cached = normalized ? &headers->fp_fingerprint_normalized
                        : &headers->fp_fingerprint;
    if (cached->data != NULL) {
        *out = *cached;
        return NGX_OK;
    }

    if (ngx_http3_settings(r, &settings) != NGX_OK) {
        return NGX_DECLINED;
    }
    if (normalized) {
        if (ngx_ssl_quic_transport_params_normalized(
                r->connection, &transport_params)
            != NGX_OK)
        {
            return NGX_DECLINED;
        }
    } else if (ngx_ssl_quic_transport_params(
                   r->connection, &transport_params)
               != NGX_OK)
    {
        return NGX_DECLINED;
    }

    n = settings.len + transport_params.len + 10
        + headers->fp_pseudoheaders_len * 2;
    cached->data = ngx_pnalloc(r->pool, n);
    if (cached->data == NULL) {
        return NGX_ERROR;
    }

    p = ngx_cpymem(cached->data, settings.data, settings.len);
    *p++ = '|';
    for (i = 0; i < headers->fp_pseudoheaders_len; i++) {
        if (i != 0) {
            *p++ = ',';
        }
        *p++ = headers->fp_pseudoheaders[i];
    }
    *p++ = '|';
    p = ngx_cpymem(p, transport_params.data, transport_params.len);
    *p++ = '|';
    p = append_uint64(p, fp->quic_dcid_length);
    *p++ = ',';
    p = append_uint64(p, fp->quic_scid_length);

    cached->len = p - cached->data;
    *out = *cached;
    return NGX_OK;
}

int
ngx_http3_fingerprint(ngx_http_request_t *r, ngx_str_t *out)
{
    return ngx_http3_fingerprint_create(r, out, 0);
}

int
ngx_http3_fingerprint_normalized(ngx_http_request_t *r, ngx_str_t *out)
{
    return ngx_http3_fingerprint_create(r, out, 1);
}

int
ngx_http3_fingerprint_hash(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_md5_t  ctx;
    ngx_str_t  fingerprint;
    u_char     digest[16];

    if (r->connection->quic == NULL || r->v3_parse == NULL) {
        return NGX_DECLINED;
    }

    if (r->v3_parse->headers.fp_fingerprint_hash.data != NULL) {
        *out = r->v3_parse->headers.fp_fingerprint_hash;
        return NGX_OK;
    }

    if (ngx_http3_fingerprint(r, &fingerprint) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->v3_parse->headers.fp_fingerprint_hash.len = 32;
    r->v3_parse->headers.fp_fingerprint_hash.data = ngx_pnalloc(r->pool, 32);
    if (r->v3_parse->headers.fp_fingerprint_hash.data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, fingerprint.data, fingerprint.len);
    ngx_md5_final(digest, &ctx);
    ngx_hex_dump(r->v3_parse->headers.fp_fingerprint_hash.data,
                 digest, sizeof(digest));

    *out = r->v3_parse->headers.fp_fingerprint_hash;
    return NGX_OK;
}

int
ngx_http3_fingerprint_hash_normalized(ngx_http_request_t *r, ngx_str_t *out)
{
    ngx_md5_t  ctx;
    ngx_str_t  fingerprint;
    u_char     digest[16];

    if (r->connection->quic == NULL || r->v3_parse == NULL) {
        return NGX_DECLINED;
    }

    if (r->v3_parse->headers.fp_fingerprint_hash_normalized.data != NULL) {
        *out = r->v3_parse->headers.fp_fingerprint_hash_normalized;
        return NGX_OK;
    }

    if (ngx_http3_fingerprint_normalized(r, &fingerprint) != NGX_OK) {
        return NGX_DECLINED;
    }

    r->v3_parse->headers.fp_fingerprint_hash_normalized.len = 32;
    r->v3_parse->headers.fp_fingerprint_hash_normalized.data =
        ngx_pnalloc(r->pool, 32);
    if (r->v3_parse->headers.fp_fingerprint_hash_normalized.data == NULL) {
        return NGX_ERROR;
    }

    ngx_md5_init(&ctx);
    ngx_md5_update(&ctx, fingerprint.data, fingerprint.len);
    ngx_md5_final(digest, &ctx);
    ngx_hex_dump(r->v3_parse->headers.fp_fingerprint_hash_normalized.data,
                 digest, sizeof(digest));

    *out = r->v3_parse->headers.fp_fingerprint_hash_normalized;
    return NGX_OK;
}

#endif
